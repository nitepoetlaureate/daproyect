"""
Base scanner interface for CamXploit
Provides abstract base classes and core scanning functionality
"""

import asyncio
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
import uuid

# Configure module logger
logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanResult:
    """Base class for scan results"""
    target: str
    timestamp: float
    success: bool
    data: Dict[str, Any]
    status: ScanStatus = ScanStatus.COMPLETED
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not isinstance(self.data, dict):
            self.data = {"raw": self.data}
    
    def add_error(self, error: str) -> None:
        """Add error to result"""
        self.errors.append(error)
        self.success = False
        
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to result"""
        self.metadata[key] = value
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "success": self.success,
            "status": self.status.value,
            "data": self.data,
            "errors": self.errors,
            "metadata": self.metadata
        }


@dataclass
class ScanTask:
    """Represents a single scanning task"""
    id: str
    target: str
    port: Optional[int] = None
    priority: int = 0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())


class BaseScanner(ABC):
    """Abstract base class for all scanners"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.results: List[ScanResult] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Configuration defaults
        self.timeout = config.get('timeout', 5.0)
        self.max_concurrent = config.get('max_concurrent', 50)
        self.retry_attempts = config.get('retry_attempts', 1)
        self.retry_delay = config.get('retry_delay', 1.0)
        
        # Async coordination
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self._running = False
        
    @abstractmethod
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Perform the scan operation
        
        Args:
            target: Target to scan (IP, URL, etc.)
            **kwargs: Scanner-specific arguments
            
        Returns:
            ScanResult object with findings
        """
        pass
        
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate the target before scanning
        
        Args:
            target: Target to validate
            
        Returns:
            True if valid, False otherwise
        """
        pass
        
    async def scan_multiple(self, tasks: List[ScanTask]) -> AsyncIterator[ScanResult]:
        """
        Scan multiple targets concurrently with proper resource management
        
        Args:
            tasks: List of ScanTask objects
            
        Yields:
            ScanResult objects as they complete
        """
        if not tasks:
            return
            
        self._running = True
        try:
            # Create task queue
            queue = asyncio.Queue()
            for task in sorted(tasks, key=lambda t: t.priority, reverse=True):
                await queue.put(task)
            
            # Create worker pool
            workers = []
            worker_count = min(self.max_concurrent, len(tasks))
            
            for i in range(worker_count):
                worker = asyncio.create_task(
                    self._worker(queue, f"worker-{i}"),
                    name=f"scanner-worker-{i}"
                )
                workers.append(worker)
            
            # Process results as they complete
            completed_count = 0
            total_count = len(tasks)
            
            while workers and completed_count < total_count:
                done, pending = await asyncio.wait(
                    workers,
                    timeout=0.1,
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                for worker in done:
                    try:
                        result = await worker
                        if result:
                            yield result
                            completed_count += 1
                    except Exception as e:
                        self.logger.error(f"Worker error: {e}")
                    
                    # Replace completed worker if more tasks remain
                    workers.remove(worker)
                    if not queue.empty() and self._running:
                        new_worker = asyncio.create_task(
                            self._worker(queue, f"worker-replace-{time.time()}"),
                            name=f"scanner-worker-replace-{time.time()}"
                        )
                        workers.append(new_worker)
                        
        finally:
            self._running = False
            # Cancel any remaining workers
            for worker in workers:
                if not worker.done():
                    worker.cancel()
                    
    async def _worker(self, queue: asyncio.Queue, name: str) -> Optional[ScanResult]:
        """Worker coroutine for processing scan tasks"""
        try:
            while self._running:
                try:
                    task = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                    
                try:
                    async with self.semaphore:
                        result = await self._scan_with_retry(task)
                        return result
                except Exception as e:
                    self.logger.error(f"{name} error scanning {task.target}: {e}")
                    return ScanResult(
                        target=task.target,
                        timestamp=time.time(),
                        success=False,
                        status=ScanStatus.FAILED,
                        errors=[str(e)]
                    )
                finally:
                    queue.task_done()
                    
        except asyncio.CancelledError:
            self.logger.debug(f"{name} cancelled")
            raise
            
    async def _scan_with_retry(self, task: ScanTask) -> ScanResult:
        """Scan with retry logic"""
        last_error = None
        
        for attempt in range(self.retry_attempts + 1):
            try:
                if task.port:
                    result = await self.scan(task.target, port=task.port)
                else:
                    result = await self.scan(task.target)
                    
                if result.success or attempt == self.retry_attempts:
                    return result
                    
            except Exception as e:
                last_error = e
                if attempt < self.retry_attempts:
                    self.logger.warning(
                        f"Retry {attempt + 1}/{self.retry_attempts} for {task.target}: {e}"
                    )
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                    
        return ScanResult(
            target=task.target,
            timestamp=time.time(),
            success=False,
            status=ScanStatus.FAILED,
            errors=[str(last_error)]
        )
        
    async def cancel(self) -> None:
        """Cancel any running scans"""
        self._running = False
        self.logger.info("Scanner cancellation requested")
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics"""
        if not self.results:
            return {"total": 0}
            
        total = len(self.results)
        successful = sum(1 for r in self.results if r.success)
        failed = total - successful
        
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate": (successful / total) * 100,
            "last_scan": max(r.timestamp for r in self.results) if self.results else None
        }
        
    def reset(self) -> None:
        """Reset scanner state"""
        self.results.clear()
        self.logger.info("Scanner state reset")


class ScannerOrchestrator:
    """Orchestrates complex multi-phase scanning operations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.Orchestrator")
        
    async def execute_scan_plan(self, scan_plan: Dict[str, Any]) -> AsyncIterator[ScanResult]:
        """
        Execute a complete scanning plan with multiple phases
        
        Args:
            scan_plan: Dictionary defining scan phases and targets
            
        Yields:
            ScanResult objects for each phase
        """
        plan_id = scan_plan.get('id', str(uuid.uuid4()))
        target = scan_plan['target']
        phases = scan_plan.get('phases', ['port_scan'])
        
        self.logger.info(f"Starting scan plan {plan_id} for {target}")
        
        start_time = time.time()
        
        try:
            # Phase 1: Port scanning
            if 'port_scan' in phases:
                yield await self._execute_port_scan(target, scan_plan)
                
            # Phase 2: Service detection
            if 'service_detection' in phases and 'open_ports' in scan_plan:
                yield await self._execute_service_detection(target, scan_plan)
                
            # Phase 3: Camera identification
            if 'camera_detection' in phases and 'services' in scan_plan:
                yield await self._execute_camera_detection(target, scan_plan)
                
            # Phase 4: Credential testing
            if 'credential_test' in phases and 'cameras' in scan_plan:
                yield await self._execute_credential_test(target, scan_plan)
                
        except Exception as e:
            self.logger.error(f"Scan plan {plan_id} failed: {e}")
            yield ScanResult(
                target=target,
                timestamp=time.time(),
                success=False,
                status=ScanStatus.FAILED,
                errors=[str(e)]
            )
        finally:
            duration = time.time() - start_time
            self.logger.info(f"Scan plan {plan_id} completed in {duration:.2f}s")
            
    async def _execute_port_scan(self, target: str, plan: Dict[str, Any]) -> ScanResult:
        """Execute port scanning phase"""
        # Implementation will be provided by concrete scanners
        return ScanResult(
            target=target,
            timestamp=time.time(),
            success=True,
            data={"phase": "port_scan", "message": "Port scanning completed"}
        )
        
    async def _execute_service_detection(self, target: str, plan: Dict[str, Any]) -> ScanResult:
        """Execute service detection phase"""
        return ScanResult(
            target=target,
            timestamp=time.time(),
            success=True,
            data={"phase": "service_detection", "message": "Service detection completed"}
        )
        
    async def _execute_camera_detection(self, target: str, plan: Dict[str, Any]) -> ScanResult:
        """Execute camera identification phase"""
        return ScanResult(
            target=target,
            timestamp=time.time(),
            success=True,
            data={"phase": "camera_detection", "message": "Camera identification completed"}
        )
        
    async def _execute_credential_test(self, target: str, plan: Dict[str, Any]) -> ScanResult:
        """Execute credential testing phase"""
        return ScanResult(
            target=target,
            timestamp=time.time(),
            success=True,
            data={"phase": "credential_test", "message": "Credential testing completed"}
        )


class ScannerContext:
    """Context manager for scanner lifecycle management"""
    
    def __init__(self, scanner: BaseScanner):
        self.scanner = scanner
        
    async def __aenter__(self):
        """Enter scanner context"""
        return self.scanner
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit scanner context and cleanup"""
        await self.scanner.cancel()
        if exc_type:
            self.scanner.logger.error(f"Scanner context error: {exc_val}")
