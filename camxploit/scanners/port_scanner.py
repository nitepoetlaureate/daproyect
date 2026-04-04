import asyncio
import socket
from typing import List, Set
from ..core.scanner import BaseScanner, ScanResult
from ..utils.validation import validate_ip_address
from ..config.constants import CAMERA_PORTS

class PortScanner(BaseScanner):
    """Async port scanner with proper resource management"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.timeout = config.get('port_timeout', 1.0)
        self.max_concurrent = config.get('max_concurrent_ports', 50)
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
    async def scan(self, target: str) -> ScanResult:
        """Scan all configured ports on target"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
            
        ports = self.config.get('ports', CAMERA_PORTS)
        open_ports = await self._scan_ports(target, ports)
        
        return ScanResult(
            target=target,
            timestamp=time.time(),
            success=True,
            data={'open_ports': open_ports}
        )
        
    async def _scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """Scan multiple ports concurrently"""
        tasks = [self._scan_single_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        open_ports = []
        for port, result in zip(ports, results):
            if result is True:
                open_ports.append(port)
            elif isinstance(result, Exception):
                self.logger.debug(f"Error scanning {host}:{port}: {result}")
                
        return open_ports
        
    async def _scan_single_port(self, host: str, port: int) -> bool:
        """Check if a single port is open"""
        async with self.semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                return True
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return False
                
    def validate_target(self, target: str) -> bool:
        """Validate IP address format"""
        return validate_ip_address(target)
