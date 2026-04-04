"""
High-performance async port scanner for CamXploit
Provides comprehensive port scanning with proper resource management
"""

import asyncio
import socket
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import time

from ..core.scanner import BaseScanner, ScanResult, ScanTask, ScanStatus
from ..utils.validation import validate_ip_address, validate_port
from ..config.constants import CAMERA_PORTS
from ..core.exceptions import ValidationError, NetworkError


logger = logging.getLogger(__name__)


@dataclass
class PortScanResult:
    """Detailed port scan result"""
    port: int
    state: str  # 'open', 'closed', 'filtered', 'timeout'
    protocol: str = 'tcp'
    service: Optional[str] = None
    response_time: Optional[float] = None
    banner: Optional[str] = None
    error: Optional[str] = None


class AsyncPortScanner(BaseScanner):
    """Async port scanner with comprehensive functionality"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Scanner-specific configuration
        self.scan_timeout = config.get('port_timeout', 1.0)
        self.connect_timeout = config.get('connect_timeout', 0.5)
        self.banner_timeout = config.get('banner_timeout', 1.0)
        self.max_retries = config.get('max_retries', 1)
        self.scan_type = config.get('scan_type', 'tcp_connect')
        self.include_closed = config.get('include_closed', False)
        
        # Port configuration
        self.ports = config.get('ports', CAMERA_PORTS)
        self.port_chunks = config.get('port_chunks', 100)
        
        # Performance tuning
        self.tcp_nodelay = config.get('tcp_nodelay', True)
        self.socket_reuse = config.get('socket_reuse', True)
        
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Scan ports on target
        
        Args:
            target: IP address to scan
            **kwargs: Additional scan parameters
            
        Returns:
            ScanResult with open ports and metadata
        """
        start_time = time.time()
        
        # Validate target
        if not self.validate_target(target):
            raise ValidationError(f"Invalid target: {target}")
            
        try:
            # Get ports to scan
            ports = kwargs.get('ports', self.ports)
            if isinstance(ports, int):
                ports = [ports]
                
            self.logger.info(f"Starting port scan for {target} on {len(ports)} ports")
            
            # Execute scan
            results = await self._scan_ports(target, ports)
            
            # Process results
            open_ports = [r.port for r in results if r.state == 'open']
            closed_ports = [r.port for r in results if r.state == 'closed']
            filtered_ports = [r.port for r in results if r.state == 'filtered']
            
            scan_data = {
                'open_ports': sorted(open_ports),
                'closed_ports': sorted(closed_ports) if self.include_closed else [],
                'filtered_ports': sorted(filtered_ports),
                'total_scanned': len(ports),
                'scan_duration': time.time() - start_time,
                'detailed_results': [r.__dict__ for r in results]
            }
            
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=True,
                data=scan_data,
                metadata={
                    'scan_type': self.scan_type,
                    'timeout': self.scan_timeout,
                    'retries': self.max_retries
                }
            )
            
        except Exception as e:
            self.logger.error(f"Port scan failed for {target}: {e}")
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=False,
                status=ScanStatus.FAILED,
                errors=[str(e)]
            )
            
    def validate_target(self, target: str) -> bool:
        """Validate IP address format"""
        try:
            validate_ip_address(target)
            return True
        except ValidationError:
            return False
            
    async def _scan_ports(self, host: str, ports: List[int]) -> List[PortScanResult]:
        """Scan multiple ports concurrently"""
        if not ports:
            return []
            
        # Create scan tasks
        tasks = [
            ScanTask(
                id=f"{host}:{port}",
                target=host,
                port=port
            )
            for port in ports
        ]
        
        # Execute concurrent scans
        results = []
        async for result in self.scan_multiple(tasks):
            if result.success and 'port_result' in result.data:
                results.append(result.data['port_result'])
                
        return results
        
    async def scan_single(self, task: ScanTask) -> Dict[str, Any]:
        """Scan a single port with comprehensive checks"""
        start_time = time.time()
        host = task.target
        port = task.port
        
        try:
            async with self.semaphore:
                # TCP Connect scan
                result = await self._tcp_connect_scan(host, port)
                
                # Optional banner grab for open ports
                if result.state == 'open' and self.config.get('grab_banner', False):
                    banner = await self._grab_banner(host, port)
                    result.banner = banner
                    
                # Service detection
                service = self._detect_service(port)
                result.service = service
                
                result.response_time = time.time() - start_time
                
                return {
                    'success': True,
                    'port_result': result
                }
                
        except asyncio.TimeoutError:
            return {
                'success': True,
                'port_result': PortScanResult(
                    port=port,
                    state='timeout',
                    error='Connection timeout'
                )
            }
        except OSError as e:
            return {
                'success': True,
                'port_result': PortScanResult(
                    port=port,
                    state='error',
                    error=str(e)
                )
            }
        except Exception as e:
            self.logger.error(f"Error scanning {host}:{port}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    async def _tcp_connect_scan(self, host: str, port: int) -> PortScanResult:
        """Perform TCP connect scan"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Configure socket options
            if self.tcp_nodelay:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.socket_reuse:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
            # Set socket timeout
            sock.settimeout(self.connect_timeout)
            
            # Attempt connection
            start_time = time.time()
            result = sock.connect_ex((host, port))
            connect_time = time.time() - start_time
            
            sock.close()
            
            if result == 0:
                return PortScanResult(
                    port=port,
                    state='open',
                    response_time=connect_time
                )
            elif result == 111:  # Connection refused
                return PortScanResult(
                    port=port,
                    state='closed',
                    response_time=connect_time
                )
            else:
                return PortScanResult(
                    port=port,
                    state='filtered',
                    error=f"Error code: {result}"
                )
                
        except socket.timeout:
            return PortScanResult(
                port=port,
                state='filtered',
                error='Connection timeout'
            )
        except socket.gaierror as e:
            raise NetworkError(f"DNS resolution failed: {e}")
        except OSError as e:
            return PortScanResult(
                port=port,
                state='error',
                error=str(e)
            )
            
    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            # Create socket for banner grabbing
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.banner_timeout
            )
            
            # Send probe
            writer.write(b'\r\n\r\n')
            await writer.drain()
            
            # Read response
            data = await asyncio.wait_for(
                reader.read(1024),
                timeout=self.banner_timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            if data:
                return data.decode('utf-8', errors='ignore').strip()
                
        except Exception as e:
            self.logger.debug(f"Banner grab failed for {host}:{port}: {e}")
            
        return None
        
    def _detect_service(self, port: int) -> Optional[str]:
        """Detect common service based on port number"""
        service_map = {
            80: 'http',
            443: 'https',
            554: 'rtsp',
            1935: 'rtmp',
            8080: 'http-alt',
            8443: 'https-alt',
            8554: 'rtsp-alt',
            37777: 'dahua',
            37778: 'dahua-alt',
            37779: 'dahua-rtsp'
        }
        return service_map.get(port)
        
    async def scan_port_range(self, host: str, start: int, end: int) -> ScanResult:
        """Scan a range of ports"""
        ports = list(range(start, end + 1))
        return await self.scan(host, ports=ports)
        
    async def scan_common_ports(self, host: str) -> ScanResult:
        """Scan common camera ports"""
        return await self.scan(host, ports=CAMERA_PORTS)
        
    async def scan_top_ports(self, host: str, count: int = 100) -> ScanResult:
        """Scan top N most common ports"""
        # Prioritize by camera relevance
        prioritized = CAMERA_PORTS[:count]
        return await self.scan(host, ports=prioritized)
        
    def get_scan_statistics(self, results: List[PortScanResult]) -> Dict[str, Any]:
        """Generate scan statistics"""
        if not results:
            return {}
            
        open_count = sum(1 for r in results if r.state == 'open')
        closed_count = sum(1 for r in results if r.state == 'closed')
        filtered_count = sum(1 for r in results if r.state == 'filtered')
        
        # Calculate average response time
        response_times = [r.response_time for r in results if r.response_time]
        avg_response = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'total_ports': len(results),
            'open': open_count,
            'closed': closed_count,
            'filtered': filtered_count,
            'success_rate': (open_count / len(results)) * 100,
            'average_response_time': avg_response,
            'scan_duration': sum(r.response_time or 0 for r in results)
        }


class PortScannerBuilder:
    """Builder pattern for creating configured port scanners"""
    
    def __init__(self):
        self.config = {}
        
    def with_timeout(self, timeout: float) -> 'PortScannerBuilder':
        """Set scan timeout"""
        self.config['port_timeout'] = timeout
        return self
        
    def with_concurrency(self, max_concurrent: int) -> 'PortScannerBuilder':
        """Set max concurrent connections"""
        self.config['max_concurrent'] = max_concurrent
        return self
        
    def with_ports(self, ports: List[int]) -> 'PortScannerBuilder':
        """Set ports to scan"""
        self.config['ports'] = ports
        return self
        
    def with_banner_grab(self, enabled: bool = True) -> 'PortScannerBuilder':
        """Enable banner grabbing"""
        self.config['grab_banner'] = enabled
        return self
        
    def with_retries(self, retries: int) -> 'PortScannerBuilder':
        """Set retry attempts"""
        self.config['max_retries'] = retries
        return self
        
    def build(self) -> AsyncPortScanner:
        """Build configured scanner"""
        return AsyncPortScanner(self.config)


# Convenience functions for quick scanning
async def quick_scan(target: str, ports: Optional[List[int]] = None) -> ScanResult:
    """Quick scan with default settings"""
    scanner = AsyncPortScanner({})
    return await scanner.scan(target, ports=ports or CAMERA_PORTS[:50])


async def full_scan(target: str) -> ScanResult:
    """Full port range scan"""
    scanner = AsyncPortScanner({
        'ports': list(range(1, 65536)),
        'max_concurrent': 100,
        'port_timeout': 2.0
    })
    return await scanner.scan(target)
