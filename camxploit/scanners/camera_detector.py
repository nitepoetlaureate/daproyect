"""
Advanced camera detection and identification scanner
Provides comprehensive camera brand/type detection with vulnerability assessment
"""

import asyncio
import aiohttp
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import time
from urllib.parse import urljoin, urlparse

from ..core.scanner import BaseScanner, ScanResult, ScanTask, ScanStatus
from ..core.models import Camera, CameraType
from ..config.constants import CAMERA_PATTERNS, CVE_DATABASE, DEFAULT_HEADERS
from ..utils.validation import validate_url
from ..core.exceptions import ValidationError, NetworkError


logger = logging.getLogger(__name__)


@dataclass
class CameraDetectionResult:
    """Detailed camera detection result"""
    url: str
    is_camera: bool
    confidence: float  # 0.0 to 1.0
    camera_type: CameraType
    model: Optional[str] = None
    firmware: Optional[str] = None
    vulnerabilities: List[str] = None
    endpoints_found: List[str] = None
    authentication_required: bool = False
    default_credentials_found: bool = False
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.endpoints_found is None:
            self.endpoints_found = []


class AsyncCameraDetector(BaseScanner):
    """Advanced async camera detector with brand identification"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Detection configuration
        self.timeout = aiohttp.ClientTimeout(
            total=config.get('http_timeout', 10),
            connect=config.get('connect_timeout', 5),
            sock_read=config.get('read_timeout', 5)
        )
        
        # Detection thresholds
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        self.max_redirects = config.get('max_redirects', 3)
        self.verify_ssl = config.get('verify_ssl', False)
        
        # Session configuration
        self.max_concurrent = config.get('max_concurrent', 20)
        self.user_agent = config.get('user_agent', DEFAULT_HEADERS['User-Agent'])
        
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Detect cameras on target
        
        Args:
            target: IP address to scan
            **kwargs: Additional parameters (ports, scan_depth, etc.)
            
        Returns:
            ScanResult with detected cameras
        """
        start_time = time.time()
        
        try:
            # Validate target
            if not self.validate_target(target):
                raise ValidationError(f"Invalid target: {target}")
                
            # Get ports from kwargs or use defaults
            ports = kwargs.get('ports', [80, 443, 8080, 8443, 8000])
            scan_depth = kwargs.get('scan_depth', 'standard')
            
            self.logger.info(f"Starting camera detection for {target} on {len(ports)} ports")
            
            # Create scan tasks
            tasks = []
            for port in ports:
                protocols = ['http', 'https'] if port in [443, 8443] else ['http']
                for protocol in protocols:
                    url = f"{protocol}://{target}:{port}"
                    tasks.append(ScanTask(
                        id=f"{target}:{port}:{protocol}",
                        target=url,
                        metadata={'port': port, 'protocol': protocol}
                    ))
            
            # Execute detection
            cameras = []
            async for result in self.scan_multiple(tasks):
                if result.success and result.data.get('camera'):
                    cameras.append(result.data['camera'])
                    
            # Generate summary
            detection_data = {
                'cameras': cameras,
                'total_detected': len(cameras),
                'by_type': self._categorize_cameras(cameras),
                'vulnerabilities': self._collect_vulnerabilities(cameras),
                'scan_duration': time.time() - start_time,
                'scan_depth': scan_depth
            }
            
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=True,
                data=detection_data,
                metadata={
                    'ports_scanned': len(ports),
                    'protocols_tested': len(set(t.metadata['protocol'] for t in tasks))
                }
            )
            
        except Exception as e:
            self.logger.error(f"Camera detection failed for {target}: {e}")
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=False,
                status=ScanStatus.FAILED,
                errors=[str(e)]
            )
            
    def validate_target(self, target: str) -> bool:
        """Validate IP address or hostname"""
        try:
            # Accept IP addresses or hostnames
            from ipaddress import ip_address
            try:
                ip_address(target)
                return True
            except ValueError:
                # Allow hostnames
                if len(target) > 0 and '.' in target:
                    return True
            return False
        except Exception:
            return False
            
    async def scan_single(self, task: ScanTask) -> Dict[str, Any]:
        """Detect camera at specific URL"""
        url = task.target
        port = task.metadata.get('port', 80)
        protocol = task.metadata.get('protocol', 'http')
        
        try:
            async with self.semaphore:
                result = await self._detect_camera_at_url(url, port, protocol)
                
                if result.is_camera:
                    # Create Camera model
                    camera = Camera(
                        ip=urlparse(url).hostname,
                        port=port,
                        type=result.camera_type,
                        model=result.model,
                        firmware=result.firmware,
                        vulnerabilities=result.vulnerabilities
                    )
                    
                    return {
                        'success': True,
                        'camera': camera
                    }
                else:
                    return {
                        'success': True,
                        'camera': None
                    }
                    
        except Exception as e:
            self.logger.error(f"Error detecting camera at {url}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    async def _detect_camera_at_url(self, url: str, port: int, protocol: str) -> CameraDetectionResult:
        """Comprehensive camera detection at specific URL"""
        start_time = time.time()
        
        # Create session
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            ssl=False,  # Skip SSL verification for cameras
            enable_cleanup_closed=True
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout.total,
            connect=5.0,
            sock_read=5.0
        )
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        ) as session:
            
            # Check multiple endpoints
            endpoints = [
                '/',
                '/admin',
                '/login',
                '/viewer',
                '/video',
                '/stream',
                '/snapshot',
                '/live',
                '/cgi-bin/magicBox.cgi',
                '/ISAPI/System/deviceInfo',
                '/axis-cgi/admin/param.cgi',
                '/onvif-http/snapshot',
                '/system.ini',
                '/config',
                '/setup',
                '/cgi-bin/snapshot.cgi',
                '/cgi-bin/video.cgi',
                '/cgi-bin/live.cgi'
            ]
            
            total_checks = 0
            positive_matches = 0
            endpoints_found = []
            
            # Test basic connectivity
            try:
                async with session.get(url, allow_redirects=self.max_redirects > 0) as response:
                    total_checks += 1
                    
                    # Check for camera indicators in response
                    content = await response.text(errors='ignore')
                    
                    # Analyze response for camera signatures
                    detection_result = await self._analyze_response(
                        response, content, url, port
                    )
                    
                    if detection_result.is_camera:
                        positive_matches += 1
                        endpoints_found.append(url)
                        
                    # Check additional endpoints
                    for endpoint in endpoints:
                        endpoint_url = urljoin(url, endpoint)
                        try:
                            async with session.get(endpoint_url) as endpoint_response:
                                total_checks += 1
                                
                                endpoint_result = await self._analyze_response(
                                    endpoint_response, 
                                    await endpoint_response.text(errors='ignore'),
                                    endpoint_url,
                                    port
                                )
                                
                                if endpoint_result.is_camera:
                                    positive_matches += 1
                                    endpoints_found.append(endpoint_url)
                                    
                                    # If high confidence, stop checking others
                                    if endpoint_result.confidence > 0.9:
                                        break
                                        
                        except Exception as e:
                            self.logger.debug(f"Endpoint check failed for {endpoint_url}: {e}")
                            continue
                            
                    # Calculate final confidence
                    confidence = min(positive_matches / max(total_checks, 1), 1.0)
                    
                    if confidence >= self.confidence_threshold:
                        return await self._enhance_detection_result(
                            detection_result,
                            endpoints_found,
                            confidence
                        )
                            
            except Exception as e:
                self.logger.debug(f"Camera detection failed for {url}: {e}")
                
            # Return negative result
            return CameraDetectionResult(
                url=url,
                is_camera=False,
                confidence=0.0,
                camera_type=CameraType.UNKNOWN
            )
            
    async def _analyze_response(self, response: aiohttp.ClientResponse, 
                              content: str, url: str, port: int) -> CameraDetectionResult:
        """Analyze HTTP response for camera indicators"""
        
        # Initialize scoring
        confidence_score = 0.0
        camera_type = CameraType.UNKNOWN
        model = None
        firmware = None
        auth_required = response.status == 401
        
        # Check headers for camera signatures
        headers = dict(response.headers)
        server_header = headers.get('Server', '').lower()
        
        # Analyze Server header
        for brand, patterns in CAMERA_PATTERNS.items():
            if any(keyword in server_header for keyword in patterns['headers']):
                camera_type = CameraType(brand.upper())
                confidence_score += 0.3
                break
                
        # Analyze response content
        content_lower = content.lower()
        
        # Check for camera keywords in content
        for brand, patterns in CAMERA_PATTERNS.items():
            content_matches = sum(1 for keyword in patterns['content'] 
                                if keyword in content_lower)
            if content_matches > 0:
                camera_type = CameraType(brand.upper())
                confidence_score += (content_matches * 0.1)
                
        # Check for specific model/firmware information
        model_info = self._extract_model_info(content, headers)
        if model_info.get('model'):
            model = model_info['model']
            confidence_score += 0.2
        if model_info.get('firmware'):
            firmware = model_info['firmware']
            confidence_score += 0.1
            
        # Check for authentication pages
        if any(auth_indicator in content_lower for auth_indicator in 
               ['login', 'username', 'password', 'auth', 'admin']):
            auth_required = True
            
        # Check for specific camera features
        camera_features = [
            'live view', 'snapshot', 'video stream', 'ptz', 'recording',
            'motion detection', 'night vision', 'ir', 'audio', 'microphone'
        ]
        
        feature_matches = sum(1 for feature in camera_features 
                            if feature in content_lower)
        confidence_score += (feature_matches * 0.05)
        
        # Cap confidence at 1.0
        confidence_score = min(confidence_score, 1.0)
        
        return CameraDetectionResult(
            url=url,
            is_camera=confidence_score >= self.confidence_threshold,
            confidence=confidence_score,
            camera_type=camera_type,
            model=model,
            firmware=firmware,
            authentication_required=auth_required,
            vulnerabilities=self._get_vulnerabilities_for_type(camera_type),
            endpoints_found=[url]
        )
        
    def _extract_model_info(self, content: str, headers: Dict[str, str]) -> Dict[str, str]:
        """Extract model and firmware information from response"""
        info = {}
        
        # Common patterns for different brands
        patterns = {
            'model': [
                r'<title>([^<]*(?:camera|dvr|nvr)[^<]*)</title>',
                r'model["\s]*[:=]["\s]*([^"<\s]+)',
                r'device["\s]*[:=]["\s]*([^"<\s]+)',
                r'product["\s]*[:=]["\s]*([^"<\s]+)',
                r'brand["\s]*[:=]["\s]*([^"<\s]+)',
            ],
            'firmware': [
                r'firmware["\s]*[:=]["\s]*([^"<\s]+)',
                r'version["\s]*[:=]["\s]*([^"<\s]+)',
                r'sw["\s]*[:=]["\s]*([^"<\s]+)',
                r'fw["\s]*[:=]["\s]*([^"<\s]+)',
            ]
        }
        
        for key, regex_list in patterns.items():
            for pattern in regex_list:
                import re
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    info[key] = match.group(1).strip()
                    break
                    
        return info
        
    def _get_vulnerabilities_for_type(self, camera_type: CameraType) -> List[str]:
        """Get CVEs for detected camera type"""
        if camera_type == CameraType.UNKNOWN:
            return []
            
        type_str = camera_type.value.lower()
        return CVE_DATABASE.get(type_str, [])
        
    def _categorize_cameras(self, cameras: List[Camera]) -> Dict[str, int]:
        """Categorize cameras by type"""
        categories = {}
        for camera in cameras:
            type_name = camera.type.value
            categories[type_name] = categories.get(type_name, 0) + 1
        return categories
        
    def _collect_vulnerabilities(self, cameras: List[Camera]) -> Dict[str, List[str]]:
        """Collect all vulnerabilities found"""
        vulns = {}
        for camera in cameras:
            if camera.vulnerabilities:
                vulns[camera.type.value] = camera.vulnerabilities
        return vulns
        
    async def detect_brand_specific(self, url: str, brand: CameraType) -> Dict[str, Any]:
        """Perform brand-specific detection"""
        
        brand_detectors = {
            CameraType.HIKVISION: self._detect_hikvision,
            CameraType.DAHUA: self._detect_dahua,
            CameraType.AXIS: self._detect_axis,
            CameraType.CP_PLUS: self._detect_cp_plus,
        }
        
        detector = brand_detectors.get(brand)
        if detector:
            return await detector(url)
            
        return {}
        
    async def _detect_hikvision(self, url: str) -> Dict[str, Any]:
        """Hikvision-specific detection"""
        endpoints = [
            '/ISAPI/System/deviceInfo',
            '/System/deviceInfo',
            '/cgi-bin/magicBox.cgi?action=getSystemInfo',
            '/cgi-bin/devInfo.cgi',
            '/Streaming/Channels/1',
            '/onvif/device_service'
        ]
        
        return await self._check_brand_endpoints(url, endpoints, 'hikvision')
        
    async def _detect_dahua(self, url: str) -> Dict[str, Any]:
        """Dahua-specific detection"""
        endpoints = [
            '/cgi-bin/magicBox.cgi?action=getSystemInfo',
            '/cgi-bin/configManager.cgi?action=getConfig&name=General',
            '/cgi-bin/devInfo.cgi',
            '/cgi-bin/magicBox.cgi?action=getProductDefinition'
        ]
        
        return await self._check_brand_endpoints(url, endpoints, 'dahua')
        
    async def _detect_axis(self, url: str) -> Dict[str, Any]:
        """Axis-specific detection"""
        endpoints = [
            '/axis-cgi/admin/param.cgi?action=list',
            '/axis-cgi/mjpg/video.cgi',
            '/axis-cgi/com/ptz.cgi',
            '/onvif/device_service',
            '/axis-cgi/param.cgi'
        ]
        
        return await self._check_brand_endpoints(url, endpoints, 'axis')
        
    async def _detect_cp_plus(self, url: str) -> Dict[str, Any]:
        """CP Plus-specific detection"""
        endpoints = [
            '/',
            '/login',
            '/admin',
            '/cgi-bin/snapshot.cgi',
            '/cgi-bin/video.cgi',
            '/cgi-bin/live.cgi'
        ]
        
        return await self._check_brand_endpoints(url, endpoints, 'cp_plus')
        
    async def _check_brand_endpoints(self, url: str, endpoints: List[str], 
                                   brand: str) -> Dict[str, Any]:
        """Check brand-specific endpoints"""
        results = {}
        
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': self.user_agent}
        ) as session:
            
            for endpoint in endpoints:
                endpoint_url = urljoin(url, endpoint)
                try:
                    async with session.get(endpoint_url) as response:
                        if response.status == 200:
                            content = await response.text(errors='ignore')
                            
                            # Brand-specific content analysis
                            brand_signatures = {
                                'hikvision': ['hikvision', 'hik', 'dvr', 'nvr'],
                                'dahua': ['dahua', 'dh', 'dvr', 'nvr'],
                                'axis': ['axis', 'axis communications'],
                                'cp_plus': ['cp plus', 'cp-plus', 'cpplus', 'uvr']
                            }
                            
                            content_lower = content.lower()
                            signatures = brand_signatures.get(brand, [])
                            
                            if any(sig in content_lower for sig in signatures):
                                results[endpoint] = {
                                    'status': response.status,
                                    'content_length': len(content),
                                    'brand_detected': True
                                }
                                
                except Exception as e:
                    self.logger.debug(f"Brand endpoint check failed for {endpoint_url}: {e}")
                    continue
                    
        return results


class CameraDetectorBuilder:
    """Builder pattern for creating configured camera detectors"""
    
    def __init__(self):
        self.config = {}
        
    def with_timeout(self, timeout: float) -> 'CameraDetectorBuilder':
        """Set HTTP timeout"""
        self.config['http_timeout'] = timeout
        return self
        
    def with_confidence(self, threshold: float) -> 'CameraDetectorBuilder':
        """Set confidence threshold"""
        self.config['confidence_threshold'] = threshold
        return self
        
    def with_user_agent(self, user_agent: str) -> 'CameraDetectorBuilder':
        """Set custom user agent"""
        self.config['user_agent'] = user_agent
        return self
        
    def with_max_redirects(self, max_redirects: int) -> 'CameraDetectorBuilder':
        """Set max redirects"""
        self.config['max_redirects'] = max_redirects
        return self
        
    def build(self) -> AsyncCameraDetector:
        """Build configured detector"""
        return AsyncCameraDetector(self.config)


# Convenience functions
async def detect_camera(url: str, **kwargs) -> CameraDetectionResult:
    """Quick camera detection for single URL"""
    detector = AsyncCameraDetector(kwargs)
    result = await detector.scan(urlparse(url).hostname, ports=[urlparse(url).port or 80])
    
    if result.data.get('cameras'):
        return CameraDetectionResult(
            url=url,
            is_camera=True,
            confidence=1.0,
            camera_type=result.data['cameras'][0].type,
            model=result.data['cameras'][0].model
        )
        
    return CameraDetectionResult(url=url, is_camera=False, confidence=0.0, camera_type=CameraType.UNKNOWN)
