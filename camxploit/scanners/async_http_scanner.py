"""
High-performance async HTTP scanner for CamXploit
Provides comprehensive HTTP/HTTPS endpoint analysis and service detection
"""

import asyncio
import aiohttp
import re
import gzip
import logging
from typing import List, Dict, Any, Optional, Tuple, Pattern
from dataclasses import dataclass
import time
from urllib.parse import urlparse, urljoin

from ..core.scanner import BaseScanner, ScanResult, ScanTask, ScanStatus
from ..config.constants import DEFAULT_HEADERS
from ..utils.validation import validate_url
from ..core.exceptions import ValidationError, NetworkError
from ..core.session_factory import SessionManager, SessionConfig


logger = logging.getLogger(__name__)

# Pre-compiled regex patterns for performance
TITLE_PATTERN = re.compile(r'<title[^>]*>([^<]+)</title>', re.IGNORECASE)
H1_PATTERN = re.compile(r'<h1[^>]*>([^<]+)</h1>', re.IGNORECASE)
META_TITLE_PATTERN = re.compile(r'<meta[^>]*name=["\']title["\'][^>]*content=["\']([^"\']+)["\']', re.IGNORECASE)
OG_TITLE_PATTERN = re.compile(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']', re.IGNORECASE)

# Security header patterns
SECURITY_HEADERS = {
    'X-Frame-Options': 'Missing clickjacking protection',
    'X-Content-Type-Options': 'Missing MIME type protection', 
    'X-XSS-Protection': 'Missing XSS protection',
    'Content-Security-Policy': 'Missing CSP',
    'Strict-Transport-Security': 'Missing HSTS'
}

# Technology detection patterns
TECHNOLOGY_PATTERNS = {
    'Apache': [re.compile(r'apache', re.IGNORECASE)],
    'Nginx': [re.compile(r'nginx', re.IGNORECASE)],
    'IIS': [re.compile(r'iis|microsoft', re.IGNORECASE)],
    'Lighttpd': [re.compile(r'lighttpd', re.IGNORECASE)],
    'Django': [re.compile(r'django|csrfmiddlewaretoken', re.IGNORECASE)],
    'Flask': [re.compile(r'flask|werkzeug', re.IGNORECASE)],
    'Express': [re.compile(r'express|node\.js', re.IGNORECASE)],
    'jQuery': [re.compile(r'jquery|\$\.', re.IGNORECASE)],
    'React': [re.compile(r'react\.', re.IGNORECASE)],
    'Vue': [re.compile(r'vue\.js|v-if', re.IGNORECASE)]
}


@dataclass
class HTTPScanResult:
    """Detailed HTTP endpoint analysis result"""
    url: str
    status_code: int
    headers: Dict[str, str]
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    server: Optional[str] = None
    title: Optional[str] = None
    content_preview: str = ""
    redirects: List[str] = None
    auth_required: bool = False
    auth_method: Optional[str] = None
    technologies: List[str] = None
    vulnerabilities: List[str] = None
    error: Optional[str] = None
    
    def __post_init__(self):
        if self.redirects is None:
            self.redirects = []
        if self.technologies is None:
            self.technologies = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []


class AsyncHTTPScanner(BaseScanner):
    """Production-ready async HTTP/HTTPS endpoint scanner"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # HTTP configuration with validation
        self.timeout = aiohttp.ClientTimeout(
            total=max(1, config.get('http_timeout', 10)),
            connect=max(0.5, config.get('connect_timeout', 5)),
            sock_read=max(0.5, config.get('read_timeout', 5))
        )
        
        # Scan options with bounds checking
        self.max_redirects = max(0, min(10, config.get('max_redirects', 5)))
        self.follow_redirects = bool(config.get('follow_redirects', True))
        self.verify_ssl = bool(config.get('verify_ssl', False))
        self.max_content_size = max(1024, min(1024 * 1024, config.get('max_content_size', 102400)))
        self.include_technologies = bool(config.get('include_technologies', True))
        
        # Rate limiting
        self.rate_limit_delay = max(0, config.get('rate_limit_delay', 0.1))
        
        # Session configuration with sanitization
        self.user_agent = str(config.get('user_agent', DEFAULT_HEADERS['User-Agent']))[:200]
        self.accept_headers = self._sanitize_headers(config.get('accept_headers', DEFAULT_HEADERS))
        
    def _sanitize_headers(self, headers: Dict[str, Any]) -> Dict[str, str]:
        """Sanitize user-provided headers"""
        sanitized = {}
        for key, value in headers.items():
            if isinstance(key, str) and isinstance(value, str):
                sanitized[key[:100]] = value[:500]
        return sanitized
        
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Production-ready HTTP scan implementation"""
        start_time = time.time()
        
        try:
            if not self.validate_target(target):
                raise ValidationError(f"Invalid target: {target}")
                
            urls = self._build_scan_urls(target, kwargs)
            if not urls:
                return ScanResult(
                    target=target,
                    timestamp=start_time,
                    success=True,
                    data={'endpoints': [], 'total_scanned': 0}
                )
                
            self.logger.info(f"Starting HTTP scan for {target} - {len(urls)} endpoints")
            
            # Execute with rate limiting
            results = []
            for url in urls:
                try:
                    result = await self._scan_with_rate_limit(url)
                    if result:
                        results.append(result)
                except asyncio.TimeoutError:
                    results.append(HTTPScanResult(url=url, status_code=0, headers={}, error="Timeout"))
                except Exception as e:
                    results.append(HTTPScanResult(url=url, status_code=0, headers={}, error=str(e)))
                    
            scan_data = {
                'endpoints': results,
                'total_scanned': len(results),
                'success_count': len([r for r in results if 200 <= r.status_code < 400]),
                'error_count': len([r for r in results if r.status_code >= 400 or r.error]),
                'scan_duration': time.time() - start_time,
                'services_detected': self._detect_services(results)
            }
            
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=True,
                data=scan_data,
                metadata={
                    'protocols_tested': len(set(urlparse(r.url).scheme for r in results)),
                    'unique_servers': len(set(r.server for r in results if r.server))
                }
            )
            
        except ValidationError as e:
            raise e
        except Exception as e:
            self.logger.error(f"HTTP scan failed: {e}")
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=False,
                status=ScanStatus.FAILED,
                errors=[str(e)]
            )
            
    def validate_target(self, target: str) -> bool:
        """Validate target format"""
        try:
            if target.startswith(('http://', 'https://')):
                validate_url(target)
            else:
                from ipaddress import ip_address
                try:
                    ip_address(target)
                    return True
                except ValueError:
                    return bool(target) and '.' in target
            return True
        except ValidationError:
            return False
            
    def _build_scan_urls(self, target: str, kwargs: Dict[str, Any]) -> List[str]:
        """Build validated scan URLs"""
        ports = kwargs.get('ports', [80, 443, 8080, 8443])
        protocols = kwargs.get('protocols', ['http'])
        paths = kwargs.get('paths', ['/'])
        
        urls = []
        for protocol in protocols:
            for port in ports:
                for path in paths:
                    if target.startswith(('http://', 'https://')):
                        base = target.rstrip('/')
                    else:
                        base = f"{protocol}://{target}"
                        if not ((protocol == 'http' and port == 80) or (protocol == 'https' and port == 443)):
                            base += f":{port}"
                    
                    url = urljoin(base, path.lstrip('/'))
                    try:
                        validate_url(url)
                        urls.append(url)
                    except ValidationError:
                        continue
                        
        return urls
        
    async def _scan_with_rate_limit(self, url: str) -> Optional[HTTPScanResult]:
        """Scan with rate limiting"""
        await asyncio.sleep(self.rate_limit_delay)
        return await self._scan_http_endpoint(url)
        
    async def _scan_http_endpoint(self, url: str) -> HTTPScanResult:
        """Single endpoint scan with retry logic"""
        session_config = SessionConfig(
            user_agent_pool=[self.user_agent],
            timeout=self.timeout.total,
            verify_ssl=self.verify_ssl,
            max_redirects=self.max_redirects
        )
        
        try:
            response = await SessionManager.secure_request(
                url,
                config=session_config,
                allow_redirects=self.follow_redirects,
                headers=self.accept_headers
            )
                    
            # Collect response data
            status_code = response.status
            headers_dict = dict(response.headers)
            
            # Safe content reading
            content = await self._safe_read_content(response)
            
            # Extract metadata
            content_type = headers_dict.get('Content-Type', '').split(';')[0].strip()
            content_length = int(headers_dict.get('Content-Length', 0)) or len(content)
            server = headers_dict.get('Server')
            
            # Collect redirect chain
            redirects = [str(r.url) for r in getattr(response, 'history', [])]
            
            # Extract title
            title = self._extract_title(content)
            
            # Authentication detection
            auth_required, auth_method = self._check_authentication(response, headers_dict)
            
            # Technology and vulnerability detection
            technologies = self._detect_technologies(headers_dict, content) if self.include_technologies else []
            vulnerabilities = self._detect_vulnerabilities(response, headers_dict, content)
            
            return HTTPScanResult(
                url=str(response.url),
                status_code=status_code,
                headers=headers_dict,
                content_type=content_type,
                content_length=content_length,
                server=server,
                title=title,
                content_preview=content[:500],
                redirects=redirects,
                auth_required=auth_required,
                auth_method=auth_method,
                technologies=technologies,
                vulnerabilities=vulnerabilities
            )
                    
        except asyncio.TimeoutError:
            return HTTPScanResult(url=url, status_code=0, headers={}, error="Timeout")
        except aiohttp.ClientError as e:
            return HTTPScanResult(url=url, status_code=0, headers={}, error=str(e))
                
    async def _safe_read_content(self, response: aiohttp.ClientResponse) -> str:
        """Safe content reading with compression handling"""
        try:
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) > self.max_content_size:
                return f"[Content too large: {content_length}]"
                
            content = await response.read()
            
            # Handle compression
            if response.headers.get('Content-Encoding') == 'gzip':
                content = gzip.decompress(content)
                
            return content.decode('utf-8', errors='ignore')[:self.max_content_size]
            
        except Exception as e:
            return f"[Content error: {e}]"
            
    def _extract_title(self, content: str) -> Optional[str]:
        """Extract page title using pre-compiled patterns"""
        for pattern in [TITLE_PATTERN, H1_PATTERN, META_TITLE_PATTERN, OG_TITLE_PATTERN]:
            match = pattern.search(content)
            if match:
                return match.group(1).strip()
        return None
        
    def _check_authentication(self, response: aiohttp.ClientResponse,
                            headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """Check authentication requirements"""
        if response.status == 401:
            auth_header = headers.get('WWW-Authenticate', '')
            for method in ['Basic', 'Digest', 'Bearer']:
                if method in auth_header:
                    return True, method
            return True, 'Unknown'
        return False, None
        
    def _detect_technologies(self, headers: Dict[str, str], content: str) -> List[str]:
        """Detect technologies using pre-compiled patterns"""
        technologies = []
        content_lower = content.lower()
        
        # Server detection
        server = headers.get('Server', '').lower()
        for tech, patterns in TECHNOLOGY_PATTERNS.items():
            if any(pattern.search(server) for pattern in patterns):
                technologies.append(tech)
                
        # Content-based detection
        for tech, patterns in TECHNOLOGY_PATTERNS.items():
            if any(pattern.search(content_lower) for pattern in patterns):
                technologies.append(tech)
                
        return list(set(technologies))
        
    def _detect_vulnerabilities(self, response: aiohttp.ClientResponse,
                              headers: Dict[str, str], content: str) -> List[str]:
        """Detect security issues"""
        vulnerabilities = []
        content_lower = content.lower()
        
        # Missing security headers
        for header, description in SECURITY_HEADERS.items():
            if not headers.get(header):
                vulnerabilities.append(description)
                
        # Server version exposure
        server = headers.get('Server', '')
        if any(char in server for char in ['/', '.']) and len(server) > 10:
            vulnerabilities.append('Server version exposed')
            
        # Debug information
        if any(indicator in content_lower for indicator in ['traceback', 'stack trace', 'exception']):
            vulnerabilities.append('Debug information exposed')
            
        return vulnerabilities
        
    def _detect_services(self, results: List[HTTPScanResult]) -> List[str]:
        """Extract unique services from results"""
        services = set()
        for result in results:
            if result.server:
                services.add(result.server)
            if result.content_type:
                services.add(f"{result.content_type} service")
        return list(services)


class HTTPScannerBuilder:
    """Production-ready builder pattern"""
    
    def __init__(self):
        self.config = {}
        
    def with_timeout(self, timeout: float) -> 'HTTPScannerBuilder':
        self.config['http_timeout'] = max(1.0, timeout)
        return self
        
    def with_concurrency(self, max_concurrent: int) -> 'HTTPScannerBuilder':
        self.config['max_concurrent'] = max(1, max_concurrent)
        return self
        
    def with_ssl_verify(self, verify: bool) -> 'HTTPScannerBuilder':
        self.config['verify_ssl'] = bool(verify)
        return self
        
    def build(self) -> AsyncHTTPScanner:
        return AsyncHTTPScanner(self.config)
