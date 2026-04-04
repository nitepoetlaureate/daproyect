"""
Discovery Scanner Plugin for Gridland
Consolidated scanner for discovering exposed files, interfaces, and endpoints.
"""
import requests
import yaml
import os
import re
from typing import List, Dict, Any, Optional
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies

class DiscoveryScannerPlugin(ScannerPlugin):
    """
    A data-driven scanner that discovers web assets based on a YAML configuration file.
    It merges the functionality of the previous ConfigScanner and WebInterfaceScanner.
    """

    def __init__(self):
        super().__init__()
        self.path_config = self._load_path_config()
        self.sensitive_patterns = self._get_sensitive_patterns()
        self.admin_indicators = self._get_admin_indicators()
        self.dir_listing_indicators = self._get_dir_listing_indicators()

    def _load_path_config(self, paths_file: str = 'data/discovery/paths.yml') -> Dict[str, Any]:
        """Loads the structured path configuration from the YAML file."""
        if not os.path.exists(paths_file):
            # Assuming a logging mechanism exists on the base plugin
            print(f"Warning: Paths file not found at {paths_file}")
            return {}
        with open(paths_file, 'r') as f:
            data = yaml.safe_load(f)
        return data if data else {}

    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has web ports for discovery scanning."""
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]
        return any(p.port in web_ports for p in target.open_ports)

    def get_description(self) -> str:
        """Get plugin description."""
        return "Optimized, context-aware discovery scanner for web assets."

    def _get_server_type(self, session: requests.Session, base_url: str) -> Optional[str]:
        """Performs a GET request to the base URL to identify the server."""
        try:
            response = session.get(base_url, timeout=5)
            server_header = response.headers.get('Server', '').lower()
            if 'nginx' in server_header:
                return 'nginx'
            if 'apache' in server_header:
                return 'apache'
        except requests.RequestException:
            return None
        return None

    def _flatten_path_groups(self, path_groups: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Converts a list of path groups into a flat list of path info dicts."""
        flat_list = []
        for group in path_groups:
            category = group.get('category', 'unknown')
            scan_type = group.get('scan_type', 'file_check')
            for path in group.get('paths', []):
                flat_list.append({'path': path, 'category': category, 'scan_type': scan_type})
        return flat_list

    def _build_scan_list(self, server_type: Optional[str], vendor: Optional[str]) -> List[Dict[str, str]]:
        """Builds a prioritized, flat list of paths to scan based on server and vendor."""
        scan_list = []
        vendor_specific_paths = []

        vendor_lower = vendor.lower() if vendor else None

        # 1. Add server-specific paths from server_specific block
        if server_type and server_type in self.path_config.get('server_specific', {}):
            specific_groups = self.path_config['server_specific'][server_type].get('path_groups', [])
            scan_list.extend(self._flatten_path_groups(specific_groups))

        # 2. Extract vendor-specific paths from the generic list
        generic_groups = self.path_config.get('generic', {}).get('path_groups', [])
        remaining_generic_groups = []

        if vendor_lower:
            for group in generic_groups:
                # Prioritize groups that are brand-specific
                if group['category'] in ['brand_specific_interface', 'camera_specific_config']:
                    for path_info in self._flatten_path_groups([group]):
                        if vendor_lower in path_info['path'].lower():
                            vendor_specific_paths.append(path_info)
                else:
                    remaining_generic_groups.append(group)
        else:
            remaining_generic_groups = generic_groups

        # 3. Combine the lists: vendor-specific first, then server-specific, then generic
        final_scan_list = vendor_specific_paths + scan_list + self._flatten_path_groups(remaining_generic_groups)

        # Remove duplicates while preserving order
        seen = set()
        unique_list = []
        for item in final_scan_list:
            if item['path'] not in seen:
                unique_list.append(item)
                seen.add(item['path'])

        return unique_list

    def _check_path(self, session: requests.Session, base_url: str, path_info: Dict[str, str], port: int) -> Optional[Finding]:
        """Checks a single path and returns a Finding if successful."""
        path = path_info['path']
        category = path_info['category']
        scan_type = path_info['scan_type']
        url = f"{base_url}{path}"

        try:
            response = session.get(url, timeout=5)

            if response.status_code == 200:
                return self._handle_successful_response(response, url, port, category, scan_type, path)

            elif response.status_code in [401, 403] and scan_type == 'interface_discovery':
                return Finding(
                    category="web_interface",
                    description=f"Protected interface found: {path}",
                    severity="low",
                    port=port,
                    url=url,
                    data={"path": path, "status_code": response.status_code, "auth_required": True}
                )
        except requests.RequestException:
            pass # This is expected for non-existent paths, so we don't log an error.
        return None

    def scan(self, target: ScanTarget, fingerprint: dict = None) -> List[Finding]:
        """Perform an intelligent discovery scan based on server type and path priority."""
        findings = []
        proxy_url = os.environ.get('PROXY_URL')

        vendor = fingerprint.get('vendor') if fingerprint else None

        for port_result in target.open_ports:
            if port_result.port not in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]:
                continue

            protocol = "https" if port_result.port in [443, 8443] else "http"
            base_url = f"{protocol}://{target.ip}:{port_result.port}"

            with requests.Session() as session:
                session.headers.update(get_request_headers())
                session.proxies = get_proxies(proxy_url)
                session.verify = False
                session.allow_redirects = True

                server_type = self._get_server_type(session, base_url)
                scan_list = self._build_scan_list(server_type, vendor)

                for path_info in scan_list:
                    finding = self._check_path(session, base_url, path_info, port_result.port)
                    if finding:
                        findings.append(finding)
        return findings

    def _handle_successful_response(self, response: requests.Response, url: str, port: int, category: str, scan_type: str, path: str) -> Optional[Finding]:
        """Process a 200 OK response based on the scan type."""
        content = response.text
        content_lower = content.lower()

        # Check for directory listing first, as it can apply to any path
        is_listing = any(indicator in content_lower for indicator in self.dir_listing_indicators)
        if is_listing:
            return Finding(
                category="vulnerability",
                description=f"Directory listing enabled: {path}",
                severity="medium",
                port=port,
                url=url,
                data={
                    "vulnerability_type": "directory_listing",
                    "directory": path,
                    "file_count": content_lower.count('<a href='),
                    "server": response.headers.get('Server', 'Unknown')
                }
            )

        if scan_type == 'file_check':
            analysis = self._analyze_file_content(content, path)
            if analysis['is_sensitive']:
                severity = self._determine_severity(analysis)
                return Finding(
                    category="configuration_exposure",
                    description=f"Exposed file found: {path}",
                    severity=severity,
                    port=port,
                    url=url,
                    data={
                        "file_category": category,
                        "file_path": path,
                        "content_size": len(response.content),
                        "sensitive_data": analysis['sensitive_data'],
                        "file_format": analysis['format']
                    }
                )

        elif scan_type == 'backup_check':
            return Finding(
                category="backup_exposure",
                description=f"Backup file exposed: {path}",
                severity="high",
                port=port,
                url=url,
                data={
                    "backup_category": category,
                    "file_path": path,
                    "content_size": len(response.content),
                }
            )

        elif scan_type == 'interface_discovery':
            is_admin = any(indicator in content_lower for indicator in self.admin_indicators)
            if is_admin:
                interface_type = self._identify_interface_type(content_lower, path)
                return Finding(
                    category="web_interface",
                    description=f"Admin interface found: {interface_type}",
                    severity="medium",
                    port=port,
                    url=url,
                    data={
                        "interface_type": interface_type,
                        "path": path,
                        "requires_auth": "password" in content_lower or "login" in content_lower,
                    }
                )

        elif scan_type == 'debug_endpoint':
            debug_indicators = ['debug', 'development', 'test', 'staging', 'error', 'stack trace', 'exception', 'phpinfo', 'server info']
            is_debug = any(indicator in content_lower for indicator in debug_indicators)
            if is_debug:
                system_info = self._extract_system_info(content)
                return Finding(
                    category="debug_exposure",
                    description=f"Debug endpoint exposed: {path}",
                    severity="medium",
                    port=port,
                    url=url,
                    data={
                        "endpoint_category": category,
                        "debug_path": path,
                        "system_info": system_info,
                    }
                )

        return None

    def _get_sensitive_patterns(self) -> Dict[str, List[str]]:
        """Consolidated sensitive data patterns."""
        return {
            "credentials": [
                r"password\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"passwd\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"secret\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"key\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"token\s*[=:]\s*['\"]?([^'\"\s<>]+)"
            ],
            "network_info": [
                r"ip\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)",
                r"hostname\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"gateway\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)",
                r"dns\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)"
            ],
            "system_info": [
                r"version\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"build\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"serial\s*[=:]\s*['\"]?([^'\"\s<>]+)",
                r"mac\s*[=:]\s*['\"]?([a-fA-F0-9:]{17})"
            ]
        }

    def _get_admin_indicators(self) -> List[str]:
        """Consolidated admin panel indicators."""
        return [
            "administration", "control panel", "management", "dashboard",
            "login", "password", "username", "sign in", "authentication",
            "admin panel", "administrator", "configuration", "settings"
        ]

    def _get_dir_listing_indicators(self) -> List[str]:
        """Directory listing indicators."""
        return [
            "index of", "directory listing", "[dir]", "parent directory",
            "<title>index of", "apache/", "nginx/", "iis/", "lighttpd/"
        ]

    def _analyze_file_content(self, content: str, file_path: str) -> Dict:
        """Analyze file content for format and sensitive data."""
        analysis = {
            'is_sensitive': False,
            'format': 'unknown',
            'sensitive_data': {}
        }
        content_lower = content.lower()

        if content.strip().startswith('<?xml') or '<configuration>' in content_lower:
            analysis['format'] = 'xml'
        elif content.strip().startswith('{') and '}' in content:
            analysis['format'] = 'json'
        elif any(indicator in content_lower for indicator in ['[section]', 'key=value', 'setting=']):
            analysis['format'] = 'ini'

        sensitive_data = self._extract_system_info(content)
        if sensitive_data:
            analysis['sensitive_data'] = sensitive_data

        if analysis['format'] != 'unknown' or analysis['sensitive_data']:
             analysis['is_sensitive'] = True

        return analysis

    def _extract_system_info(self, content: str) -> Dict[str, List[str]]:
        """Extracts structured sensitive information from text content."""
        info = {}
        for data_type, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    if data_type not in info:
                        info[data_type] = []
                    info[data_type].extend(matches[:5])
        return info

    def _determine_severity(self, analysis: Dict) -> str:
        """Determine severity based on analysis."""
        if not analysis.get('sensitive_data'):
            return "medium"

        high_risk_types = ['credentials']
        for data_type in analysis['sensitive_data']:
            if data_type in high_risk_types:
                return "critical"

        return "high"

    def _identify_interface_type(self, content_lower: str, path: str) -> str:
        """Identify the type of admin interface from content."""
        if any(brand in content_lower for brand in ['hikvision', 'hik-connect']):
            return "Hikvision Admin Panel"
        elif any(brand in content_lower for brand in ['dahua', 'dss']):
            return "Dahua Admin Panel"
        elif 'axis' in content_lower:
            return "Axis Admin Panel"
        elif 'sony' in content_lower:
            return "Sony Admin Panel"
        elif 'panasonic' in content_lower:
            return "Panasonic Admin Panel"
        elif any(term in content_lower for term in ['webcamxp', 'webcam']):
            return "WebcamXP Interface"
        elif any(term in content_lower for term in ['dvr', 'nvr', 'recorder']):
            return "DVR/NVR Management Interface"
        elif any(term in content_lower for term in ['camera', 'video', 'surveillance']):
            return "Camera Management Interface"
        elif 'configuration' in content_lower or 'settings' in content_lower:
            return "Configuration Interface"
        elif 'dashboard' in content_lower:
            return "Admin Dashboard"
        elif 'control panel' in content_lower:
            return "Control Panel"
        else:
            return "Generic Admin Interface"
