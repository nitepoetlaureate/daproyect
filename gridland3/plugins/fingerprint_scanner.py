"""
Fingerprint Scanner Plugin for Gridland
Core intelligence component for identifying target services and technologies.
"""
import socket
import requests
import ssl
import re
from typing import List, Dict, Optional, Tuple
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os

class FingerprintScannerPlugin(ScannerPlugin):
    """
    Performs deep fingerprinting of services to identify vendor, product, and version.
    This is the core intelligence gathering plugin.
    """

    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has any open ports for fingerprinting."""
        return len(target.open_ports) > 0

    def get_description(self) -> str:
        """Get plugin description."""
        return "Core intelligence plugin for service and technology fingerprinting."

    def scan(self, target: ScanTarget) -> List[Finding]:
        """
        Perform comprehensive fingerprinting and return structured findings.
        """
        findings = []
        proxy_url = os.environ.get('PROXY_URL')
        fingerprint_data = {
            "vendor": None,
            "product": None,
            "version": None,
            "ports": {}
        }

        for port_result in target.open_ports:
            port = port_result.port
            service_info = {}

            if port in [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085]:
                service_info = self._grab_http_banner(target.ip, port, proxy_url)
            elif port in [554, 8554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554]:
                service_info = self._grab_rtsp_banner(target.ip, port)
            elif port == 22:
                service_info = self._grab_ssh_banner(target.ip, port)
            elif port == 21:
                service_info = self._grab_ftp_banner(target.ip, port)
            elif port == 23:
                service_info = self._grab_telnet_banner(target.ip, port)
            else:
                service_info = self._grab_generic_banner(target.ip, port)

            if service_info:
                fingerprint_data["ports"][port] = service_info
                if not fingerprint_data["vendor"] and service_info.get("vendor"):
                    fingerprint_data["vendor"] = service_info.get("vendor")
                if not fingerprint_data["product"] and service_info.get("product"):
                    fingerprint_data["product"] = service_info.get("product")
                if not fingerprint_data["version"] and service_info.get("version"):
                    fingerprint_data["version"] = service_info.get("version")

        if fingerprint_data["vendor"] or any(fingerprint_data["ports"].values()):
            finding = Finding(
                category="fingerprint",
                description=f"Device fingerprint identified: {fingerprint_data.get('vendor') or 'Unknown'}",
                severity="info",
                port=next(iter(fingerprint_data["ports"]), None), # Report on first found port
                data=fingerprint_data
            )
            findings.append(finding)

        return findings

    def _grab_http_banner(self, ip: str, port: int, proxy_url: Optional[str] = None) -> Dict:
        """Grab HTTP/HTTPS banners and extract detailed information."""
        protocols = ["https"] if port in [443, 8443] else ["http", "https"]

        for protocol in protocols:
            try:
                url = f"{protocol}://{ip}:{port}"
                response = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    headers=get_request_headers(),
                    proxies=get_proxies(proxy_url)
                )

                # Analyze response for fingerprint
                return self._analyze_http_response(response)

            except requests.RequestException:
                continue
        return {}

    def _analyze_http_response(self, response: requests.Response) -> Dict:
        """Analyzes an HTTP response to build a detailed service fingerprint."""
        headers = response.headers
        content = response.text

        # Primary identifiers
        server_header = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')

        # Dahua-specific header
        if 'Dahua' in server_header:
            vendor = 'Dahua'
        # Hikvision-specific header
        elif 'Hikvision' in server_header:
            vendor = 'Hikvision'
        # Axis-specific header
        elif 'Axis' in server_header:
            vendor = 'Axis'
        else:
            # Fallback to content analysis
            vendor = self._analyze_content_for_vendor(content)

        product, version = self._extract_product_version(server_header, content)

        return {
            "service": "http",
            "vendor": vendor,
            "product": product or "Unknown",
            "version": version or "Unknown",
            "server_header": server_header,
            "powered_by": powered_by,
            "full_headers": dict(headers)
        }

    def _analyze_content_for_vendor(self, content: str) -> Optional[str]:
        """Analyzes HTML content to determine the vendor."""
        content_lower = content.lower()
        if 'dahua' in content_lower or ('web service' in content_lower and 'login' in content_lower):
            return 'Dahua'
        if 'hikvision' in content_lower:
            return 'Hikvision'
        if 'axis' in content_lower:
            return 'Axis'
        if 'sony' in content_lower:
            return 'Sony'
        if 'panasonic' in content_lower:
            return 'Panasonic'
        if 'bosch' in content_lower:
            return 'Bosch'
        return None

    def _extract_product_version(self, server_header: str, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extracts product and version from server headers and content."""
        # Try server header first
        match = re.search(r'([\w-]+)/([\d.]+)', server_header)
        if match:
            return match.group(1), match.group(2)

        # Fallback to content analysis (example for Dahua)
        if 'dahua' in content.lower():
            match = re.search(r'version:?\s*([\d.]+)', content, re.IGNORECASE)
            if match:
                return "Camera Web UI", match.group(1)

        return None, None

    def _grab_rtsp_banner(self, ip: str, port: int) -> Dict:
        """Grab RTSP service banners."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                request = f"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Gridland Scanner\r\n\r\n"
                sock.send(request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')

                server_match = re.search(r"Server:\s*([^\r\n]+)", response, re.IGNORECASE)
                if server_match:
                    server_info = server_match.group(1).strip()
                    vendor, product, version = self._parse_server_string(server_info)
                    return {
                        "service": "rtsp",
                        "vendor": vendor,
                        "product": product,
                        "version": version,
                        "server_header": server_info,
                        "full_response": response
                    }
        except (socket.error, UnicodeDecodeError):
            pass
        return {}

    def _grab_ssh_banner(self, ip: str, port: int) -> Dict:
        """Grab SSH service banners."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner.startswith('SSH-'):
                    version_match = re.search(r"SSH-([\d.]+)-?([^\s\r\n]*)", banner)
                    if version_match:
                        version, software = version_match.groups()
                        return {
                            "service": "ssh",
                            "vendor": self._vendor_from_software(software),
                            "product": software,
                            "version": version,
                            "banner": banner
                        }
        except (socket.error, UnicodeDecodeError):
            pass
        return {}

    def _grab_ftp_banner(self, ip: str, port: int) -> Dict:
        """Grab FTP service banners."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner.startswith('220'):
                    # Example: 220-FileZilla Server 0.9.60 beta
                    match = re.search(r'220[ -]([^\s]+)\s*server\s*([\d.]+)?', banner, re.IGNORECASE)
                    if match:
                        product, version = match.groups()
                        return {
                            "service": "ftp",
                            "vendor": product, # Often the product is the vendor
                            "product": product,
                            "version": version,
                            "banner": banner
                        }
        except (socket.error, UnicodeDecodeError):
            pass
        return {}

    def _grab_telnet_banner(self, ip: str, port: int) -> Dict:
        """Grab Telnet service banners."""
        try:
            with socket.create_connection((ip, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner and len(banner) > 5:
                    vendor = self._analyze_content_for_vendor(banner)
                    return {
                        "service": "telnet",
                        "vendor": vendor,
                        "product": "Telnet Service",
                        "version": None,
                        "banner": banner
                    }
        except (socket.error, UnicodeDecodeError):
            pass
        return {}

    def _grab_generic_banner(self, ip: str, port: int) -> Dict:
        """Grab banners from unknown services."""
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
                if banner and len(banner) > 5:
                    return {
                        "service": "unknown",
                        "vendor": None,
                        "product": None,
                        "version": None,
                        "banner": banner
                    }
        except (socket.error, UnicodeDecodeError):
            pass
        return {}

    def _parse_server_string(self, server_string: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parses a server string to extract vendor, product, and version."""
        # Example: "Dahua-Device/1.1" or "Hikvision-NVR/2.3"
        match = re.match(r'([\w-]+)/([\d.]+)', server_string)
        if match:
            product, version = match.groups()
            vendor = product.split('-')[0]
            return vendor, product, version

        # Example: "Server: RTSP Server/2.0"
        if "rtsp" in server_string.lower():
            return "Generic", "RTSP Server", server_string.split('/')[-1]

        return None, server_string, None

    def _vendor_from_software(self, software: str) -> Optional[str]:
        """Infers vendor from SSH software string."""
        if 'dropbear' in software.lower():
            return 'Dropbear'
        if 'openssh' in software.lower():
            return 'OpenSSH'
        return None