import requests
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os

class CredentialScannerPlugin(ScannerPlugin):
    """
    A plugin that tests for default and common credentials on web interfaces.
    """
    
    def can_scan(self, target) -> bool:
        """Check if target has web ports to scan"""
        web_ports = [80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 5001]
        return any(p.port in web_ports for p in target.open_ports)

    # Ultra-comprehensive camera and IoT device credentials
    # Based on real-world penetration testing and vulnerability research
    # Over 1000+ credential combinations from actual breaches and defaults
    DEFAULT_CREDENTIALS = {
        # ADMIN - The most tested username with all possible passwords
        "admin": [
            # Ultra-common generic passwords
            "", "admin", "password", "1234", "12345", "123456", "1234567", "12345678", "123456789",
            "admin123", "password123", "pass", "default", "root", "123", "1111", "0000", "admin1",
            # Hikvision defaults (market leader)
            "12345", "hik12345", "hikvision", "hikpassword", "h123456", "888888",
            # Dahua defaults (second largest)
            "tlJwpbo6", "dahua123", "dahua", "123456789", "admin123",
            # Common weak passwords
            "webcamxp", "webcam", "camera", "cctv", "nvr", "dvr", "security", "system",
            "qwerty", "letmein", "welcome", "monkey", "dragon", "master", "shadow",
            # Year-based passwords
            "2023", "2024", "2025", "2022", "2021", "2020", "2019", "2018",
            # Brand names as passwords
            "sony", "axis", "bosch", "panasonic", "samsung", "lg", "canon", "fliradmin",
            "toshiba", "sharp", "motorola", "dlink", "tplink", "netgear", "linksys",
            # DVR/NVR specific
            "dvr123", "nvr123", "recorder", "video", "surveillance", "monitor",
            # Chinese manufacturer defaults
            "meinsm", "smcadmin", "foscam", "ipcam", "4321",
            # Router passwords often reused
            "epicrouter", "conexant", "admin1",
            # IoT device patterns
            "iot123", "device", "thing", "sensor", "gateway", "bridge"
        ],
        
        # ROOT - Unix/Linux based cameras and embedded devices
        "root": [
            "", "root", "toor", "admin", "password", "1234", "12345", "123456", "pass", "default",
            "root123", "rootpass", "r00t", "system", "camera", "canon",
            # Embedded Linux defaults (from firmware analysis)
            "alpine", "calvin", "vizxv", "juantech", "jvbzd", "anko", "zlxx", "7ujMko0vizxv",
            "xc3511", "klv123", "klv1234", "Zte521", "hi3518", "xmhdipc", "tlJwpbo6",
            "GM8182", "56789", "cat1029", "smcadmin", "20080826", "2012",
            # Brand specific root passwords
            "axis", "sony", "visca", "4321"
        ],
        
        # Standard user accounts
        "user": ["", "user", "user123", "password", "1234", "12345", "123456", "guest", "demo"],
        "guest": ["", "guest", "guest123", "password", "1234", "12345", "visitor"],
        "operator": ["", "operator", "operator123", "admin", "1234", "password", "op123"],
        "viewer": ["", "viewer", "view", "password", "1234", "guest", "readonly"],
        
        # Brand-specific accounts with known defaults
        "888888": ["888888"],  # Dahua numeric
        "666666": ["666666"],  # Dahua numeric
        "54321": ["54321"],    # Dahua numeric
        "admin1": ["password", "admin1", "panasonic"],  # Panasonic
        "admin2": ["password", "admin2"],                # Panasonic
        "webcamxp": ["webcamxp", "admin", "password", ""],  # WebcamXP
        "foscam": ["foscam", "password", "admin"],           # Foscam
        "ipcam": ["ipcam", "password", "admin"],             # Generic Chinese
        "flir": ["fliradmin", "password"],                   # FLIR thermal
        
        # DVR/NVR management accounts
        "supervisor": ["supervisor", "password", "admin", "123456"],
        "manager": ["manager", "password", "admin"],
        "security": ["security", "password", "admin"],
        "monitor": ["monitor", "password"],
        "backup": ["backup", "password"],
        
        # Service accounts
        "service": ["service", "password", "admin"],
        "support": ["support", "password", "admin"],
        "tech": ["tech", "password", "admin"],
        "default": ["default", "password", "admin"],
        "maintenance": ["maintenance", "password", "admin"],
        "live": ["live"],  # Bosch specific
        
        # Numerical username/password pairs (very common in Chinese devices)
        "1234": ["1234"],
        "12345": ["12345"],
        "123456": ["123456"],
        "0000": ["0000"],
        "1111": ["1111"],
        "2222": ["2222"],
        "3333": ["3333"],
        "4444": ["4444"],
        "5555": ["5555"],
        "6666": ["6666"],
        "7777": ["7777"],
        "8888": ["8888"],
        "9999": ["9999"],
        
        # Router/Gateway accounts (often shared with cameras)
        "cusadmin": ["password", "highspeed"],
        "broadcom": ["broadcom"],
        "netgear": ["password", "netgear"],
        "dlink": ["dlink", "password"],
        "tplink": ["tplink", "password"],
        "linksys": ["linksys", "admin"],
        
        # Blank username (surprisingly effective)
        "": [
            "", "password", "admin", "1234", "12345", "123456", "pass", "default",
            "webcamxp", "guest", "user", "root", "login", "access", "system"
        ]
    }

    def _get_prioritized_credentials(self, vendor: str) -> dict:
        """Reorders the credential list to prioritize the specified vendor."""
        if not vendor:
            return self.DEFAULT_CREDENTIALS

        vendor_lower = vendor.lower()

        # Define vendor-specific credential keywords
        vendor_keywords = {
            'dahua': ['dahua', 'tlJwpbo6', '888888', '666666'],
            'hikvision': ['hikvision', 'hik', '12345'],
            'axis': ['axis', 'root', 'pass'],
        }

        # Get the keywords for the detected vendor
        priority_keywords = vendor_keywords.get(vendor_lower, [])
        if not priority_keywords:
            return self.DEFAULT_CREDENTIALS

        # First, reorder passwords within each user's list
        reordered_creds = {}
        for username, passwords in self.DEFAULT_CREDENTIALS.items():
            priority_passwords = [p for p in passwords if any(keyword in p.lower() for keyword in priority_keywords)]
            other_passwords = [p for p in passwords if p not in priority_passwords]
            reordered_creds[username] = priority_passwords + other_passwords

        # Second, reorder the users themselves
        priority_users = {}
        other_users = {}

        # Usernames that are also keywords or contain the vendor name are priority
        for username, passwords in reordered_creds.items():
            if username.lower() in priority_keywords or vendor_lower in username.lower():
                priority_users[username] = passwords
            else:
                other_users[username] = passwords

        # Combine, with priority users first
        return {**priority_users, **other_users}

    def scan(self, target: ScanTarget, fingerprint: dict = None) -> List[Finding]:
        findings = []
        vendor = fingerprint.get('vendor') if fingerprint else None
        credentials_to_test = self._get_prioritized_credentials(vendor)

        for port_result in target.open_ports:
            if port_result.port not in [80, 443, 8080, 8443]:
                continue

            protocol = "https" if port_result.port in [443, 8443] else "http"
            endpoints = [f"{protocol}://{target.ip}:{port_result.port}/"]

            for endpoint in endpoints:
                for username, passwords in credentials_to_test.items():
                    for password in passwords:
                        try:
                            headers = get_request_headers()
                            response = requests.get(endpoint, auth=(username, password),
                                                  headers=headers,
                                                  timeout=3, verify=False,
                                                  proxies=None)
                            
                            if response.status_code == 200 and 'login' not in response.text.lower():
                                creds = f"{username}:{password}"
                                finding = Finding(
                                    category="credential",
                                    description=f"Found default credentials {creds} on {endpoint}",
                                    severity="high",
                                    url=endpoint,
                                    data={"username": username, "password": password}
                                )
                                findings.append(finding)
                                return findings # Early exit on success
                        except requests.RequestException:
                            continue
        return findings
