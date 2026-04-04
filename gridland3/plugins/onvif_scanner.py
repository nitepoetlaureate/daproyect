"""
ONVIF Scanner Plugin for Gridland
ONVIF (Open Network Video Interface Forum) protocol testing and exploitation
"""
import requests
import socket
from typing import List, Dict, Optional
from xml.etree import ElementTree as ET
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os


class ONVIFScannerPlugin(ScannerPlugin):
    """
    ONVIF protocol scanner for IP cameras.
    Tests for ONVIF services, device information disclosure, and authentication issues.
    """
    
    def can_scan(self, target: ScanTarget) -> bool:
        """Check if target has ONVIF-capable ports"""
        # ONVIF typically runs on HTTP/HTTPS ports
        onvif_ports = [80, 443, 8080, 8443, 3702, 8000, 8001]
        return any(p.port in onvif_ports for p in target.open_ports)

    # ONVIF SOAP envelope templates
    ONVIF_REQUESTS = {
        "get_device_information": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetDeviceInformation/>
    </soap:Body>
</soap:Envelope>""",

        "get_capabilities": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetCapabilities/>
    </soap:Body>
</soap:Envelope>""",

        "get_services": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetServices>
            <tds:IncludeCapability>false</tds:IncludeCapability>
        </tds:GetServices>
    </soap:Body>
</soap:Envelope>""",

        "get_system_date_time": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetSystemDateAndTime/>
    </soap:Body>
</soap:Envelope>""",

        "get_users": """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <soap:Header/>
    <soap:Body>
        <tds:GetUsers/>
    </soap:Body>
</soap:Envelope>"""
    }

    # Common ONVIF endpoints
    ONVIF_ENDPOINTS = [
        "/onvif/device_service",
        "/onvif/Device",
        "/device_service",
        "/Device",
        "/onvif/services",
        "/cgi-bin/onvif_device_service",
        "/axis-cgi/onvif/device_service"
    ]

    def scan(self, target: ScanTarget, fingerprint: dict = None) -> List[Finding]:
        """Perform ONVIF protocol scanning"""
        findings = []
        proxy_url = os.environ.get('PROXY_URL')
        
        for port_result in target.open_ports:
            if port_result.port not in [80, 443, 8080, 8443, 3702, 8000, 8001]:
                continue
                
            protocol = "https" if port_result.port in [443, 8443] else "http"
            
            # Test each potential ONVIF endpoint
            for endpoint in self.ONVIF_ENDPOINTS:
                base_url = f"{protocol}://{target.ip}:{port_result.port}{endpoint}"
                endpoint_findings = self._test_onvif_endpoint(base_url, target.ip, port_result.port, proxy_url)
                findings.extend(endpoint_findings)
                
                # If we found a working ONVIF endpoint, don't test others on this port
                if endpoint_findings:
                    break
        
        # Test for ONVIF discovery via WS-Discovery (port 3702)
        if any(p.port == 3702 for p in target.open_ports):
            discovery_findings = self._test_ws_discovery(target.ip)
            findings.extend(discovery_findings)
            
        return findings

    def _test_onvif_endpoint(self, base_url: str, ip: str, port: int, proxy_url: str = None) -> List[Finding]:
        """Test a specific ONVIF endpoint"""
        findings = []
        
        headers = get_request_headers()
        headers.update({
            'Content-Type': 'application/soap+xml',
            'SOAPAction': ''
        })
        
        # Test different ONVIF requests
        for request_name, soap_request in self.ONVIF_REQUESTS.items():
            try:
                response = requests.post(
                    base_url,
                    data=soap_request,
                    headers=headers,
                    timeout=10,
                    verify=False,
                    proxies=get_proxies(proxy_url)
                )
                
                if response.status_code == 200 and 'soap' in response.text.lower():
                    # Parse ONVIF response
                    parsed_data = self._parse_onvif_response(response.text, request_name)
                    
                    if parsed_data:
                        finding = Finding(
                            category="onvif",
                            description=f"ONVIF {request_name.replace('_', ' ').title()} successful",
                            severity="medium",
                            port=port,
                            url=base_url,
                            data={
                                "request_type": request_name,
                                "onvif_data": parsed_data,
                                "endpoint": base_url
                            }
                        )
                        findings.append(finding)
                        
                        # Check for sensitive information disclosure
                        if self._contains_sensitive_info(parsed_data):
                            sensitive_finding = Finding(
                                category="vulnerability",
                                description="ONVIF service exposes sensitive device information",
                                severity="high",
                                port=port,
                                url=base_url,
                                data={
                                    "vulnerability_type": "information_disclosure",
                                    "exposed_data": parsed_data
                                }
                            )
                            findings.append(sensitive_finding)
                
                # Test for authentication bypass
                elif response.status_code == 401:
                    # Try without authentication first
                    bypass_finding = self._test_auth_bypass(base_url, soap_request, headers, port, proxy_url)
                    if bypass_finding:
                        findings.append(bypass_finding)
                        
            except requests.RequestException:
                continue
                
        return findings

    def _parse_onvif_response(self, xml_text: str, request_type: str) -> Optional[Dict]:
        """Parse ONVIF XML response and extract useful information"""
        try:
            # Remove namespaces for easier parsing
            xml_clean = xml_text.replace('xmlns:', 'xmlnamespace:')
            xml_clean = xml_clean.replace('xmlns=', 'xmlnamespace=')
            
            root = ET.fromstring(xml_clean)
            data = {}
            
            if request_type == "get_device_information":
                # Extract device information
                for elem in root.iter():
                    if 'manufacturer' in elem.tag.lower():
                        data['manufacturer'] = elem.text
                    elif 'model' in elem.tag.lower():
                        data['model'] = elem.text
                    elif 'firmwareversion' in elem.tag.lower():
                        data['firmware_version'] = elem.text
                    elif 'serialnumber' in elem.tag.lower():
                        data['serial_number'] = elem.text
                    elif 'hardwareid' in elem.tag.lower():
                        data['hardware_id'] = elem.text
                        
            elif request_type == "get_capabilities":
                # Extract capabilities
                capabilities = []
                for elem in root.iter():
                    if 'capability' in elem.tag.lower() or 'service' in elem.tag.lower():
                        capabilities.append(elem.tag)
                data['capabilities'] = capabilities
                
            elif request_type == "get_services":
                # Extract service information
                services = []
                for elem in root.iter():
                    if 'service' in elem.tag.lower():
                        service_info = {}
                        for child in elem:
                            service_info[child.tag] = child.text
                        if service_info:
                            services.append(service_info)
                data['services'] = services
                
            elif request_type == "get_users":
                # Extract user information (security sensitive!)
                users = []
                for elem in root.iter():
                    if 'user' in elem.tag.lower():
                        user_info = {}
                        for child in elem:
                            user_info[child.tag] = child.text
                        if user_info:
                            users.append(user_info)
                data['users'] = users
                
            elif request_type == "get_system_date_time":
                # Extract system time
                for elem in root.iter():
                    if 'time' in elem.tag.lower() or 'date' in elem.tag.lower():
                        data['system_time'] = elem.text
                        
            return data if data else None
            
        except ET.ParseError:
            return None

    def _contains_sensitive_info(self, data: Dict) -> bool:
        """Check if ONVIF response contains sensitive information"""
        sensitive_keys = [
            'serial_number', 'hardware_id', 'users', 'password',
            'firmware_version', 'mac_address', 'network_settings'
        ]
        
        for key in sensitive_keys:
            if key in data and data[key]:
                return True
                
        return False

    def _test_auth_bypass(self, url: str, soap_request: str, headers: Dict, port: int, proxy_url: str = None) -> Optional[Finding]:
        """Test for ONVIF authentication bypass vulnerabilities"""
        
        # Common authentication bypass techniques
        bypass_attempts = [
            # Try with empty credentials
            ("", ""),
            # Try with common default credentials
            ("admin", ""),
            ("admin", "admin"),
            ("root", "root"),
            # Try with SQL injection in SOAP header
            ("admin'--", ""),
            ("admin' OR '1'='1", "")
        ]
        
        for username, password in bypass_attempts:
            try:
                # Add authentication header
                auth_headers = headers.copy()
                if username or password:
                    import base64
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    auth_headers['Authorization'] = f'Basic {credentials}'
                
                response = requests.post(
                    url,
                    data=soap_request,
                    headers=auth_headers,
                    timeout=5,
                    verify=False,
                    proxies=get_proxies(proxy_url)
                )
                
                if response.status_code == 200 and 'soap' in response.text.lower():
                    return Finding(
                        category="vulnerability",
                        description=f"ONVIF authentication bypass with credentials: {username}:{password}",
                        severity="critical",
                        port=port,
                        url=url,
                        data={
                            "vulnerability_type": "authentication_bypass",
                            "credentials_used": f"{username}:{password}",
                            "method": "ONVIF SOAP"
                        }
                    )
                    
            except requests.RequestException:
                continue
                
        return None

    def _test_ws_discovery(self, ip: str) -> List[Finding]:
        """Test WS-Discovery protocol on port 3702"""
        findings = []
        
        # WS-Discovery probe message
        ws_discovery_probe = """<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" 
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
    <soap:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
        <wsa:MessageID>urn:uuid:12345678-1234-1234-1234-123456789012</wsa:MessageID>
        <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    </soap:Header>
    <soap:Body>
        <wsd:Probe>
            <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
        </wsd:Probe>
    </soap:Body>
</soap:Envelope>"""
        
        try:
            # Send UDP multicast probe
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Send to both unicast and multicast addresses
            addresses = [
                (ip, 3702),  # Unicast
                ('239.255.255.250', 3702)  # Multicast
            ]
            
            for addr in addresses:
                try:
                    sock.sendto(ws_discovery_probe.encode(), addr)
                    response, _ = sock.recvfrom(4096)
                    
                    if response and b'soap' in response.lower():
                        finding = Finding(
                            category="onvif",
                            description="WS-Discovery service found - ONVIF device discoverable",
                            severity="medium",
                            port=3702,
                            data={
                                "protocol": "WS-Discovery",
                                "response": response.decode('utf-8', errors='ignore')[:500]
                            }
                        )
                        findings.append(finding)
                        break
                        
                except socket.error:
                    continue
                    
            sock.close()
            
        except socket.error:
            pass
            
        return findings

    def get_description(self) -> str:
        """Get plugin description"""
        return "ONVIF protocol scanner for IP camera security assessment"