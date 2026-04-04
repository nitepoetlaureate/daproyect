import requests
import socket
from typing import List
from lib.plugins import ScannerPlugin, Finding
from lib.core import ScanTarget
from lib.evasion import get_request_headers, get_proxies
import os

class StreamScannerPlugin(ScannerPlugin):
    """
    A plugin that discovers common RTSP and HTTP video streams.
    """
    
    def can_scan(self, target) -> bool:
        """Check if target has streaming ports"""
        stream_ports = [554, 8554, 80, 443, 8080, 8443, 5001]
        return any(p.port in stream_ports for p in target.open_ports)

    RTSP_PATHS = ['/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub']
    HTTP_PATHS = ['/video', '/video.mjpg', '/stream', '/mjpg/video.mjpg', '/snapshot.jpg', '/cgi-bin/video.cgi', '/video.jpg', '/video.cgi', '/']
    HTTP_TIMEOUT = 3

    def _test_rtsp_stream(self, ip: str, port: int) -> bool:
        """
        Tests for a valid RTSP stream by sending an OPTIONS request.
        Returns True only if the server responds with RTSP/1.0 200 OK.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.HTTP_TIMEOUT)
                sock.connect((ip, port))

                # Send RTSP OPTIONS request
                rtsp_request = f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                sock.sendall(rtsp_request.encode('utf-8'))

                # Read response
                response = sock.recv(1024).decode('utf-8', errors='ignore')

                # Check for a valid RTSP 200 OK response
                return "RTSP/1.0 200 OK" in response

        except (socket.error, socket.timeout):
            return False

    def _verify_http_stream(self, url: str, verify_ssl: bool = False) -> bool:
        """
        Verifies if a stream URL is active by reading a small chunk of the stream.
        """
        try:
            response = requests.get(url, timeout=self.HTTP_TIMEOUT, verify=verify_ssl, stream=True, headers=get_request_headers())
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if any(t in content_type for t in ['video', 'image', 'mjpeg', 'jpeg', 'application/octet-stream', 'x-mixed-replace']):
                    return True
            return False
        except requests.RequestException:
            return False

    def scan(self, target: ScanTarget, fingerprint: dict = None) -> List[Finding]:
        findings = []
        # Organize ports by protocol
        rtsp_ports = [p for p in target.open_ports if p.port in [554, 8554]]
        http_ports = [p for p in target.open_ports if p.port in [80, 443, 8080, 8443]]

        # Check HTTP streams first
        for port_result in http_ports:
            protocol = "https" if port_result.port in [443, 8443] else "http"
            base_url = f"{protocol}://{target.ip}:{port_result.port}"

            # Check common stream paths
            for path in self.HTTP_PATHS:
                url = f"{base_url}{path}"
                if self._verify_http_stream(url):
                    finding = Finding(
                        category="stream",
                        description=f"Verified HTTP stream found at {url}",
                        severity="medium",
                        url=url,
                        data={"protocol": "http", "path": path}
                    )
                    findings.append(finding)
                    break  # Found one stream on this port, move to next

        # Then check RTSP streams
        for port_result in rtsp_ports:
            if self._test_rtsp_stream(target.ip, port_result.port):
                # If the server responds correctly, we can assume standard paths might work
                for path in self.RTSP_PATHS:
                    url = f"rtsp://{target.ip}:{port_result.port}{path}"
                    finding = Finding(
                        category="stream",
                        description=f"Verified RTSP service at {url}",
                        severity="medium",
                        url=url,
                        data={"protocol": "rtsp", "path": path}
                    )
                    findings.append(finding)
                break  # Found RTSP stream on this port, move to next
        return findings
