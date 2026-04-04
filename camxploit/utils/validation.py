"""
Input validation utilities for CamXploit
Provides validation to prevent crashes while maintaining full functionality
"""

import ipaddress
import re
from typing import Union, List, Optional, Any
from urllib.parse import urlparse
from pathlib import Path
from ..core.exceptions import ValidationError


def validate_ip_address(ip: str) -> ipaddress.IPv4Address:
    """
    Validate and parse IP address
    
    Args:
        ip: IP address string
        
    Returns:
        Validated IPv4Address object
        
    Raises:
        ValidationError: If IP format is invalid only
    """
    if not isinstance(ip, str):
        raise ValidationError(
            f"IP must be string, got {type(ip)}",
            field='ip',
            value=ip
        )
        
    try:
        addr = ipaddress.IPv4Address(ip.strip())
    except ipaddress.AddressValueError as e:
        raise ValidationError(
            f"Invalid IP address format: {ip}",
            field='ip',
            value=ip
        ) from e
        
    # Only validate format, not scope - allow private, loopback, multicast
    return addr


def validate_port(port: Union[int, str]) -> int:
    """
    Validate port number
    
    Args:
        port: Port number as int or string
        
    Returns:
        Validated port number
        
    Raises:
        ValidationError: If port is invalid
    """
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        raise ValidationError(
            f"Invalid port: {port}",
            field='port',
            value=port
        )
        
    if not 1 <= port_num <= 65535:
        raise ValidationError(
            f"Port must be between 1-65535, got {port_num}",
            field='port',
            value=port_num
        )
        
    return port_num


def validate_port_range(port_range: str) -> List[int]:
    """
    Validate and parse port range
    
    Args:
        port_range: Port range like "80-443" or comma-separated "80,443,8080"
        
    Returns:
        List of port numbers
        
    Raises:
        ValidationError: If range is invalid
    """
    if not isinstance(port_range, str):
        raise ValidationError(
            f"Port range must be string, got {type(port_range)}",
            field='port_range',
            value=port_range
        )
        
    ports = set()
    
    # Handle comma-separated ports
    if ',' in port_range:
        for port in port_range.split(','):
            ports.add(validate_port(port.strip()))
            
    # Handle port range
    elif '-' in port_range:
        parts = port_range.split('-')
        if len(parts) != 2:
            raise ValidationError(
                f"Invalid port range format: {port_range}",
                field='port_range',
                value=port_range
            )
            
        start = validate_port(parts[0].strip())
        end = validate_port(parts[1].strip())
        
        if start > end:
            raise ValidationError(
                f"Invalid range: {start} > {end}",
                field='port_range',
                value=port_range
            )
            
        # Allow large ranges for comprehensive scanning
        ports.update(range(start, end + 1))
        
    # Single port
    else:
        ports.add(validate_port(port_range))
        
    return sorted(ports)


def validate_url(url: str) -> str:
    """
    Validate and normalize URL
    
    Args:
        url: URL string
        
    Returns:
        Normalized URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    if not isinstance(url, str):
        raise ValidationError(
            f"URL must be string, got {type(url)}",
            field='url',
            value=url
        )
        
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://', 'rtsp://', 'rtmp://')):
        url = f'http://{url}'
        
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(
            f"Invalid URL: {url}",
            field='url',
            value=url
        ) from e
        
    if not parsed.netloc:
        raise ValidationError(
            f"URL missing host: {url}",
            field='url',
            value=url
        )
        
    # Validate host is IP or domain
    host = parsed.hostname
    if not host:
        raise ValidationError(
            f"Cannot parse host from URL: {url}",
            field='url',
            value=url
        )
        
    # Accept any valid IP or domain format
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        # Domain validation - basic format check
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', host):
            raise ValidationError(
                f"Invalid hostname format: {host}",
                field='url',
                value=host
            )
            
    return url


def validate_credentials(username: str, password: str) -> tuple[str, str]:
    """
    Validate credentials format
    
    Args:
        username: Username string
        password: Password string
        
    Returns:
        Tuple of (username, password)
        
    Raises:
        ValidationError: If credentials are invalid
    """
    if not username or not isinstance(username, str):
        raise ValidationError(
            "Username must be non-empty string",
            field='username',
            value=username
        )
        
    if not password or not isinstance(password, str):
        raise ValidationError(
            "Password must be non-empty string",
            field='password',
            value=password
        )
        
    # Basic sanitization to prevent injection
    dangerous_chars = ['\0', '\n', '\r']
    for char in dangerous_chars:
        if char in username or char in password:
            raise ValidationError(
                f"Invalid character in credentials",
                field='credentials',
                value=f"contains control character"
            )
            
    return username.strip(), password.strip()


def sanitize_filepath(filepath: str) -> str:
    """
    Sanitize filepath to prevent directory traversal while preserving functionality
    
    Args:
        filepath: File path string
        
    Returns:
        Sanitized filepath
        
    Raises:
        ValidationError: If path is dangerous
    """
    if not isinstance(filepath, str):
        raise ValidationError(
            f"Filepath must be string, got {type(filepath)}",
            field='filepath',
            value=filepath
        )
        
    # Remove directory traversal attempts but allow absolute paths
    filepath = re.sub(r'\.{2,}', '', filepath)
    filepath = filepath.replace('\\\\', '\\')
    
    # Remove null bytes
    if '\0' in filepath:
        raise ValidationError(
            "Null byte in filepath",
            field='filepath',
            value=filepath
        )
        
    return filepath.strip()


def validate_timeout(timeout: Union[int, float]) -> float:
    """
    Validate timeout value
    
    Args:
        timeout: Timeout in seconds
        
    Returns:
        Validated timeout as float
        
    Raises:
        ValidationError: If timeout is invalid
    """
    try:
        timeout_float = float(timeout)
    except (TypeError, ValueError):
        raise ValidationError(
            f"Timeout must be numeric, got {type(timeout)}",
            field='timeout',
            value=timeout
        )
        
    if timeout_float <= 0:
        raise ValidationError(
            f"Timeout must be positive, got {timeout_float}",
            field='timeout',
            value=timeout_float
        )
        
    # Allow long timeouts for thorough scanning
    return timeout_float
