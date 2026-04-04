from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import ipaddress

class CameraType(Enum):
    HIKVISION = "hikvision"
    DAHUA = "dahua"
    AXIS = "axis"
    CP_PLUS = "cp_plus"
    GENERIC = "generic"
    UNKNOWN = "unknown"

@dataclass
class Target:
    """Represents a scan target"""
    ip: ipaddress.IPv4Address
    ports: List[int] = field(default_factory=list)
    
    def __post_init__(self):
        if isinstance(self.ip, str):
            self.ip = ipaddress.IPv4Address(self.ip)
            
@dataclass
class Camera:
    """Represents a detected camera"""
    ip: str
    port: int
    type: CameraType
    model: Optional[str] = None
    firmware: Optional[str] = None
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: Optional[Dict[str, str]] = None
    streams: List[str] = field(default_factory=list)
    
@dataclass
class ScanSession:
    """Represents a complete scan session"""
    id: str
    targets: List[Target]
    start_time: float
    end_time: Optional[float] = None
    cameras: List[Camera] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
