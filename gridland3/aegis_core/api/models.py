from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field

class GISCoordinate(BaseModel):
    """Pydantic model for strict GPS coordinate validation."""
    latitude: float = Field(..., ge=-90, le=90, description="Latitude of the signal or target")
    longitude: float = Field(..., ge=-180, le=180, description="Longitude of the signal or target")
    altitude: Optional[float] = Field(None, description="Altitude/Z-Axis triangulation floor level")

class OSINTSignal(BaseModel):
    """Pydantic model for WireTapper passive signal intelligence."""
    id: str = Field(..., description="Unique identifier (BSSID, MAC, or Cell ID)")
    signal_type: str = Field(..., description="Type of signal: wifi, bluetooth, cell_tower")
    rssi: float = Field(..., description="Signal strength indicator for 3D Heatmap rendering")
    vendor: Optional[str] = None
    classified_device_type: Optional[str] = Field(None, description="Output from classify_device() engine")
    coordinates: GISCoordinate
    
class TargetNode(BaseModel):
    """Pydantic model for Gridland active reconnaissance node."""
    ip: str = Field(..., description="IPv4 or IPv6 target address")
    open_ports: List[int] = Field(default_factory=list)
    detected_brand: Optional[str] = None
    firmware_version: Optional[str] = None
    coordinates: Optional[GISCoordinate] = None # Snapped from OSINT anchors
    
    model_config = ConfigDict(from_attributes=True)
