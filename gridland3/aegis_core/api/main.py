import json
import logging
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from .models import OSINTSignal, TargetNode

# Configure Aegis API Logger
logging.basicConfig(level=logging.INFO, format="[AEGIS API] %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Gridland Tactical Aegis",
    description="Multi-Agent Geo-SIGINT and Exploitation Hub",
    version="4.0.0"
)

# ---------------------------------------------------------
# Redis Pub/Sub WebSocket Telemetry Pipe (Task 1.1 / Task 1.3)
# ---------------------------------------------------------
class PubSubManager:
    """Manages active WebSockets and pipelines Redis broadcast events to the 3D HUD."""
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New HUD Telemetry Connection Established. Active users: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("HUD Telemetry Connection Dropped.")

    async def broadcast(self, message: dict):
        # In the future, this will pipe natively from aioredis pubsub.
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Failed to push to HUD: {e}")

telemetry_manager = PubSubManager()

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await telemetry_manager.connect(websocket)
    try:
        while True:
            # The UI doesn't send data here, it only listens. 
            # We await receive_text just to keep the connection alive.
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        telemetry_manager.disconnect(websocket)

@app.post("/api/intelligence/signal", tags=["OSINT"])
async def ingest_osint_signal(signal: OSINTSignal):
    """
    Ingest a new passive signal from Agent_01 (WireTapper).
    Publishes to the HUD immediately.
    """
    logger.info(f"Signal Detected: {signal.signal_type.upper()} [{signal.id}] at {signal.coordinates.latitude}, {signal.coordinates.longitude}")
    payload = {"event": "new_signal", "data": signal.model_dump()}
    await telemetry_manager.broadcast(payload)
    return {"status": "ingested", "id": signal.id}

@app.post("/api/intelligence/target", tags=["Active Recon"])
async def ingest_active_target(target: TargetNode):
    """
    Ingest a newly active, fingerprinted node from Agent_02 (CamXploit).
    """
    logger.info(f"Target Fingerprinted: {target.ip} - {target.detected_brand}")
    payload = {"event": "new_target", "data": target.model_dump()}
    await telemetry_manager.broadcast(payload)
    return {"status": "ingested", "ip": target.ip}

@app.get("/api/health")
async def health_check():
    """Verify ASGI Server status."""
    return {"status": "tactical_aegis_online", "components": {"fastapi": True}}
