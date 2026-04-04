#!/bin/bash

# Gridland Tactical Aegis (GTA) - Absolute Integration Script
# Target Environment: /Users/michaelraftery/daproyect/

CORE_DIR="gta_core"
BASE_PATH="/Users/michaelraftery/daproyect"

echo "--- Rebuilding GTA Core Logic for Absolute Pathing ---"

# 1. Update main.py with the /nearby SIGINT bridge and camxploit integration
cat << EOF > $CORE_DIR/main.py
import os
import sys
import asyncio
from fastapi import FastAPI, WebSocket, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Path Discovery
BASE_DIR = "$BASE_PATH"
load_dotenv(os.path.join(BASE_DIR, "$CORE_DIR/.env"))

# Inject Local Repos into Path
sys.path.append(os.path.join(BASE_DIR, "camxploit"))
sys.path.append(os.path.join(BASE_DIR, "WireTapper"))

app = FastAPI(title="Gridland Tactical Aegis")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Mounts
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "gridland3/static")), name="static")
app.mount("/wt_images", StaticFiles(directory=os.path.join(BASE_DIR, "WireTapper/images")), name="wt_images")

# The SIGINT Bridge logic from WireTapper
@app.get("/nearby")
async def nearby(lat: float, lon: float):
    """
    Direct bridge to WireTapper discovery logic using local API keys.
    Returns Wi-Fi and Bluetooth SIGINT data.
    """
    import requests
    wigle_name = os.getenv("WIGLE_API_NAME")
    wigle_token = os.getenv("WIGLE_API_TOKEN")
    
    url = f"https://api.wigle.net/api/v2/network/search?latrange1={lat-0.01}&latrange2={lat+0.01}&longrange1={lon-0.01}&longrange2={lon+0.01}"
    auth = (wigle_name, wigle_token)
    response = requests.get(url, auth=auth)
    return response.json()

@app.get("/health")
async def health():
    return {"status": "ONLINE", "base_dir": BASE_DIR}

@app.websocket("/ws/telemetry")
async def telemetry_bridge(websocket: WebSocket):
    await websocket.accept()
    while True:
        await websocket.send_json({"heartbeat": "synced", "geo": "Philly_Anchor"})
        await asyncio.sleep(5)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
EOF

# 2. Fix the Agent to link CamXploit Scanner
cat << EOF > $CORE_DIR/agents/stream_validator.py
import sys
import os
import asyncio

# Hard-coded linkage to CamXploit core
sys.path.append("$BASE_PATH/camxploit")

try:
    # Attempting to import the specific Scanner class from your local camxploit tree
    from core.scanner import Scanner
    print("[GTA_AGENT] Successfully linked CamXploit Intelligence.")
except ImportError as e:
    print(f"[GTA_AGENT] Critical Linkage Failure: {e}")

async def validate_target(ip):
    # Wrapper for camxploit scanning
    return {"ip": ip, "status": "Ready for Scan"}
EOF

echo "GTA Core Rebuilt. Starting Server..."
uv run uvicorn main:app --app-dir gta_core --port 8080 --reload
