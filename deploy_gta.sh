#!/bin/bash

# Gridland Tactical Aegis (GTA) - Absolute Local Deployment
# Target: ~/daproyect/
# Logic: Bridges local 'gridland3', 'camxploit', and 'WireTapper'

CORE_DIR="gta_core"
BASE_PATH=$(pwd)

echo "--- Re-initializing GTA Architecture at $BASE_PATH ---"

# 1. Clean and Create fresh structure
mkdir -p $CORE_DIR/static/js $CORE_DIR/static/css $CORE_DIR/agents $CORE_DIR/logs

# 2. Generate main.py (The Asynchronous Hub)
cat << EOF > $CORE_DIR/main.py
import os
import asyncio
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Path Discovery
BASE_DIR = "$BASE_PATH"
load_dotenv(os.path.join(BASE_DIR, "$CORE_DIR/.env"))

app = FastAPI(title="Gridland Tactical Aegis")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared Telemetry State
class SignalState:
    def __init__(self):
        self.targets = []

state = SignalState()

# Mounting Local Assets from your project tree
# Utilizing absolute paths derived from your 'tree' command results
grid_static = os.path.join(BASE_DIR, "gridland3/static")
grid_ui = os.path.join(BASE_DIR, "gridland3/frontend") # Mapping to Vite-based frontend
wt_images = os.path.join(BASE_DIR, "WireTapper/images")

if os.path.exists(grid_static):
    app.mount("/static", StaticFiles(directory=grid_static), name="static")
if os.path.exists(grid_ui):
    app.mount("/ui", StaticFiles(directory=grid_ui), name="ui")
if os.path.exists(wt_images):
    app.mount("/wt_images", StaticFiles(directory=wt_images), name="wt_images")

@app.get("/health")
async def health():
    return {"status": "ONLINE", "base_dir": BASE_DIR}

@app.websocket("/ws/telemetry")
async def telemetry_bridge(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            await websocket.send_json({"heartbeat": "synced", "active_path": BASE_DIR})
            await asyncio.sleep(5)
    except Exception:
        pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
EOF

# 3. Generate aegis_map.js (3D Geospatial Engine)
cat << EOF > $CORE_DIR/static/js/aegis_map.js
// GTA 3D Geospatial Engine (deck.gl)
// Centered on Philadelphia per system context

const INITIAL_VIEW = {
  latitude: 39.9526, 
  longitude: -75.1652, 
  zoom: 15, 
  pitch: 60,
  bearing: 0
};

// This script expects a div with id 'aegis-canvas' 
// to be present in your gridland3 index.html
console.log("GTA 3D Engine Initialized at coordinates: ", INITIAL_VIEW);
EOF

# 4. Generate stream_validator.py (Agent_03)
# Directly utilizes the camxploit core logic found in your tree
cat << EOF > $CORE_DIR/agents/stream_validator.py
import sys
import os

# Link to your local camxploit directory
sys.path.append("$BASE_PATH/camxploit")

try:
    from core.scanner import Scanner
    print("[SUCCESS] CamXploit Scanner linked to GTA Agent.")
except ImportError:
    print("[ERROR] Could not find camxploit/core/scanner.py")

async def run_validation(target_ip):
    # This logic bridges camxploit's port scanner with the GTA UI
    pass
EOF

# 5. Populate .env if not exists
if [ ! -f $CORE_DIR/.env ]; then
cat << EOF > $CORE_DIR/.env
SHODAN_API_KEY=""
WIGLE_API_NAME=""
WIGLE_API_TOKEN=""
MAPBOX_ACCESS_TOKEN=""
EOF
fi

echo "GTA_CORE Sync Complete."
echo "1. Edit $CORE_DIR/.env with your keys."
echo "2. Run: uv run uvicorn main:app --app-dir gta_core --port 8080 --reload"
