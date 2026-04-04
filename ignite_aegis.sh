#!/bin/bash

# ignite_aegis.sh - Final Integration Logic
# Target: /Users/michaelraftery/daproyect/

echo "--- Gridland Tactical Aegis: Ignition Sequence Start ---"

# 1. Kill any zombie processes on port 8080
lsof -ti:8080 | xargs kill -9 2>/dev/null

# 2. Hardcoded Absolute Paths from your tree output
BASE="/Users/michaelraftery/daproyect"
GRID_DEEP="$BASE/gridland3/gridland3-bb8a273349b9ab08d0e8ed09b41efb8a312de779"
CORE_DIR="$BASE/gta_core"

# 3. Ensure 'requests' is available for the SIGINT bridge
uv pip install requests python-dotenv

# 4. Generate the Unified Main Server
cat << EOF > $CORE_DIR/main.py
import os
import sys
import asyncio
from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Absolute Pathing to prevent context loss
load_dotenv("$CORE_DIR/.env")

app = FastAPI(title="Gridland Tactical Aegis")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Direct Mounts using EXACT paths from tree
static_path = "$GRID_DEEP/static"
ui_path = "$GRID_DEEP/gridland-ui"
wt_images = "$BASE/WireTapper/images"

# Mounting with check_dir=False prevents startup crash
if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path, check_dir=False), name="static")
if os.path.exists(ui_path):
    app.mount("/ui", StaticFiles(directory=ui_path, check_dir=False), name="ui")
if os.path.exists(wt_images):
    app.mount("/wt_images", StaticFiles(directory=wt_images, check_dir=False), name="wt_images")

@app.get("/health")
async def health():
    return {
        "status": "ONLINE",
        "path_verification": {
            "static_root": static_path,
            "static_found": os.path.exists(static_path),
            "ui_found": os.path.exists(ui_path)
        }
    }

@app.get("/nearby")
async def nearby(lat: float, lon: float):
    import requests
    auth = (os.getenv("WIGLE_API_NAME"), os.getenv("WIGLE_API_TOKEN"))
    url = f"https://api.wigle.net/api/v2/network/search?latrange1={lat-0.005}&latrange2={lat+0.005}&longrange1={lon-0.005}&longrange2={lon+0.005}"
    r = requests.get(url, auth=auth)
    return r.json()

@app.websocket("/ws/telemetry")
async def telemetry_bridge(websocket: WebSocket):
    await websocket.accept()
    while True:
        await websocket.send_json({"heartbeat": "online"})
        await asyncio.sleep(5)
EOF

echo "--- Logic Stabilized. Launching Asynchronous Stack ---"
uv run uvicorn main:app --app-dir gta_core --port 8080 --reload
