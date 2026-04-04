#!/bin/bash

# aegis_final_fix.sh - Dynamic Asset Discovery
# Locate the actual files on Michael's MacBook Pro

BASE="/Users/michaelraftery/daproyect"
CORE_DIR="$BASE/gta_core"

echo "--- Gridland Tactical Aegis: Scanning for Asset Markers ---"

# 1. Find where ChicagoFLF.woff is actually hiding
FONT_LOC=$(find "$BASE/gridland3" -name "ChicagoFLF.woff" | head -n 1)

if [ -z "$FONT_LOC" ]; then
    echo "[CRITICAL] Could not find ChicagoFLF.woff. System visuals will be janky."
    # Fallback to standard gridland3 static if find fails
    STATIC_PATH="$BASE/gridland3/static"
else
    # The static folder is two levels up from the font file
    STATIC_PATH=$(dirname "$(dirname "$FONT_LOC")")
    echo "[SUCCESS] Found Static Assets at: $STATIC_PATH"
fi

# 2. Kill port 8080
lsof -ti:8080 | xargs kill -9 2>/dev/null

# 3. Generate main.py with the REAL path found by the scan
cat << EOF > $CORE_DIR/main.py
import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from dotenv import load_dotenv

load_dotenv("$CORE_DIR/.env")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"])

# VERIFIED DYNAMIC PATHS
static_dir = "$STATIC_PATH"
ui_dist = "$BASE/gridland3/frontend/dist"

# Mounts
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    
if os.path.exists(ui_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(ui_dist, "assets")), name="assets")
    app.mount("/ui", StaticFiles(directory=ui_dist, html=True), name="ui")

@app.get("/health")
async def health():
    return {
        "status": "ONLINE",
        "detected_static": static_dir,
        "static_exists": os.path.exists(static_dir),
        "font_exists": os.path.exists(os.path.join(static_dir, "fonts/ChicagoFLF.woff"))
    }

@app.get("/nearby")
async def nearby(lat: float, lon: float):
    import requests
    auth = (os.getenv("WIGLE_API_NAME"), os.getenv("WIGLE_API_TOKEN"))
    url = f"https://api.wigle.net/api/v2/network/search?latrange1={lat-0.005}&latrange2={lat+0.005}&longrange1={lon-0.005}&longrange2={lon+0.005}"
    return requests.get(url, auth=auth).json()

@app.get("/")
async def root():
    return FileResponse(os.path.join(ui_dist, "index.html"))

EOF

echo "--- Launching Stack ---"
uv run uvicorn main:app --app-dir gta_core --port 8080 --reload
