#!/bin/bash

# ignite_final.sh - The Absolute Nexus
# Target: /Users/michaelraftery/daproyect/

BASE="/Users/michaelraftery/daproyect"
CORE_DIR="$BASE/gta_core"
# Based on your npm run build earlier:
UI_DIST="$BASE/gridland3/frontend/dist"

echo "--- Gridland Tactical Aegis: Final Path Hardening ---"

# 1. Kill port 8080
lsof -ti:8080 | xargs kill -9 2>/dev/null

# 2. Build the Hub
cat << EOF > $CORE_DIR/main.py
import os
import sys
import requests
import asyncio
from fastapi import FastAPI, WebSocket, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv

load_dotenv("$CORE_DIR/.env")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# MOUNT 1: THE VITE ASSETS (CRITICAL FIX FOR 404s)
# Vite expects /assets/... not /ui/assets/...
if os.path.exists("$UI_DIST/assets"):
    app.mount("/assets", StaticFiles(directory="$UI_DIST/assets"), name="assets")

# MOUNT 2: WIRE TAPPER ICONOGRAPHY
if os.path.exists("$BASE/WireTapper/images"):
    app.mount("/wt_images", StaticFiles(directory="$BASE/WireTapper/images"), name="wt_images")

@app.get("/nearby")
async def nearby(lat: float, lon: float):
    """
    Pulls real Shodan nodes for Philly. 
    Matches the JSON output you verified.
    """
    shodan_key = os.getenv("SHODAN_API_KEY")
    query = f"device:webcam geo:{lat},{lon},1"
    url = f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query={query}"
    r = requests.get(url)
    data = r.json()
    
    # Flatten for the map rendering engine
    nodes = []
    for match in data.get("matches", []):
        nodes.append({
            "type": "camera",
            "lat": match.get("location", {}).get("latitude"),
            "lon": match.get("location", {}).get("longitude"),
            "ip": match.get("ip_str"),
            "label": match.get("product", "Tactical Node"),
            "port": match.get("port")
        })
    return {"status": "SUCCESS", "nodes": nodes}

@app.get("/health")
async def health():
    return {"status": "ONLINE", "dist_exists": os.path.exists("$UI_DIST")}

@app.get("/")
async def root():
    index_path = os.path.join("$UI_DIST", "index.html")
    with open(index_path, "r") as f:
        html = f.read()
    
    # Force retro font injection
    retro_css = '<link rel="stylesheet" href="https://unpkg.com/@sakun/system.css" />'
    return HTMLResponse(content=html.replace("</head>", f"{retro_css}</head>"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
EOF

echo "--- Launching Corrected Stack ---"
uv run uvicorn main:app --app-dir gta_core --port 8080 --reload
