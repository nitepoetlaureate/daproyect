import os
import requests
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from dotenv import load_dotenv

# Absolute paths
BASE = "/Users/michaelraftery/daproyect"
DIST = os.path.join(BASE, "gridland3/frontend/dist")
load_dotenv(os.path.join(BASE, "gta_core/.env"))

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- DATA ENDPOINT ---
@app.get("/nearby")
async def nearby(lat: float, lon: float):
    key = os.getenv("SHODAN_API_KEY")
    url = f"https://api.shodan.io/shodan/host/search?key={key}&query=device:webcam geo:{lat},{lon},1"
    try:
        r = requests.get(url).json()
        return {"status": "SUCCESS", "nodes": r.get("matches", [])}
    except:
        return {"status": "ERROR", "nodes": []}

# --- STATIC FILE SERVING (The Fix for the Blank Page) ---
# We mount the ASSETS folder FIRST
if os.path.exists(os.path.join(DIST, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST, "assets")), name="assets")

# We serve everything else as a flat file
@app.get("/{path:path}")
async def serve_all(path: str):
    # 1. If path is empty or "/", serve index.html
    if not path or path == "/":
        return FileResponse(os.path.join(DIST, "index.html"))
    
    # 2. Check if it's a physical file (vite.svg, favicon, etc)
    full_path = os.path.join(DIST, path)
    if os.path.isfile(full_path):
        return FileResponse(full_path)
    
    # 3. Fallback to index.html for React Router
    return FileResponse(os.path.join(DIST, "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
