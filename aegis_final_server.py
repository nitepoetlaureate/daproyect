import os
import requests
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from dotenv import load_dotenv

# Load real keys from your specific .env location
load_dotenv("/Users/michaelraftery/daproyect/gta_core/.env")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# --- PHYSICAL MOUNTING (The Fix for 404s) ---
# Vite looks for /assets/file.js. We map it directly to the physical folder.
if os.path.exists("/Users/michaelraftery/daproyect/gridland3/frontend/dist/assets"):
    app.mount("/assets", StaticFiles(directory="/Users/michaelraftery/daproyect/gridland3/frontend/dist/assets"), name="assets")

# --- UNIFIED INTELLIGENCE ENDPOINT (The Fix for Empty Map) ---
@app.get("/nearby")
async def nearby(lat: float, lon: float):
    shodan_key = os.getenv("SHODAN_API_KEY")
    ocid_key = os.getenv("OPENCELLID_API_KEY")
    
    # Discovery: Finding Cameras and Towers in a 1km radius
    results = {"nodes": []}
    
    # 1. Real Shodan Camera Search
    try:
        s_url = f"https://api.shodan.io/shodan/host/search?key={shodan_key}&query=device:webcam geo:{lat},{lon},1"
        s_data = requests.get(s_url).json()
        for m in s_data.get("matches", []):
            results["nodes"].append({
                "id": m.get("ip_str"),
                "type": "camera",
                "lat": m.get("location", {}).get("latitude"),
                "lon": m.get("location", {}).get("longitude"),
                "label": m.get("product", "Tactical Camera")
            })
    except: pass

    # 2. Real Cell Tower Discovery
    try:
        c_url = f"https://opencellid.org/cell/getInArea?key={ocid_key}&lat={lat}&lon={lon}&range=1000&format=json"
        c_data = requests.get(c_url).json()
        for c in c_data.get("cells", []):
            results["nodes"].append({
                "type": "cell",
                "lat": c.get("lat"),
                "lon": c.get("lon"),
                "label": f"Cell Tower: {c.get('mcc')}"
            })
    except: pass

    return results

# --- CATCH-ALL SPA ROUTER (The Fix for White Page) ---
@app.get("/{path:path}")
async def serve_ui(path: str):
    # 1. If asking for a physical file (vite.svg, etc.), serve it
    physical_file = os.path.join("/Users/michaelraftery/daproyect/gridland3/frontend/dist", path)
    if os.path.isfile(physical_file):
        return FileResponse(physical_file)
    
    # 2. Otherwise, serve index.html and inject ALL keys into the window object
    index_path = os.path.join("/Users/michaelraftery/daproyect/gridland3/frontend/dist", "index.html")
    with open(index_path, "r") as f:
        html = f.read()

    # Injection: Forces Mapbox to work and System.css to style the UI
    m_token = os.getenv("MAPBOX_ACCESS_TOKEN")
    injection = f'''
    <link rel="stylesheet" href="https://unpkg.com/@sakun/system.css" />
    <script>
        window.MAPBOX_ACCESS_TOKEN = "{m_token}";
        window.mapboxgl = window.mapboxgl || {{}};
        window.mapboxgl.accessToken = "{m_token}";
        console.log("Aegis: Mapbox Token Injected.");
    </script>
    '''
    return HTMLResponse(content=html.replace("</head>", f"{{injection}}</head>"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
