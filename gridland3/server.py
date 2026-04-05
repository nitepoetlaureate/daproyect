#!/usr/bin/env python3
"""
FastAPI server launcher for Gridland
"""
import logging
import os
from datetime import datetime
import concurrent.futures
from fastapi import FastAPI, BackgroundTasks, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from dotenv import load_dotenv
from lib.jobs import create_job, get_job
from lib.orchestrator import run_scan

# Load environment variables from .env file
load_dotenv()

app = FastAPI()
executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)

import secrets

SECRET_KEY = os.environ.get('SECRET_KEY', 'default-insecure-key-for-dev')

from itsdangerous import URLSafeSerializer

# The app has SECRET_KEY defined above
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    serializer = URLSafeSerializer(SECRET_KEY)

    # Get CSRF token from cookie or generate a new one
    csrf_cookie = request.cookies.get("csrf_token")
    if not csrf_cookie:
        raw_token = secrets.token_urlsafe(32)
        signed_token = serializer.dumps(raw_token)
        request.state.csrf_token = signed_token
        csrf_cookie_to_set = signed_token
    else:
        request.state.csrf_token = csrf_cookie
        csrf_cookie_to_set = None

    # Validate CSRF for mutable methods
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        submitted_token = request.headers.get("X-CSRFToken")
        if not submitted_token:
            try:
                form = await request.form()
                submitted_token = form.get("csrf_token")
            except Exception:
                pass

        # Validate that we can unsign it and it matches the cookie
        is_valid = False
        if submitted_token and csrf_cookie:
            try:
                # the submitted token is the signed one, compare with cookie
                if secrets.compare_digest(submitted_token, csrf_cookie):
                    # also verify it can be loaded
                    serializer.loads(submitted_token)
                    is_valid = True
            except Exception:
                pass

        if not is_valid:
            return JSONResponse(status_code=403, content={"error": "CSRF token missing or invalid"})

    response = await call_next(request)

    if csrf_cookie_to_set:
        response.set_cookie("csrf_token", csrf_cookie_to_set, httponly=True, samesite="lax", secure=False)

    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: http:"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

class ScanRequest(BaseModel):
    target: str

@app.post('/scan', status_code=status.HTTP_202_ACCEPTED)
async def scan_endpoint(req: ScanRequest, background_tasks: BackgroundTasks, request: Request):
    target = req.target
    if not target:
        return JSONResponse(status_code=400, content={"error": "Target is required"})
    try:
        job = create_job(target)
        executor.submit(run_scan, job.id, target, True, 100)
        return {"status": "accepted", "job_id": job.id, "target": target, "action": "scan"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

@app.post('/discover', status_code=status.HTTP_202_ACCEPTED)
async def discover_endpoint(req: ScanRequest, background_tasks: BackgroundTasks, request: Request):
    target = req.target
    if not target:
        return JSONResponse(status_code=400, content={"error": "Target is required"})
    try:
        job = create_job(target)
        executor.submit(run_scan, job.id, target, False, 100) # Discover is non-aggressive perhaps
        return {"status": "accepted", "job_id": job.id, "target": target, "action": "discover"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


# Jinja2 templates (assuming templates directory exists at 'gridland3/templates')
# Note: Jinja2Templates requires jinja2 package. If not installed, it might need to be.
# Using a simpler fallback or standard HTML response if templating is just static.
# Flask's `render_template` used `templates` folder by default.
templates = Jinja2Templates(directory="templates") if os.path.exists("templates") else Jinja2Templates(directory="gridland3/templates") if os.path.exists("gridland3/templates") else None


# Configure web interface logging
def setup_web_logging() -> logging.Logger:
    """Setup detailed logging for web interface operations"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"gridland_web_server_{timestamp}.log"
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    log_path = os.path.join('logs', log_filename)
    
    # Configure logger
    logger = logging.getLogger('gridland_web')
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler for detailed logs
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler for Flask output -> FastAPI output
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Detailed formatter for file
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # Simple formatter for console
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    logger.info(f"=== GRIDLAND WEB SERVER SESSION STARTED ===")
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Log file: {log_path}")
    logger.info(f"=" * 50)
    
    return logger

# Initialize web logger
web_logger = setup_web_logging()

class JobRequest(BaseModel):
    target: str

@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main HTML page."""
    web_logger.info("Serving main HTML page")
    client_host = request.client.host if request.client else "unknown"
    web_logger.debug(f"Request from {client_host}")
    if templates:
        token = request.state.csrf_token
        return templates.TemplateResponse("index.html", {"request": request, "csrf_token": token})
    else:
        # Fallback if templates directory doesn't exist during fast iteration
        return HTMLResponse(content="<h1>Gridland</h1><p>index.html not found</p>")

@app.post('/api/jobs', status_code=status.HTTP_202_ACCEPTED)
async def submit_job(job_req: JobRequest, background_tasks: BackgroundTasks, request: Request):
    """
    Submits a new scan job.
    Expects a JSON payload with a 'target' key.
    """
    client_host = request.client.host if request.client else "unknown"
    web_logger.info(f"Job submission request from {client_host}")
    
    web_logger.debug(f"Request data: {job_req.model_dump()}")
    
    target = job_req.target
    if not target:
        web_logger.warning("Job submission failed - missing target")
        return JSONResponse(status_code=400, content={"error": "Target is required"})

    web_logger.info(f"Creating job for target: {target}")
    
    try:
        job = create_job(target)
        web_logger.debug(f"Job created with ID: {job.id}")

        # Run the scan in a background task (FastAPI native)
        web_logger.info(f"Starting background scan task for job {job.id}")
        executor.submit(run_scan, job.id, target, True, 100) # aggressive=True, threads=100 for now
        web_logger.debug(f"Background task scheduled for job {job.id}")

        web_logger.info(f"Job {job.id} successfully submitted")
        return {"job_id": job.id}
        
    except Exception as e:
        web_logger.error(f"Job submission failed: {str(e)}")
        web_logger.debug(f"Job submission exception details", exc_info=True)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

@app.get('/api/jobs/{job_id}')
async def get_job_status(job_id: str, request: Request):
    """
    Retrieves the status, logs, and results for a given job.
    """
    client_host = request.client.host if request.client else "unknown"
    web_logger.debug(f"Job status request for {job_id} from {client_host}")
    
    try:
        job = get_job(job_id)
        if not job:
            web_logger.warning(f"Job {job_id} not found")
            return JSONResponse(status_code=404, content={"error": "Job not found"})

        web_logger.debug(f"Returning status for job {job_id}: {job.status}")
        return job.to_dict()
        
    except Exception as e:
        web_logger.error(f"Error retrieving job {job_id}: {str(e)}")
        web_logger.debug(f"Job status exception details", exc_info=True)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

if __name__ == '__main__':
    import uvicorn
    web_logger.info("Starting FastAPI development server on port 5001")
    web_logger.warning("This is a development server - not for production use")
    uvicorn.run(app, host="127.0.0.1", port=5001)
