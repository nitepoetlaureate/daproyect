#!/usr/bin/env python3
"""
FastAPI server launcher for Gridland.

All scan work is dispatched to Celery workers via Redis.
Job state is queried directly from Redis via AsyncResult — there is
no shared in-memory state between this process and the workers.
"""
import logging
import os
from datetime import datetime

from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from dotenv import load_dotenv
from celery.result import AsyncResult

from celery_app import celery_app
from lib.tasks import celery_run_scan, celery_run_discover

import secrets
from itsdangerous import URLSafeSerializer

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

SECRET_KEY = os.environ.get('SECRET_KEY')
if SECRET_KEY is None:
    raise ValueError("SECRET_KEY environment variable is mandatory")


# ── CSRF + Security Headers Middleware ───────────────────────────────
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
                if secrets.compare_digest(submitted_token, csrf_cookie):
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


# ── Request Models ───────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str

class JobRequest(BaseModel):
    target: str


# ── Scan / Discover Endpoints ────────────────────────────────────────
@app.post('/scan', status_code=status.HTTP_202_ACCEPTED)
async def scan_endpoint(req: ScanRequest, request: Request):
    if not req.target:
        return JSONResponse(status_code=400, content={"error": "Target is required"})
    try:
        result = celery_run_scan.delay(req.target, True, 100)
        return {"status": "accepted", "job_id": result.id, "target": req.target, "action": "scan"}
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


@app.post('/discover', status_code=status.HTTP_202_ACCEPTED)
async def discover_endpoint(req: ScanRequest, request: Request):
    if not req.target:
        return JSONResponse(status_code=400, content={"error": "Target is required"})
    try:
        result = celery_run_discover.delay(req.target, 100)
        return {"status": "accepted", "job_id": result.id, "target": req.target, "action": "discover"}
    except Exception:
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ── Jinja2 Templates ────────────────────────────────────────────────
templates = (
    Jinja2Templates(directory="templates") if os.path.exists("templates")
    else Jinja2Templates(directory="gridland3/templates") if os.path.exists("gridland3/templates")
    else None
)


# ── Web Logging ──────────────────────────────────────────────────────
def setup_web_logging() -> logging.Logger:
    """Setup detailed logging for web interface operations"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"gridland_web_server_{timestamp}.log"

    if not os.path.exists('logs'):
        os.makedirs('logs')

    log_path = os.path.join('logs', log_filename)

    logger = logging.getLogger('gridland_web')
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    logger.info("=== GRIDLAND WEB SERVER SESSION STARTED ===")
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Log file: {log_path}")
    logger.info("=" * 50)

    return logger


web_logger = setup_web_logging()


# ── HTML Index ───────────────────────────────────────────────────────
@app.get('/', response_class=HTMLResponse)
async def index(request: Request):
    """Serves the main HTML page."""
    web_logger.info("Serving main HTML page")
    client_host = request.client.host if request.client else "unknown"
    web_logger.debug(f"Request from {client_host}")
    if templates:
        token = request.state.csrf_token
        return templates.TemplateResponse(request, "index.html", {"csrf_token": token})
    else:
        return HTMLResponse(content="<h1>Gridland</h1><p>index.html not found</p>")


# ── Job Submission (dispatches to Celery) ────────────────────────────
@app.post('/api/jobs', status_code=status.HTTP_202_ACCEPTED)
async def submit_job(job_req: JobRequest, request: Request):
    """
    Submits a new scan job.
    Expects a JSON payload with a 'target' key.
    Returns 202 Accepted with the Celery task ID immediately.
    """
    client_host = request.client.host if request.client else "unknown"
    web_logger.info(f"Job submission request from {client_host}")

    if not job_req.target:
        web_logger.warning("Job submission failed - missing target")
        return JSONResponse(status_code=400, content={"error": "Target is required"})

    web_logger.info(f"Dispatching scan to Celery for target: {job_req.target}")

    try:
        result = celery_run_scan.delay(job_req.target, True, 100)
        web_logger.info(f"Task {result.id} dispatched successfully")
        return {"job_id": result.id}

    except Exception as e:
        web_logger.error(f"Job submission failed: {str(e)}")
        web_logger.debug("Job submission exception details", exc_info=True)
        return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ── Job Status (queries Redis via AsyncResult) ───────────────────────
@app.get('/api/jobs/{job_id}')
async def get_job_status(job_id: str, request: Request):
    """
    Retrieves the status, logs, and results for a given job.
    All state is read from Redis via Celery's AsyncResult — zero in-memory lookups.
    """
    client_host = request.client.host if request.client else "unknown"
    web_logger.debug(f"Job status request for {job_id} from {client_host}")

    result = AsyncResult(job_id, app=celery_app)

    if result.state == 'PENDING':
        # PENDING can mean "unknown task" or "not yet started"
        return {"id": job_id, "status": "pending", "logs": [], "results": []}

    elif result.state == 'STARTED':
        return {"id": job_id, "status": "running", "logs": [], "results": []}

    elif result.state == 'PROGRESS':
        meta = result.info or {}
        return {
            "id": job_id,
            "status": "running",
            "logs": meta.get("logs", []),
            "results": [],
        }

    elif result.state == 'SUCCESS':
        data = result.result or {}
        return {
            "id": job_id,
            "status": "completed",
            "logs": data.get("logs", []),
            "results": data.get("results", []),
        }

    elif result.state in ('FAILURE', 'REVOKED'):
        web_logger.error(f"Job {job_id} failed: {result.info}")
        return JSONResponse(
            status_code=500,
            content={"id": job_id, "status": "failed", "error": str(result.info)},
        )

    else:
        # Catch-all for custom states
        return {"id": job_id, "status": result.state.lower(), "logs": [], "results": []}


if __name__ == '__main__':
    import uvicorn
    web_logger.info("Starting FastAPI development server on port 5001")
    web_logger.warning("This is a development server - not for production use")
    uvicorn.run(app, host="127.0.0.1", port=5001)
