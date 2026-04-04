#!/usr/bin/env python3
"""
Flask server launcher for Gridland
"""
from flask import Flask, render_template, request, jsonify
from flask import Flask, render_template, request, jsonify
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
import threading
import logging
import os
from datetime import datetime
from dotenv import load_dotenv
from lib.jobs import create_job, get_job
from lib.orchestrator import run_scan

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

# Enable security headers
talisman = Talisman(app)

# Enable CSRF protection
csrf = CSRFProtect(app)

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
    
    # Console handler for Flask output
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

@app.route('/')
def index():
    """Serves the main HTML page."""
    web_logger.info("Serving main HTML page")
    web_logger.debug(f"Request from {request.remote_addr}")
    return render_template('index.html')

@app.route('/api/jobs', methods=['POST'])
def submit_job():
    """
    Submits a new scan job.
    Expects a JSON payload with a 'target' key.
    """
    web_logger.info(f"Job submission request from {request.remote_addr}")
    
    data = request.get_json()
    web_logger.debug(f"Request data: {data}")
    
    if not data or 'target' not in data:
        web_logger.warning("Job submission failed - missing target")
        return jsonify({"error": "Target is required"}), 400

    target = data['target']
    web_logger.info(f"Creating job for target: {target}")
    
    try:
        job = create_job(target)
        web_logger.debug(f"Job created with ID: {job.id}")

        # Run the scan in a background thread
        web_logger.info(f"Starting background scan thread for job {job.id}")
        scan_thread = threading.Thread(
            target=run_scan,
            args=(job.id, target, True, 100)  # aggressive=True, threads=100 for now
        )
        scan_thread.start()
        web_logger.debug(f"Background thread started for job {job.id}")

        web_logger.info(f"Job {job.id} successfully submitted")
        return jsonify({"job_id": job.id}), 202
        
    except Exception as e:
        web_logger.error(f"Job submission failed: {str(e)}")
        web_logger.debug(f"Job submission exception details", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/api/jobs/<job_id>', methods=['GET'])
def get_job_status(job_id: str):
    """
    Retrieves the status, logs, and results for a given job.
    """
    web_logger.debug(f"Job status request for {job_id} from {request.remote_addr}")
    
    try:
        job = get_job(job_id)
        if not job:
            web_logger.warning(f"Job {job_id} not found")
            return jsonify({"error": "Job not found"}), 404

        web_logger.debug(f"Returning status for job {job_id}: {job.status}")
        return jsonify(job.to_dict())
        
    except Exception as e:
        web_logger.error(f"Error retrieving job {job_id}: {str(e)}")
        web_logger.debug(f"Job status exception details", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    web_logger.info("Starting Flask development server on port 5001")
    web_logger.warning("This is a development server - not for production use")
    app.run(debug=True, port=5001)