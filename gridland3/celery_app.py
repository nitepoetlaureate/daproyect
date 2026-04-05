"""
Celery application instance for Gridland.

Redis serves as both the message broker and the result backend.
All job state (PENDING → STARTED → PROGRESS → SUCCESS/FAILURE) is stored
in Redis and queried from FastAPI via AsyncResult — zero shared memory.
"""
import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "gridland",
    broker=CELERY_BROKER_URL,
    backend=CELERY_BROKER_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,          # expose STARTED state via AsyncResult
    result_expires=3600,              # purge finished results after 1 hour
    worker_hijack_root_logger=False,  # don't clobber app-level logging
)

# Auto-discover @shared_task definitions inside lib/tasks.py
celery_app.autodiscover_tasks(["lib"])
