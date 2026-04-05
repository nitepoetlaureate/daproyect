# Task Queue Standards (Phase 2)

## Architectural Mandates
- **Task Framework:** You MUST use `Celery`. Alternative queues like ARQ or RQ are strictly forbidden due to their inability to safely sandbox thread-heavy legacy code.
- **Broker:** Use `Redis` (running locally on `redis://localhost:6379/0`).
- **Isolation:** You must utilize Celery's default prefork multiprocessing pool. Do not force Gevent or Eventlet, as the legacy `run_scan` spawns its own threads and requires hard OS process isolation.

## Code Structure
- **YAGNI:** Do not build complex class-based worker factories. Define your Celery application in a clean `worker.py` or `tasks.py` file.
- **API Integration:** Modify the existing `/scan` and `/discover` endpoints in `server.py` to use `celery_app.send_task()` instead of `executor.submit()`. 
