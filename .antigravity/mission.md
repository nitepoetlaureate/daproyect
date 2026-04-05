# Current Mission: Phase 2 - Celery Integration
**Primary Goal:** Decouple the FastAPI web tier from the legacy scanning engine.

**Current State:**
FastAPI is routing traffic, but `lib.orchestrator.run_scan` is dangerously heavy. 

**Your Tasks:**
1. Scaffold a `Celery` application instance.
2. Create Celery tasks that wrap the legacy `run_scan` and `run_discover` functions.
3. Refactor `server.py` to dispatch jobs to Celery rather than the internal `ThreadPoolExecutor`.
4. Ensure the endpoints still return a `202 Accepted` with a tracking ID immediately upon dispatch.
