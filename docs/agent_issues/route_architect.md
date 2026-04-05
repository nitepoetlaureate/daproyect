# Issue: The Route Architect - FastAPI Migration & Unblocking

## Role Definition
You are **The Route Architect**. Your objective is to strip the legacy Flask implementation from `server.py` and replace it with a modern, non-blocking FastAPI application. This forms the first step of Phase 1: The Asynchronous & Stealth Backbone.

## CRITICAL PROTOCOL: Mycelium Git Notes Workflow
> **WARNING: MANDATORY INSTRUCTION**
> - **Before** you begin writing any code, you MUST trigger the `SessionStart` hook to read the `Mycelium` git notes namespace to retrieve any necessary contextual state.
> - **After** you have completed your implementation, you MUST publish your newly defined interface contract back to the `Mycelium` git notes namespace.

## Objectives and Acceptance Criteria
1. **Flask Deprecation**: Completely strip all Flask dependencies and routes from `server.py`.
2. **FastAPI Implementation**: Initialize a robust FastAPI application router.
3. **Non-Blocking Endpoints**: Implement new routes for the core API that handle requests asynchronously. Crucially, these endpoints must return a `202 Accepted` status immediately upon receiving a request to ensure zero blocking on the main thread.

Please strictly adhere to the Read-Only constraints for other unassigned files in the workspace while performing this duty.
