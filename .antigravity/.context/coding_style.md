# Global Coding Standards & Anti-Patterns

## Unacceptable Practices (Failure Conditions)
- **God Objects / God Files:** No file should exceed 500 lines. Break logic down into focused modules.
- **YAGNI (You Aren't Gonna Need It):** Do NOT build abstractions, interfaces, or generic base classes for features that do not exist yet. Write simple, direct code for the exact task requested.
- **Route Bloat:** Zero business logic is allowed inside API route handlers (e.g., `server.py`). Routes only handle HTTP translation; logic goes in `services/` or `lib/`.
- **Insecure Defaults:** Never use `'default-insecure-key'` fallbacks. If an environment secret is missing, the application MUST crash immediately on startup.

## Stack Requirements
- Backend: Python 3.11+, strict typing (`mypy`), asynchronous FastAPI.
- Frontend: React, JSX, functional components.
