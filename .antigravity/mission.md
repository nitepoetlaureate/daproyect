# Current Mission: Phase 3 - Tactical HTMX Dashboard
**Primary Goal:** Design and build the real-time scanning dashboard.

**Constraints (NON-NEGOTIABLE):**
- NO React. NO npm. NO build steps.
- Pure Jinja2 + HTMX + SSE + CSS Grid.
- All assets air-gapped into `gridland3/static/`.
- PicoCSS (classless) for semantic reset; custom `aegis.css` for grid + tactical styling.

**Phase 3 Execution Steps:**
1. **Air-Gap Assets:** Download `htmx.min.js`, HTMX SSE extension (`sse.js`), and `pico.classless.min.css` into `gridland3/static/`.
2. **Build the SSE Pipeline:** Implement `GET /api/stream/{job_id}` in `server.py` using `EventSourceResponse` to yield Jinja2 HTML fragments from Celery's Redis state.
3. **Construct the Grid:** Build `templates/index.html` as the Aegis Grid shell (3-row × 2-column). Build Jinja2 partials for targets, intel, logs, and header.
4. **Wire HTMX:** Connect `hx-ext="sse"` + `sse-connect` to inject live scan data into grid panels. Enforce 50-line FIFO via MutationObserver.
