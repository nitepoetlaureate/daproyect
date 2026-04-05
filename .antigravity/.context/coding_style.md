# Frontend Architecture & Aesthetic Standards (Phase 3)

## The Aesthetic Mandate (ANTI-CORPORATE)
- **No Consumer Web Bloat:** This is a tactical instrument, not a consumer SaaS product. No massive hero images, no excess padding, no rounded friendly corners. 
- **High-Density Information:** The UI must handle multiple concurrent data streams (logs, CVEs, IPs) without obfuscation. Use tight CSS Grids, monospace fonts for data, and highly considered color-coding (e.g., Neon Green for active, Red for critical vulnerabilities, muted grey for layout).
- **Focus and Hierarchy:** Nothing should dwarf or hide the active scan data. Controls should be minimal and out of the way once a scan begins.

## Technical Mandates (STRICT FAILURE CONDITIONS)
- **NO NODE.JS OR NPM:** No build steps. No React.
- **The Pipeline:** Use HTMX (`hx-ext="sse"`) and Server-Sent Events (SSE) via `sse-starlette` in FastAPI. The backend yields HTML, the frontend swaps it.
- **Air-Gapped Assets:** All CSS (PicoCSS/Tailwind) and JS (HTMX) must be downloaded and served locally from the `static/` folder. NO external CDNs.
