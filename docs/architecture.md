# Architecture

M-PHISH X is a modular monolith for the first cloud-portable release. The MV3 service worker performs navigation filtering, local caching, and the URL quick check. Suspicious or uncertain navigations call the FastAPI investigation API. The backend keeps analysis, evidence, context, risk, AI fallback, and persistence behind module interfaces.

SQLite is the default local store. `DATABASE_URL` is reserved for the PostgreSQL adapter used by a deployment migration. A future worker can extract Playwright and AI work without changing the extension contract.

## Request path

`navigation -> local cache -> quick-check -> deep investigation -> evidence -> risk -> explanation -> notification/report`
