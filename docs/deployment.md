# Deployment

Local development uses the included FastAPI, Next.js, and SQLite setup. Run the backend and dashboard as separate processes or use Docker Compose. Production should place a TLS-terminating load balancer in front of API instances, use PostgreSQL, and run browser analysis in restricted workers. No Kubernetes or broker is required for the first release.

## Deep crawler

The bounded Playwright analyzer is opt-in with `ENABLE_PLAYWRIGHT=true`:

```powershell
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.venv\Scripts\python.exe -m playwright install chromium
```

The backend image installs Chromium and runs as UID 10001 without host mounts. For public production traffic, move this analyzer into a separate worker with an explicit network policy before enabling it. It rejects non-public targets, does not submit forms, disables downloads, caps redirects and requests, and returns unavailable metadata when it cannot run.
