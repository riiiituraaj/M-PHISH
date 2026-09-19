# M-PHISH X

M-PHISH X is a contextual digital threat-intelligence prototype for helping people make safer decisions before trusting a website or digital interaction. It combines URL signals, optional page observations, behavioral evidence, and contextual relationships into a transparent risk assessment with human-readable guidance.

The project contains:

- A FastAPI backend for quick checks, investigations, evidence, reports, and risk scoring.
- A Next.js dashboard for reviewing investigations and report details.
- A Chromium Manifest V3 extension for lightweight, top-level navigation checks.
- A SQLite-backed persistence layer with Alembic migrations for deployment workflows.

This is a prototype, not a malware scanner or a guarantee that a website is safe.

## How It Works

The extension uses a two-stage flow:

1. A fast URL-only check runs for each eligible top-level HTTP(S) navigation.
2. Low-risk pages remain quiet. Medium, high, or uncertain results trigger a deeper investigation.

Deep investigations combine deterministic URL and page evidence with the risk engine, context engine, and optional AI-generated wording. The score, classification, and evidence remain deterministic. Groq is used only to phrase supplied evidence and falls back automatically when unavailable.

Results are cached locally by the extension for five minutes per URL.

## Repository Layout

```text
backend/
	app/
		main.py                 FastAPI application and API contracts
		core/                   Configuration and logging
		services/
			webpage/              Page analysis and crawler boundary
			domain/               Domain-level signals
			risk/                 Deterministic scoring and classification
			context/              Evidence relationships and context graph
			ai/                   Optional provider integration
			ml/                   ML extension point
	alembic/                  Database migration environment and revisions
	tests/                    API and security tests
data/samples/               Safe local HTML fixtures
docs/                       API, architecture, deployment, privacy, and security notes
extension/                  Built Chromium extension and TypeScript sources
web/                        Next.js dashboard
docker-compose.yml          Local backend and dashboard containers
```

## Requirements

- Python 3.11 or newer
- Node.js 20 or newer and npm
- Chrome or another Chromium browser for extension testing
- Docker Desktop, only if using the Compose workflow

## Local Development

### Backend

From the repository root:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r backend\requirements.txt
uvicorn app.main:app --app-dir backend --reload --port 8000
```

On macOS or Linux, use `python3 -m venv .venv`, `source .venv/bin/activate`, and `python -m pip` with the equivalent commands.

The API is available at `http://localhost:8000`. FastAPI’s interactive documentation is available at `/docs`.

### Dashboard

In a second terminal:

```powershell
cd web
npm install
npm run dev
```

Open `http://localhost:3000`. Set `NEXT_PUBLIC_API_URL` when the API is not running at the default local address. If the API is unavailable, the dashboard retains a safe demo report for product walkthroughs.

### Browser Extension

In a third terminal:

```powershell
cd extension
npm install
npm run build
```

Then open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the `extension` directory. Start the backend before investigating a tab.

The extension popup can enable **Protection ON**. Its Options page controls automatic notifications, low-risk badges, and explanation level. After changing TypeScript source, run the build again and click **Reload** for the extension in Chrome.

For a predictable local smoke test, use `https://login-verify.example.com/account`; it contains URL signals that should cause a deeper check. The safe local fixtures can also be addressed through the `m-phish.local` sample path used by the analyzer.

## Configuration

Create a local `.env` file at the repository root when overrides are needed. Never commit secrets.

```env
APP_ENV=development
LOG_LEVEL=INFO
DATABASE_URL=sqlite:///m_phish.db
SQLITE_DB_PATH=backend/m_phish.db
M_PHISH_API_KEY=
INVESTIGATION_RATE_LIMIT=30
RATE_WINDOW_SECONDS=60
ENABLE_PLAYWRIGHT=false
CRAWLER_TIMEOUT_SECONDS=15
MAX_REDIRECTS=5
MAX_CRAWLER_REQUESTS=100
AI_PROVIDER=fallback
GROQ_API_KEY=
AI_MODEL=openai/gpt-oss-20b
```

Groq is optional. To enable explanations, set `AI_PROVIDER=groq`, provide `GROQ_API_KEY`, and choose an available `AI_MODEL`. Restart the backend after changing environment variables. The API key is sent only to the configured Groq endpoint; it must not be placed in frontend or extension code.

If `M_PHISH_API_KEY` is non-empty, versioned API routes require an `X-API-Key` header. Leave it empty for local development only.

## API Overview

The stable API namespace is `/api/v1`. Successful versioned responses use the `{success, data, request_id}` shape.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Service health check |
| `POST` | `/api/v1/quick-check` | Fast URL-only assessment |
| `POST` | `/api/v1/investigations` | Queue a deep investigation |
| `GET` | `/api/v1/investigations` | List stored investigations |
| `GET` | `/api/v1/investigations/{id}` | Read investigation status/report |
| `GET` | `/api/v1/investigations/{id}/evidence` | Read evidence items |
| `GET` | `/api/v1/investigations/{id}/timeline` | Read investigation events |
| `GET` | `/api/v1/investigations/{id}/graph` | Read contextual relationships |
| `GET` | `/api/v1/investigations/{id}/report` | Read the report payload |

Example quick check:

```bash
curl -X POST http://localhost:8000/api/v1/quick-check \
	-H "Content-Type: application/json" \
	-d '{"url":"https://login-verify.example.com/account"}'
```

`POST /api/v1/investigations` returns an investigation ID with `QUEUED` status. Poll the investigation endpoint until it reaches `ANALYZING`, `COMPLETED`, or `FAILED`; then read the evidence, timeline, graph, and report endpoints. The unversioned `/api` routes remain for local dashboard and extension compatibility.

More detail is in [docs/api.md](docs/api.md).

## Security and Privacy Boundaries

- Only `http` and `https` targets are accepted.
- Localhost, `.local`, loopback, private, link-local, reserved, and targets resolving to private addresses are rejected.
- The system does not submit credentials or automatically interact with authentication systems.
- Rate limiting applies to investigation and quick-check creation endpoints.
- Request IDs are returned for tracing API requests.
- Playwright crawling is disabled by default and should run in a disposable, restricted worker before production use.
- The extension observes top-level navigation and does not need access to credentials.
- Treat reports as advisory evidence, not proof of malicious intent or safety.

See [docs/security.md](docs/security.md), [docs/privacy.md](docs/privacy.md), and [docs/threat-model.md](docs/threat-model.md) for the detailed boundaries.

## Database Migrations

The application can initialize its local SQLite tables directly. For a migration-backed deployment, run:

```powershell
cd backend
..\.venv\Scripts\python.exe -m alembic upgrade head
```

The migration configuration and revisions live in `backend/alembic/`.

## Verification

Run the focused checks from the repository root:

```powershell
py -m pip install pytest
py -m pytest backend/tests
py -m py_compile backend/app/main.py backend/tests/test_api.py backend/tests/test_security.py
cd web
npm run build
cd ..\extension
npm run build
```

The test suite covers API behavior and security boundaries. The dashboard and extension builds provide TypeScript and production-compilation checks.

## Docker Compose

To run the backend and dashboard together:

```powershell
docker compose up --build
```

The backend is exposed on port `8000` and the dashboard on port `3000`. Compose disables Playwright by default and sets a bounded crawler timeout and redirect limit. Stop the services with `docker compose down`.

## Current Scope and Next Steps

The current crawler stage is deliberately bounded and deterministic. Remote Playwright crawling, screenshots, DNS enrichment, ML inference, and richer LLM workflows are extension points rather than prerequisites for the core result. Any future remote crawler should be isolated from the API process with strict network, resource, and target controls.

Useful project references:

- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)
- [Testing](docs/testing.md)
- [API reference](docs/api.md)

## License

No license has been declared in this repository yet. Treat the project as all-rights-reserved unless the repository owner adds explicit licensing terms.
