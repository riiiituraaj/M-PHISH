# M-PHISH 

**Contextual phishing evidence, private investigations, and browser interaction review.**

M-PHISH X helps users examine a website and the sensitive actions it requests. It combines URL checks, bounded page observations, destination and identity context, deterministic rules, and optional model outputs into reports that explain what was observed and what remains unknown.

The project includes a FastAPI backend, a Next.js dashboard, a Chromium Manifest V3 extension, a durable investigation queue, an isolated passive collector, and offline model-evaluation tools.

**Version:** application/extension `0.2.0` · report contract `2.0` · policy `evidence-policy-v2`.

**Current status:** local checks passed for the documented scope. Full-feature general availability is blocked by outstanding detection and operational validation. No remote deployment or extension-store submission has been performed. See [release readiness](docs/RELEASE_READINESS.md) for the evidence and exact prerequisites.

## Contents

- [Purpose and scope](#purpose-and-scope)
- [Features and implementation status](#features-and-implementation-status)
- [Architecture and investigation flow](#architecture-and-investigation-flow)
- [Technology and requirements](#technology-and-requirements)
- [Repository structure](#repository-structure)
- [Local installation](#local-installation)
- [Running the application](#running-the-application)
- [Configuration](#configuration)
- [Using the dashboard](#using-the-dashboard)
- [Installing and pairing the extension](#installing-and-pairing-the-extension)
- [Understanding reports](#understanding-reports)
- [API reference](#api-reference)
- [Storage and job lifecycle](#storage-and-job-lifecycle)
- [Security and privacy](#security-and-privacy)
- [Machine learning and research](#machine-learning-and-research)
- [Optional AI and visual analysis](#optional-ai-and-visual-analysis)
- [Testing and verification](#testing-and-verification)
- [Builds and release artifacts](#builds-and-release-artifacts)
- [Production deployment and operations](#production-deployment-and-operations)
- [Troubleshooting](#troubleshooting)
- [Known limitations and remaining gates](#known-limitations-and-remaining-gates)
- [Development guidelines](#development-guidelines)
- [Documentation index](#documentation-index)
- [Licensing and support](#licensing-and-support)

## Purpose and scope

The application is designed to answer practical questions: What evidence is available about this destination? What information does this page request? Does the observed form destination fit the apparent context? Which checks could not run? What should the user review before proceeding?

Reports separate operational status, evidence coverage, rule-based severity and model probability. A completed investigation can still have insufficient evidence. Missing DNS, page, identity or model observations must not become a reassuring verdict.

The product is advisory. It does not certify a business, verify every textual claim, prove attacker identity, scan downloaded binaries for malware, or universally prevent data exfiltration. Submitted target URLs are reduced to their origin, which protects sensitive paths and query parameters but also limits detection coverage.

## Features and implementation status

| Feature family | Implemented behavior | Important boundary |
| --- | --- | --- |
| Accounts and access | Password login, opaque sessions, owner-scoped history, settings and deletion | Production account creation is closed by default |
| Quick URL checks | Local origin/hostname signals and explicit partial coverage | No complete-page safety verdict; URL paths are omitted |
| Deep investigation | Persisted jobs, separate execution, status, retry and cancellation | Requires dispatcher, Redis and a worker |
| Domain and transport | Collector-supplied DNS/TLS observations | Registration/age information is unavailable without a real source |
| Webpage analysis | Bounded passive HTML parsing and structural observations | Server collection does not execute target JavaScript |
| Identity context | Brand/destination relationships, tutorial and SSO context | Limited catalog; brand mention alone is not impersonation |
| Requested information | Password, email, OTP, card, phone, address and banking categories | Entered values are not collected; category presence is not misuse probability |
| Synthetic-language indicators | Weak templated-language observations | No AI-authorship verdict or independent maliciousness claim |
| Claim patterns | Observed pressure or suspicious phrasing | Does not fact-check whether a claim is true |
| Download assessment | Executable-type observations and supported browser pauses | No binary execution, antivirus scan or malware-clean result |
| Campaign similarity | Specific endpoint hashes compared with the same owner's reports | Similarity does not identify an attacker; no cross-account linkage |
| Context and timeline | Returned entities, relationships and recorded events | No fabricated browsing history or unsupported edges |
| ML inference | Checksum-pinned JSON artifacts, calibration and abstention | No independently validated model is bundled |
| Research | Read-only stored evaluation results and comparisons | No online training or invented benchmark winner |
| Explanations | Deterministic guidance; optional constrained evidence selection | Provider cannot change scores, policy or actions |
| Visual/OCR | Consent gate and optional offline Linux renderer | Runtime/reference validation remains outstanding; disabled by default |
| Dashboard | Investigations, reports, exports, research, demos, settings and admin view | Some journeys use controlled API substitutes in browser tests |
| Browser extension | Local/cloud settings, pairing, observations and limited action intervention | Top-frame native actions only; other data channels can bypass coverage |
| Operations | Migrations, quotas, retention, deployment configuration and runbooks | Real infrastructure, recovery and capacity gates remain open |

The [feature acceptance matrix](docs/FEATURE_MATRIX.md) maps these families to implementation files, criteria and validation gaps.

## Architecture and investigation flow

```text
Dashboard / Chromium extension
            |
            | authenticated requests
            v
       FastAPI API ---------> PostgreSQL (SQLite for local development)
            |                   accounts, sessions, settings, owned jobs/reports
            | committed job
            v
     Outbox dispatcher -----> Redis / RQ -----> Investigation worker
                                                     |
                                                     | private collection RPC
                                                     v
                                              Isolated collector
                                                     |
                                                     | restricted public HTTP(S)
                                                     v
                                              Target origin

Collected observations -> analyzers -> evidence/risk/context -> owned report
```

1. The user signs in or pairs an authorized extension. Requests pass authentication, origin, schema, quota and ownership checks.
2. An investigation request is committed to the database before the API acknowledges its job ID.
3. The dispatcher finds queued or recoverable work and submits it to Redis/RQ.
4. A worker claims a database lease and requests collection from the private collector when configured.
5. The collector validates DNS answers, destination addresses, redirects and connected peers, then fetches bounded passive HTML under a hard process deadline.
6. Analyzers produce evidence with provenance and availability. Client observations remain separate from server observations.
7. Rules and optional validated model outputs contribute to the assessment. Optional AI can select existing evidence to emphasize; it cannot invent policy decisions.
8. The report is published only if the job is still owned by the current lease and has not been cancelled or deleted.
9. The dashboard polls active jobs and renders available evidence. Exports repeat authorization checks.

The API does not run a target crawler inside an in-process background task. The collector should have no database, Redis, account or provider credentials. See [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).

## Technology and requirements

| Layer | Technology |
| --- | --- |
| Backend | Python 3.12, FastAPI, Pydantic |
| Persistence | SQLAlchemy, Alembic, PostgreSQL; SQLite for development/tests |
| Jobs | Redis and RQ, with database-backed outbox and leases |
| Authentication | Argon2 password hashing and hashed opaque sessions |
| Dashboard | Next.js 15.5.28, React 18.3.1, TypeScript |
| Extension | Chromium Manifest V3, TypeScript, esbuild |
| PDF export | ReportLab |
| Offline evaluation | scikit-learn, XGBoost and separate evaluation lockfile |
| Browser testing | Playwright and installed Chromium |
| Optional visual processing | Linux sandboxed Chromium, Pillow/pytesseract/Tesseract prerequisites |
| Deployment configuration | Linux Docker/Compose, separate collector network and host firewall |

Use **Python 3.12** and **Node.js 22** for the documented development/CI target. The recorded local Node checks ran on Node 26; the Linux/Node 22 CI job has not been observed running in this workspace. Native Windows supports API/dashboard development and the recorded browser tests. Use Linux or Linux containers for the RQ worker deployment and optional visual stack.

Runtime dependencies are pinned in `backend/requirements.lock`; development dependencies are in `backend/requirements-dev.lock`; offline evaluation dependencies are in `backend/requirements-evaluation.lock`. Both Node projects have `package-lock.json` files. Use locked installations instead of replacing the pins with arbitrary latest versions.

## Repository structure

```text
backend/
  app/
    main.py                 FastAPI entry point and production startup checks
    api.py                  Authentication, investigations and business routes
    contracts.py            Bounded request schemas and contract versions
    analysis.py             Evidence assembly and assessment orchestration
    collector.py            Isolated passive collection service
    jobs.py                 Durable job execution and outbox dispatch
    worker.py               RQ worker using configured Redis connection
    visual.py               Optional offline visual/OCR path
    exports.py              Report export generation
    manage.py               Administrator bootstrap and retention commands
    core/                   Storage, security, networking and process boundaries
    services/               Analyzer families, ML and explanation providers
  alembic/                  Versioned database migrations
  tests/                    API, analyzer, lifecycle and security regressions
  requirements*.lock        Dependency pins by execution scope
  Dockerfile                Backend production image definition
web/
  app/                      Dashboard routes
  components/               Shared session, navigation and report UI
  lib/                      Typed API access and helpers
  tests/                    API-client and browser tests
extension/
  src/                      TypeScript source of truth
  manifest.json             MV3 permissions and runtime configuration
  tests/                    Policy/broker and loaded-browser tests
  scripts/                  Deterministic packaging
  release/                  Generated extension ZIP and checksum
data/samples/               Harmless labelled demo fixtures
deploy/                    Production Compose and collector firewall rules
scripts/                   Verification, dependency locks, benchmark and release tools
docs/                      Architecture, privacy, research and operational evidence
artifacts/                 Generated verification and source-release files
docker-compose.yml         Local multi-service configuration
.env.example               Configuration reference without real secrets
```

## Local installation

Run all commands from the repository root unless a different directory is explicitly shown. Commands below assume this project is already present on your machine; no repository URL or remote ownership is assumed.

### 1. Create a Python environment

Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS shell:

```sh
python3.12 -m venv .venv
source .venv/bin/activate
```

If PowerShell policy prevents activation, call `.\.venv\Scripts\python.exe` directly in place of `python`. Activation is a convenience; it is not necessary to weaken system execution policy.

### 2. Set development configuration

The examples use local SQLite and no remote collector. Set environment variables in every process that needs them. Copying `.env.example` alone does not load it into all Python/Node entry points.

PowerShell:

```powershell
$env:APP_ENV = 'development'
$env:DATABASE_URL = 'sqlite:///backend/m_phish.db'
$env:REDIS_URL = 'redis://127.0.0.1:6379/0'
$env:WEB_ORIGINS = 'http://localhost:3000,http://127.0.0.1:3000'
$env:ALLOW_REGISTRATION = 'true'
```

Linux/macOS:

```sh
export APP_ENV=development
export DATABASE_URL=sqlite:///backend/m_phish.db
export REDIS_URL=redis://127.0.0.1:6379/0
export WEB_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
export ALLOW_REGISTRATION=true
```

Leave `CRAWLER_URL`, model artifact paths and provider credentials unset for an initial local setup. Collection/model unavailability will be reported explicitly.

### 3. Install dependencies and migrate

```sh
python -m pip install -r backend/requirements-dev.lock
python -m alembic -c backend/alembic.ini upgrade head
npm --prefix web ci
npm --prefix extension ci
```

Migrations must use the same `DATABASE_URL` as the API and workers. Schema creation is migration-driven; starting the API does not replace this step. Existing anonymous legacy data is not automatically assigned to a new account.

## Running the application

### API and dashboard

In an activated Python terminal:

```sh
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
npm --prefix web run dev
```

Open [http://localhost:3000](http://localhost:3000). Health is available at [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health). Health reports process/service availability; it does not prove that the queue, collector or model is working.

Local registration is enabled by default. Passwords must contain 12–128 characters. Production registration defaults to closed. There is no shipped administrator password. Bootstrap an administrator in an authorized operator terminal:

```sh
python -m backend.app.manage create-admin --email YOUR_EMAIL
```

The command prompts for a password without echoing it. Use an actual email value rather than the placeholder.

### Dispatcher and worker

Investigations remain queued without execution services. With Redis available and the same database/Redis environment configured, start these in separate Linux process terminals:

```sh
python -m backend.app.jobs
```

```sh
python -m backend.app.worker
```

The worker uses the `investigations` queue. Native Windows worker operation is not the supported production path. Collection also requires `CRAWLER_URL` pointing to an isolated collector; a worker without it can return a report with collection unavailable.

### Local containers

```sh
docker compose up --build
```

The local definition includes PostgreSQL, Redis, a migration service, API, dispatcher, worker and dashboard. It binds the API/dashboard to loopback and uses named persistence volumes. Its database password is explicitly for local development. Stop the services with `docker compose down`; do not add `--volumes` unless you intend to delete persisted local data.

**Validation status:** Docker is not installed on the development host used for the recorded checks, so this topology has not been runtime verified. The local Compose file intentionally does not expose an unrestricted collector. Production uses the separate [deployment configuration](deploy/compose.production.yml).

## Configuration

The table describes the active paths in this release. Older settings declarations are not evidence that a knob controls the current collector, quotas or authentication. In particular, `M_PHISH_API_KEY` is not a replacement for session authentication, and `ENABLE_PLAYWRIGHT` is not the active visual-consent switch.

| Variable | Default or example | Meaning |
| --- | --- | --- |
| `APP_ENV` | `development` | `production` enables startup requirements and Secure cookies |
| `DATABASE_URL` | `sqlite:///backend/m_phish.db` in active storage | Shared database DSN; private PostgreSQL required in production |
| `REDIS_URL` | Local template: `redis://127.0.0.1:6379/0` | Required environment for dispatcher/worker; use protected Redis in production |
| `WEB_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Comma-separated exact allowed dashboard origins |
| `ALLOW_REGISTRATION` | `true` in development; `false` in production | Public registration switch; explicit value uses lowercase `true` |
| `EXTENSION_IDS` | Empty | Comma-separated allowed Chromium extension IDs |
| `CRAWLER_URL` | Unset | Private isolated collector service address |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Browser API origin; supplied at dashboard production build time |
| `LOG_LEVEL` | `INFO` | Application log level |
| `ML_ARTIFACT_PATH` | Unset | Local pure-JSON inference artifact |
| `ML_ARTIFACT_SHA256` | Unset | Required integrity pin for the model artifact |
| `ML_RESEARCH_RESULTS` | Unset | Stored `evaluation-v2` results file for research views |
| `AI_PROVIDER` | `fallback` | Set `groq` only when enabling the optional provider |
| `GROQ_API_KEY` | Unset | Server-only optional provider credential |
| `AI_MODEL` | `openai/gpt-oss-20b` | Configured provider model identifier; provider availability must be verified separately |
| `ENABLE_VISUAL` | Disabled unless exactly `true` | Optional Linux renderer; per-scan consent is still required |
| `WEB_TEST_URL` | `http://localhost:3000` | Dashboard target for browser tests |

Production Compose additionally requires `BACKEND_IMAGE`, `WEB_IMAGE` and `PRIVATE_NETWORK`. Use immutable image digests and an existing private network. See [.env.example](.env.example) and [deployment instructions](docs/deployment.md).

Secrets belong in operator-managed runtime configuration, never source files, images, logs or browser bundles. Every `NEXT_PUBLIC_*` value is public. Use exact origins without paths; check that production cookie site topology is compatible with SameSite=Strict.

## Using the dashboard

| Page | Purpose |
| --- | --- |
| `/` | Overview and investigation entry |
| `/signin` | Account sign-in and permitted registration |
| `/investigations` | Private history with pagination/search/filter/sort |
| `/investigations/{id}` | Job progress, report, cancellation/retry/delete and exports |
| `/settings` | Explanation detail, history, retention, notifications, AI consent, pairing and account deletion |
| `/research` | Stored evaluation availability and comparisons |
| `/demo` | Explicitly labelled isolated fixture runs |
| `/admin` | Administrator-only operational status and retention action |
| `/privacy` | Collection and product limitations |

Typical workflow:

1. Sign in and enter a public HTTP(S) website URL. Paths, fragments and query parameters are removed before submission.
2. Select visual consent only if you want the optional visual path to be considered.
3. Start the investigation and wait for the worker status to change.
4. Read coverage and limitations before interpreting risk or model output.
5. Review evidence, destinations, module availability, context relationships and recorded events.
6. Export JSON/PDF if needed, or delete the owned result. Exported files are private copies outside server retention control.

Account preferences default to standard explanation detail, history enabled, notifications enabled, AI disabled and seven-day retention. Retention can be set to 1–30 days. Turning history off applies to new jobs, which expire after one hour and are omitted from saved history; delete old reports separately if required.

Demo fixtures are excluded from ordinary investigation history and detection metrics. A demo is not evidence that a live website was collected or classified correctly.

## Installing and pairing the extension

### Build and load

```sh
npm --prefix extension ci
npm --prefix extension run package
```

1. Open `chrome://extensions` in Chromium/Chrome or the equivalent extension page in a compatible browser.
2. Enable developer mode and choose **Load unpacked**.
3. Select this repository's `extension/` directory after building.
4. Copy the actual extension ID shown by the browser. The manifest declares a minimum Chromium version of 120; this is not a claim of testing every later browser release.

### Pair with the service

1. Add that ID to the backend `EXTENSION_IDS` allowlist and restart the backend process with the updated environment.
2. Sign in to the dashboard and request a pairing code in Settings for the same ID.
3. Open extension settings and configure the backend's exact origin. Production requires HTTPS; HTTP localhost/127.0.0.1 is allowed for development.
4. Grant the explicitly requested backend host permission and exchange the code within five minutes.
5. Enable cloud consent and choose a cloud mode when remote checks are wanted.

Pairing codes are single-use. Extension bearer sessions last thirty minutes and are bound to the approved extension origin. Tokens are kept in browser session storage, not synchronized storage. An expired or revoked session requires pairing again.

### Behavior and permissions

Protection starts enabled in **local mode**, with **cloud consent off**. Local observations do not call the backend. The off switch aborts pending requests, clears current warnings/assessments and stops extension navigation/interaction traffic. Exclusions match exact origins and expire.

The manifest requests `activeTab`, `tabs`, `storage`, `webNavigation` and `notifications`, plus optional backend host permissions. Tabs/navigation information binds results to the actual top-frame document and prevents stale results being reused on another page. HTTP(S) content scripts inspect structural field categories; they do not read entered values, cookies, clipboard data or keystrokes.

Supported native sensitive form submissions and direct executable links can be paused before their native action. **Continue once** requires a trusted user click; programmatic clicks cannot authorize it. If checking fails, the UI presents unavailable/review behavior rather than a safety claim. Other scripts, frames and data channels can bypass this limited intervention, and hostile pages can remove or imitate injected notices.

The generated ZIP is [extension/release/m-phish-0.2.0.zip](extension/release/m-phish-0.2.0.zip). Its status is **packaged**, not submitted, approved or public. See [extension release instructions](docs/EXTENSION_RELEASE.md).

## Understanding reports

| Report concept | Interpretation |
| --- | --- |
| Job status | Whether execution is queued, analyzing, completed, failed or cancelled |
| Module availability | Whether a particular observation could be obtained |
| Evidence coverage | How much of the intended observation scope was available |
| Rule risk score | A deterministic policy indicator; not an estimated probability |
| Raw model probability | Uncalibrated output from a valid configured model, otherwise null/unavailable |
| Calibrated probability | Separately calibrated output under that model's evaluation assumptions |
| Trust/authenticity | A bounded assessment that can remain UNKNOWN; not a safety guarantee |
| Attribution | Per-feature contributions to raw model log-odds; not causality |
| Provenance | Source and timing of the specific evidence used |
| Expiry | Freshness of the assessment, separate from how long history is retained |

For example, an investigation can be `COMPLETED` with only URL observations, no DOM evidence and no model. The correct interpretation is limited coverage with unknown authenticity—not a clean site. Null values must remain unavailable rather than displaying as 0% or 100%.

Observed server facts and untrusted client-supplied categories are separate. Reports do not store raw fetched HTML, entered credentials or screenshots. A hash-based endpoint relationship is evidence of technical similarity, not proof of common ownership or attacker identity.

## API reference

The current application disables the public OpenAPI/Swagger/ReDoc endpoints. Use [backend/app/api.py](backend/app/api.py) for route behavior and [backend/app/contracts.py](backend/app/contracts.py) for exact request schemas. Do not rely on `/docs` or `/openapi.json` being available.

### Authentication and response format

Business routes require a session. Web clients use the HttpOnly `m_phish_session` cookie and send credentials with requests. Mutations require an exact approved `Origin`. Extension bearer requests also require the bound approved `chrome-extension://...` origin. Health, login, permitted registration and pairing-code exchange are the limited public exceptions.

Versioned JSON responses use this general shape:

```json
{
  "success": true,
  "data": {},
  "request_id": "request-correlation-id"
}
```

Failures have `success: false`, an `error` object and a correlation ID. Validation errors do not echo submitted values. Protected responses use no-store behavior. Unknown input fields are rejected. The legacy quick-check/investigation aliases share security and ownership checks, but their response wrapping can differ; new clients should use `/api/v1`.

### Routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/v1/health` | Service identity/version and process health |
| POST | `/api/v1/auth/register` | Create an account when registration is allowed |
| POST | `/api/v1/auth/login` | Issue a web session |
| GET | `/api/v1/auth/session` | Read signed-in identity |
| POST | `/api/v1/auth/logout` | Revoke the current session |
| DELETE | `/api/v1/auth/account` | Delete the current account and owned data |
| POST | `/api/v1/auth/pair` | Create an allowlisted extension pairing code |
| POST | `/api/v1/auth/pair/exchange` | Consume a valid code for an extension bearer session |
| GET / PATCH | `/api/v1/settings` | Read/update account preferences |
| POST | `/api/v1/quick-check` | Perform bounded origin-only URL checks |
| POST | `/api/v1/investigations` | Create a durable job |
| GET | `/api/v1/investigations` | List owned saved history |
| GET / DELETE | `/api/v1/investigations/{id}` | Read status/report or delete an owned job |
| POST | `/api/v1/investigations/{id}/cancel` | Cancel eligible work |
| POST | `/api/v1/investigations/{id}/retry` | Retry eligible work under lifecycle limits |
| GET | `/api/v1/investigations/{id}/report` | Read the completed report section |
| GET | `/api/v1/investigations/{id}/evidence` | Read evidence |
| GET | `/api/v1/investigations/{id}/timeline` | Read recorded events |
| GET | `/api/v1/investigations/{id}/graph` | Read context relationships |
| GET | `/api/v1/investigations/{id}/export?format=json` | Export JSON; use `format=pdf` for PDF |
| POST | `/api/v1/dynamic-trust/evaluate` | Evaluate bounded interaction observations |
| GET | `/api/v1/research/experiments` | Read stored evaluations; rerun/training is forbidden |
| GET | `/api/v1/demo/scenarios` | List available demo fixtures |
| POST | `/api/v1/demo/scenarios/{scenario}` | Run an explicitly selected isolated fixture |
| GET | `/api/v1/admin/status` | Administrator-only counts/configuration status |
| POST | `/api/v1/admin/retention` | Administrator-only retention cleanup |

History supports `limit` (1–100, default 25), `offset` (0–10000), `q`, `classification` and `sort` (`newest` or `oldest`). Filtering is applied before pagination.

### Example investigation body

```json
{
  "url": "https://example.com/",
  "context": {
    "visual_consent": false
  }
}
```

Send this through an authenticated client with the correct origin. Optional consented observations contain allowed categories, origin-only form destinations, bounded counts and top-frame coverage. They must never contain actual passwords, OTPs, card data or arbitrary page content. Supported interaction actions include sensitive-field focus, form submission and download attempt; see the strict contracts for the exact allowlist.

### Limits

| Control | Current value |
| --- | --- |
| Request body | 32 KiB |
| Authenticated requests | 120 per user per minute |
| Login/register/exchange | 10 per client IP per minute |
| POST/export quota | 30 per user/client per minute |
| Active jobs | 3 per user; aggregate admission target 200 |
| Web session | 8 hours |
| Extension session | 30 minutes |
| Pairing code | 5 minutes, single-use |
| Retained history | 1–30 days, default 7 |
| No-history job | 1 hour |

These are implementation limits, not capacity guarantees. Cross-owner aggregate job admission has a known race and still needs production concurrency validation. Configure trusted proxy handling correctly before relying on client-IP quotas behind a reverse proxy.

## Storage and job lifecycle

The migrated schema separates account users, hashed sessions, pairing records, owned jobs, owned reports and quota buckets. Queries for user results include the owner ID. The legacy anonymous tables remain quarantined; there is no safe automatic ownership inference.

Job flow is normally `QUEUED -> ANALYZING -> COMPLETED`. Recoverable failures can return to `QUEUED`, bounded attempts end in `FAILED`, and eligible work can be `CANCELLED`. Workers use a 40-second database lease, a 30-second RQ timeout and at most three execution attempts. The dispatcher polls approximately every two seconds. Lease/attempt checks prevent duplicate or cancelled work from publishing a later result.

Redis delivers work; the database stores the durable job state. Losing queue state should be recoverable through dispatch, but real Redis/PostgreSQL recovery remains an unverified deployment gate. SQLite lifecycle tests are not proof of production locking behavior.

Apply migrations before starting upgraded services:

```sh
python -m alembic -c backend/alembic.ini upgrade head
```

Run retention using the management command and schedule it at least daily in the deployed environment:

```sh
python -m backend.app.manage retention
```

It removes expired jobs and associated data, sessions, pairing codes and quota records. Backup copies and previously downloaded exports require their own retention policy. Account deletion removes owned active data and sessions but cannot delete an exported file on another machine.

## Security and privacy

### Account and API boundaries

- Passwords use Argon2; opaque session secrets are hashed before storage.
- Web cookies are HttpOnly and SameSite=Strict, with Secure enabled in production.
- Origin checks, strict schemas, quotas and owner-scoped queries apply to protected paths, including legacy aliases and exports.
- Pairing is short-lived, single-use and bound to an explicitly allowlisted extension ID.
- Logs and validation responses avoid target bodies and submitted secret values.
- Report exports render escaped evidence; they do not render arbitrary target HTML or fetch remote resources.

### Collection boundary

The collector rejects unsupported schemes, embedded credentials, invalid/non-public targets and mixed public/private DNS answers. Each redirect is revalidated. Connections use an approved numeric peer while preserving TLS hostname verification. Requests are passive GETs without browser cookies or target JavaScript execution.

Collection is bounded by a 1 MiB body limit, five redirects, restricted response handling and a 24-second killable subprocess deadline. DNS stalls and slow reads cannot rely solely on a socket timeout. The caller also has its own timeout, so some checks may become unavailable before the collector's outer deadline.

Production must enforce network egress independently using the isolated collector network and reviewed host rules. See [collector firewall](deploy/collector-firewall.sh). The presence of a firewall script is not evidence that a deployed host has enforced it.

### Data minimization

Full URL paths, queries and fragments are omitted from service targets. The extension inspects structural attributes and categories rather than entered values. Its short-lived local tab cache currently uses the exact tab URL to reject stale results; those URLs are not sent as full paths to the service. Cached assessments expire after sixty seconds.

Optional AI receives generated evidence identifiers/categories/titles/severity, not raw URLs or page text. Optional screenshots and raw OCR text are discarded. Reports retain only limited derived observations. The product adds no advertising or analytics telemetry.

See [privacy](docs/privacy.md), [security operations](docs/security.md) and [threat model](docs/threat-model.md) for residual risks and operator obligations.

## Machine learning and research

**No validated production model or independently measured detection accuracy is bundled.** Runtime inference remains unavailable unless an operator supplies a compatible artifact, matching SHA256 and passing release-gate metadata.

The `observations-v2` feature schema contains 31 URL/domain/page/behavior/context features plus missingness indicators. Unknown domain age remains unknown; it is not replaced with an invented age. Runtime input preprocessing is origin-only and supplied training data must use the same coverage assumptions. Unsupported missingness or values outside training ranges can cause abstention.

The deployment format is pure JSON containing logistic-regression coefficients and held-out sigmoid calibration. Raw probability, calibrated probability, intercept and raw-log-odds contributions are separate. Random forest and XGBoost are offline comparison baselines, not implicitly active runtime ensembles. No pickle/joblib upload endpoint exists.

### Offline evaluation workflow

1. Establish the right to use a real labelled dataset. Absence from a phishing feed is not a benign label.
2. Prepare UTF-8 JSONL observations with `target_url`, binary `label`, ISO `observed_at`, `url_features`, `domain_analysis`, `page_analysis`, `context` and optional `campaign_id`.
3. Supply a provenance manifest with `dataset_version`, `source`, `license`, `usage_permission`, `collected_at`, `label_methodology`, file `sha256` and `kind`. Eligible real data uses `real_labelled`.
4. Install the separate evaluation dependencies and run the offline command:

```sh
python -m pip install -r backend/requirements-evaluation.lock
python -m backend.app.services.ml.offline --dataset /path/to/observations.jsonl --manifest /path/to/provenance.json --output /path/to/new-run --seed 42
```

Use real local paths and a new output directory. Keep private data outside source control. Expected outputs include `release_targets.json`, `splits.json`, `model.json`, `results.json` and checksums.

Domain/campaign group splits separate training, calibration, validation and final test data. Exact duplicates are removed; ablations reuse the same splits. Thresholds are selected from validation, not final-test outcomes. The predefined gates use 95% interval bounds for at least 95% precision, at least 90% recall and at most 1% legitimate false-positive rate. Small samples cannot silently satisfy the gates through point estimates alone.

Reports include supports, confusion matrices, PR/ROC-AUC, Brier score, reliability bins, Wilson intervals, error IDs and artifact metadata. Synthetic fixtures cannot justify production detection claims. Temporal holdout, near-template review, subgroup evaluation, end-to-end warning-policy performance and independent replication remain required work.

Set `ML_RESEARCH_RESULTS` to reviewed stored results for the research dashboard. API requests never train or rerun experiments. See the [model card](docs/ML_MODEL_CARD.md) and [dataset guide](docs/DATASETS.md).

## Optional AI and visual analysis

### Grounded explanation provider

The deterministic explanation works without an external provider. Optional Groq use requires all of: account AI consent, `AI_PROVIDER=groq`, a server `GROQ_API_KEY`, and available evidence.

The provider can select at most three existing evidence IDs from a bounded supplied set. Returned identifiers are validated. It cannot introduce unsupported prose claims, alter scores, select an intervention policy or change the recommended action. The request has a four-second timeout; repeated failures open a short circuit breaker and return deterministic fallback behavior.

### Visual/OCR path

Visual processing requires per-investigation consent, `ENABLE_VISUAL=true`, a supported POSIX runtime and separately provisioned sandboxed browser/OCR prerequisites. Sensitive forms are rejected. The renderer uses supplied HTML with JavaScript and network requests disabled; remote images/styles are unavailable. The result is not a faithful live-page screenshot or validated visual phishing detector.

Rendering is subprocess-bounded. Screenshot size is capped, and pixels/raw OCR text are discarded after deriving limited metadata and matched brand terms. Brand terms do not establish identity. Production images do not currently include the optional visual stack, and successful Linux rendering/OCR/reference evaluation has not been verified. Do not disable the browser sandbox to force deployment success.

## Testing and verification

### Main verification entry point

```sh
python scripts/verify.py
```

This installs the development lockfile, runs `npm ci` for both Node projects, checks Python lint/format, runs backend tests, runs dashboard API tests/typechecks/build, and typechecks/tests/builds/packages the extension. It stops on a failing command and records logs and results under `artifacts/verification/`.

If dependencies are already installed and that narrower scope is intentional:

```sh
python scripts/verify.py --skip-install
```

### Browser tests

```sh
python -m playwright install chromium
```

For dashboard tests, start a production dashboard in another terminal:

```sh
npm --prefix web run build
npm --prefix web run start
```

Then run:

```sh
python web/tests/browser_smoke.py
python extension/tests/browser.py
```

Set `WEB_TEST_URL` if the dashboard is not at `http://localhost:3000`. The dashboard runner uses intercepted, explicitly controlled API responses. The extension runner loads the actual MV3 build against a harmless local fixture server. They do not prove production backend/queue connectivity.

### Recorded local results — November 4, 2026

| Check | Recorded outcome | Scope |
| --- | --- | --- |
| Backend tests | 44 passed | Temporary migrated SQLite and controlled external responses |
| Dashboard API-client tests | 6 passed | Credentials, errors, null values and payload behavior |
| Extension policy/broker tests | 13 passed | Message validation, consent, redaction and unavailable states |
| Dashboard browser journeys | 9 passed | Real Chromium with controlled API; desktop and 390px mobile |
| Loaded-extension checks | 8 passed | Actual extension, harmless local API/fixture |
| Python lint/format and TypeScript | Passed | Checked source scope in verification script |
| Dashboard production build | Passed | Local build, not a deployed environment |
| Extension package | Passed | Deterministic runtime ZIP |
| Dependency audits | No known advisories reported after updates | Python recorded scan and registry-backed Node audits |

Python's pinned packages were installed into the existing virtual environment; a second clean Python environment has not been verified. `npm ci` refreshed both Node installations. One backend test-client deprecation warning was recorded. A system Edge driver shutdown failure was resolved by using installed Chromium. Neither failed runs nor unavailable infrastructure are counted as passing evidence.

The limited secret-pattern scan checks the release allowlist for selected private-key/AWS/GitHub/Groq formats. It is not a comprehensive entropy or secret audit. Dependency audits cover known advisories, not all vulnerabilities.

A local benchmark (`python scripts/benchmark.py`) recorded 1,000 sequential in-process quick checks: median approximately 27.0 ms and p95 42.7 ms on the recorded Windows host. It excludes HTTP, authentication, queue, collection and model work and is not production throughput or latency evidence.

Evidence lives in `artifacts/verification/`, `web/artifacts/browser/`, `extension/test-results/` and the linked [testing guide](docs/testing.md). CI is defined in [.github/workflows/ci.yml](.github/workflows/ci.yml); its remote execution has not been verified here.

## Builds and release artifacts

Dashboard production build and local production server:

```sh
npm --prefix web run build
npm --prefix web run start
```

Extension build and validated package:

```sh
npm --prefix extension run package
```

Source package and limited secret scan:

```sh
python scripts/release.py
```

| Artifact | Location |
| --- | --- |
| Extension runtime ZIP | `extension/release/m-phish-0.2.0.zip` |
| Extension checksum | `extension/release/SHA256SUMS` |
| Source ZIP | `artifacts/release/m-phish-source-0.2.0.zip` |
| Source checksum | `artifacts/release/SHA256SUMS` |
| Per-file source inventory | `artifacts/release/source-inventory.json` |
| Limited secret scan | `artifacts/release/secret-scan.json` |
| Aggregate verification | `artifacts/verification/results.json` and command logs |

The packagers use explicit inclusion rules and fixed ZIP timestamps. Source edits require regenerating the source package to include them. The extension package excludes development dependencies and test profiles. Packaged, submitted, approved and public are separate release states.

## Production deployment and operations

The prepared path is **Linux Docker with private PostgreSQL and Redis**, a separately isolated collector, and HTTPS ingress. It is a prepared configuration, not a tested remote deployment.

Before deployment:

1. Establish an authorized hosting destination, registry, domain, private services, scoped credentials, backups and monitoring.
2. Build the backend from the repository root and the dashboard from `web/`. Supply the public API origin at dashboard build time; retain immutable image digests.
3. Review and apply collector network restrictions on the Docker host. Test forbidden addresses, metadata endpoints, redirects, mixed DNS and IPv6 boundaries from the actual collector environment.
4. Configure production environment values, exact HTTPS origins, extension IDs and a private network. Keep registration closed.
5. Run migrations before API/worker startup. Use non-root images, resource limits, restricted ingress, narrowly trusted proxies and secret injection.
6. Verify real sign-in, two-account isolation, a harmless investigation, cancellation, queue restart, exports, provider failures and actual extension pairing.
7. Rehearse backup restore and rollback, measure capacity and prove operational alerts before approving launch.

The orchestrator definition is [deploy/compose.production.yml](deploy/compose.production.yml). Follow [deployment](docs/deployment.md) and [operations](docs/OPERATIONS.md) for exact ordering and remaining configuration.

Monitor API errors/latency, queue depth and oldest-job age, worker heartbeats, retries/timeouts, database connections/disk, Redis persistence/memory, collector rejections and optional provider fallback. Hosted metrics export/alert routing is not yet integrated. Start with bounded capacity and measure before adding workers; no uptime, RPO, RTO or minimum launch throughput has been established.

For rollback, retain prior image digests, schema revision, configuration, extension artifact and a verified backup. Do not blindly downgrade a live schema. Restore into a replacement private staging database first, invalidate restored sessions and verify ownership/lifecycle behavior before switching traffic.

## Troubleshooting

| Symptom | Likely cause and next step |
| --- | --- |
| PowerShell refuses virtual-environment activation | Use `.\.venv\Scripts\python.exe` directly; do not change machine policy just to run the project |
| Database table missing | Run Alembic against the same `DATABASE_URL` and working directory as the service |
| Dashboard cannot reach the API | Check port 8000, browser API origin, exact `WEB_ORIGINS`, and whether the dashboard needs rebuilding after a public environment change |
| Sign-in appears to work but later requests fail | Check cookie credentials, origin/site consistency and production HTTPS/SameSite requirements |
| `401` | Session is absent, expired or revoked; sign in or pair again |
| `403` | Check exact Origin, role, registration setting or extension allowlist; do not broaden CORS to bypass it |
| `404` for a report | ID may be unknown, expired, deleted or belong to another account |
| `409` when reading a report section/export | The job has not produced a report yet |
| `422` | Request violates strict schemas, URL policy or field bounds |
| `429` | Request quota or active-job capacity exceeded; wait and inspect queue pressure |
| Investigation stays `QUEUED` | Check dispatcher, worker, Redis connectivity and shared database configuration |
| Investigation completes with `UNKNOWN` | Review module availability; a missing collector/model is an expected explicit limitation |
| Collector refuses a URL | Check public HTTP(S) destination policy, ports, DNS answers and redirects; never disable private-address protections to make a target pass |
| Pairing fails | Confirm actual ID, backend allowlist, exact extension origin, host permission and unused code age under five minutes |
| Extension sends no cloud requests | Local mode/cloud consent/off switch/exclusion/session expiry may explain it; check settings before assuming a network defect |
| Native form is paused | Review the notice and use a deliberate one-shot override only when intended; page scripts cannot click the override for you |
| Research is unavailable | Configure a valid stored evaluation file; the endpoint does not train a replacement |
| Model probabilities are unavailable | Check artifact schema, release gate, checksum, coverage and input range; no bundled model exists |
| Visual/OCR is unavailable | Check per-scan consent, sensitive-form rejection, ENABLE_VISUAL, POSIX runtime and separately provisioned sandbox/OCR dependencies |
| `/docs` or `/openapi.json` returns 404 | Those endpoints are disabled in the current entry point; use source contracts |
| Browser runner cannot launch | Install Chromium with Playwright and allow required local subprocess/temp-directory operations in your execution environment |
| Port 3000 or 8000 is occupied | Identify the existing process; reuse the intended server or configure a consistent alternate port/origin |

## Known limitations and remaining gates

- No licensed real labelled dataset, independent operating-point evaluation or validated model artifact has been supplied.
- Origin-only processing loses path-specific evidence, and passive collection misses JavaScript-generated behavior.
- The identity catalog, campaign indicators, text patterns and warning policy need independent false-positive and subgroup evaluation.
- Browser intervention covers limited native top-frame actions; it cannot universally block script-driven data transfer or make page-injected UI trusted.
- Linux collector firewall enforcement, PostgreSQL concurrency, Redis process-crash recovery, backup restore and sustained load have not been exercised here.
- The optional Linux visual/OCR stack and reference set are not provisioned or validated.
- Current global queue admission has a cross-owner concurrency race; infrastructure limits and a reviewed fix/validation are required before relying on it as a strict global cap.
- Hosted monitoring, operator contacts, legal terms, authorized deployment destination and publisher account are not established.
- No deployed revision, store submission, store approval or public service has been verified.

Full-feature GA requires closing the relevant gates in [RELEASE_READINESS.md](docs/RELEASE_READINESS.md). Successful local builds and controlled fixtures do not complete them, and the requested full release has not silently been reclassified as a finished beta.

## Development guidelines

Use TypeScript sources in `extension/src/` as the extension source of truth; rebuild generated scripts after edits. Keep request schemas strict and maintain owner/origin checks on every new business route. Preserve unknown/unavailable semantics across backend, dashboard and extension.

Add behavior-focused tests for security, lifecycle or analyzer changes. Avoid real credentials or uncontrolled malicious targets in fixtures. Keep datasets, customer reports, local databases, environment secrets and browser profiles out of source control and release packages.

Regenerate lockfiles intentionally and review dependency changes. Run the verification entry point before packaging. Model experiments belong in explicit offline workflows, not API startup, scans, research GETs or ordinary builds. Update the feature matrix and release evidence whenever capability or validation scope changes.

No repository remote, contribution policy or external issue tracker ownership is assumed by this README. Coordinate publication through the actual project owner.

## Documentation index

| Document | Coverage |
| --- | --- |
| [Feature matrix](docs/FEATURE_MATRIX.md) | Feature-to-source mapping and acceptance gaps |
| [Architecture](docs/architecture.md) | Service boundaries and evidence flow |
| [API notes](docs/api.md) | Route overview; source remains authoritative |
| [Privacy](docs/privacy.md) | Collection, retention and product disclosures |
| [Threat model](docs/threat-model.md) | Trust boundaries, controls and residual risks |
| [Security operations](docs/security.md) | Operational controls and audit interpretation |
| [Testing](docs/testing.md) | Test scope and evidence locations |
| [Model card](docs/ML_MODEL_CARD.md) | Feature schema, calibration, gates and limitations |
| [Dataset guide](docs/DATASETS.md) | Provenance and offline evaluation inputs |
| [Dashboard work log](docs/WEB_WORK.md) | Dashboard implementation and verification |
| [Extension work log](docs/EXTENSION_WORK.md) | Extension implementation and regression evidence |
| [Extension release](docs/EXTENSION_RELEASE.md) | Pairing, permissions and store prerequisites |
| [Deployment](docs/deployment.md) | Prepared Linux deployment path and staging gates |
| [Operations](docs/OPERATIONS.md) | Retention, monitoring, backup/restore and rollback |
| [Release readiness](docs/RELEASE_READINESS.md) | Separate build, functional, detection and deployment statuses |
| [0.2.0 changelog](CHANGELOG_v0.2.0.md) | Upgrade summary |

## Licensing and support

No top-level license file was present when this README was prepared. Do not assume the project is MIT-licensed or otherwise freely redistributable; the owner must establish project licensing before distribution. Dependencies and any future datasets retain their own license and usage terms.

No verified public support address, security-reporting contact, publisher identity or legal approval is supplied. Configure real operator-owned contacts and disclosures before public launch. For local troubleshooting, retain sanitized request IDs and test evidence without sharing credentials, private targets or report payloads.
