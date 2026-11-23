# Release readiness — 2026-11-04

Full-feature general availability is **not achieved**. The requested scope remains the target; this is not an implicit downgrade to a completed beta release.

| Gate | Evidence/status |
| --- | --- |
| Build verification | Aggregate locked-install run passed: Python lint/format, 44 backend tests, six dashboard API tests, typechecks, production web build, 13 extension tests and package. Python lock installed into the existing venv; npm ci refreshed both Node installations. A fresh Python environment and Linux/Node 22 CI execution remain unverified. See artifacts/verification/results.json. |
| Functional verification | Auth/ownership/lifecycle backend tests and nine dashboard/eight loaded-extension browser checks pass with explicitly controlled dependencies. Real PostgreSQL/Redis/collector end-to-end remains unverified. |
| Security/operations | Origin/ownership/redaction/SSRF/timeout tests pass in scope. Linux firewall, crash recovery, restore, sustained capacity and hosted monitoring are not validated. |
| Detection validation | Blocked: no licensed real labelled dataset or independent operating-point evidence. No deployable validated ML artifact bundled. |
| Visual/OCR | Consent/disabled/failure states tested. Optional Linux sandbox/runtime and reference-set evaluation are unavailable. |
| Deployment | Not deployed. No verified authorized hosting destination, Docker runtime, domain/private services or credentials established. |
| Extension distribution | ZIP packaged with checksum. Not submitted, approved or public. |

## Concrete prerequisites to finish

Provide an authorized Linux staging/deployment destination with Docker, private PostgreSQL/Redis, TLS domain/registry, backup/monitoring services and scoped secret injection. Establish actual operator support/privacy/security contacts and a publisher account if store distribution is required. Supply licensed real observations with provenance/labels/time/campaign groups for offline evaluation. Provision the optional sandboxed Linux visual/OCR stack and reference data if that feature is promised at launch.

Then execute the staging/restore/egress/queue/load gates in deployment.md and OPERATIONS.md; fix failures, evaluate detection without relaxing thresholds, deploy verified immutable images, run remote smoke tests and submit the reviewed extension package. No metric, ownership, certification, publication or uptime has been fabricated to fill these gaps.

## Local artifacts

- `docs/backend-tests.xml`, `artifacts/verification/`: backend and aggregate verification evidence.
- `web/artifacts/browser/`: nine controlled-API UI journeys and responsive screenshots.
- `extension/test-results/`: eight loaded-extension checks and screenshots.
- `extension/release/`: runtime ZIP and SHA256.
- `artifacts/release/`: source ZIP, per-file checksums and limited secret-pattern scan.
- `artifacts/verification/rule-benchmark.json`: 1,000 sequential in-process quick checks, median 27.0 ms / p95 42.7 ms on this Windows host. Excludes HTTP/auth/queue/collection/model work; not launch capacity evidence.
- `docs/dependency-audit-final.json`: Python advisory scan after upgrades; Node scan results under artifacts/verification/.
- `docs/FEATURE_MATRIX.md`, `ML_MODEL_CARD.md`, `DATASETS.md`: feature and model limitations.

Dependency scanners detect known advisories in their database/scope, not all vulnerabilities. Controlled browser responses prove UI handling, not remote-service reliability or detection accuracy. Tests using SQLite do not prove PostgreSQL race behavior.
