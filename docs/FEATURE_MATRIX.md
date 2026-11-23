# M-PHISH acceptance matrix

Updated 2026-11-03. This is a development release candidate, **not completed GA**.
`Partial` means implemented behavior has a material scope or verification gap.
Unit tests use deterministic inputs and SQLite; they are not detection benchmarks.

| Feature | Implementation / dependency | Acceptance criterion | Evidence and current status |
|---|---|---|---|
| Quick URL checks | `analysis.py`, `/api[/v1]/quick-check`, bundled PSL | Bounded check, no network/training, explicit origin-only coverage, escalate sensitive observations | `test_api.py`, benchmark script; partial, full paths deliberately omitted for privacy |
| Deep investigations | `api.py`, `jobs.py`, SQLAlchemy, RQ/Redis | Persist before acknowledgement; status, cancel/retry, crash recovery and private results | SQLite lifecycle tests pass; real Redis/PostgreSQL and process-kill recovery require staging |
| Domain analysis | `collector.py`, pinned DNS/TLS sockets | Actual observations with unavailable registration fields; block non-public destinations | Mocked network tests; remote integration and registration source unavailable |
| Webpage/behavior | `collector.py`, `webpage/analyzer.py`, extension | Passive bounded HTML and consented field/destination categories; no field values | Parser/client regression tests; partial: no server JS behavior, frame and dynamic coverage limited |
| Identity/impersonation | `identity/analyzer.py`, `observations.py` | Tutorial mentions do not imply impersonation; exact catalog and SSO context | Regression tests; partial: catalog coverage and independent false-positive evaluation limited |
| Privacy assessment | `privacy/analyzer.py`, strict Pydantic payloads | Field categories only, contextual destinations, sensitive values excluded | Regression tests; collection burden is not a misuse probability |
| Synthetic/templated content | `synthetic/analyzer.py` | Weak language indicators, no AI-authorship verdict, no automatic maliciousness weight | Implemented; independent indicator evaluation unavailable |
| Deceptive claims | `claims/analyzer.py` | Report observed pressure patterns without fact-checking claims | Implemented; context accuracy not independently validated |
| Download assessment | `download/analyzer.py`, extension | Warn on observed executable types, pause supported actions, no malware-clean verdict | Analyzer coverage; MIME/redirect reputation and actual browser intervention validation tracked in extension report |
| Campaign relationships | `campaign/analyzer.py`, owner-scoped prior reports | Specific endpoint hashes, same owner only, no attacker attribution | Regression tests; generic forms cannot link campaigns; real campaign evaluation unavailable |
| Context graph/timeline | `context/engine.py`, `analysis.py` | Bounded observed nodes/destinations, source/time metadata | Implemented; no fabricated event history; graph browser journey pending |
| ML/evidence fusion | `ml/model.py`, `ml/offline.py`, risk/trust engines | Offline training only; checksum-pinned JSON artifact, missingness, calibration, valid attribution | Pipeline and unit checks; **blocked on licensed real labelled observations and independent gates** |
| Research dashboard | `ml/experiments.py`, `/research` | Stored runs only, honest unavailable state, no fixed winner | Stored-read contract tested; no real benchmark results bundled |
| AI explanation | `ai/grounded.py`, optional Groq | Provider cannot change claims/scores/actions; strict evidence IDs; deterministic fallback | Injection fallback test; optional evidence selection implemented; free wording intentionally remains bounded to deterministic templates |
| Browser extension | `extension/src`, Manifest V3 | Off switch everywhere, consent, pairing, expiry, pause/override, unavailable state | See `EXTENSION_WORK.md` and `EXTENSION_RELEASE.md`; not store submitted |
| Web dashboard | `web/app`, `web/lib/api.ts` | Account, private history/settings/report/export, accessible responsive states | See `WEB_WORK.md`; browser and build evidence tracked separately |
| Demonstrations | `/api/v1/demo/scenarios/{id}`, `data/samples` | Explicit fixture execution, excluded from history/metrics; no hostname network bypass | Regression tests; authenticated and labelled synthetic |
| Operations | Alembic, Compose, firewall, CI, manage CLI | Private store/queue, quotas, retention, backup/restore, rollout/rollback and monitoring | Local migrations/retention tests; **production topology and restore rehearsal not verified** |
| Visual inspection | `visual.py`, optional Linux Playwright/Tesseract | Explicit consent, no sensitive forms, bounded offline rendering, image/text discarded | Disabled/consent/limited states tested; Linux renderer/OCR availability and reference-set evaluation unverified |

## Historical defect disposition

1. Original 19-test baseline could not run before edits: pytest missing; dependency setup needed sandbox escalation. Do not cite historical results as this checkout's baseline.
2. Extension independent-module check reproduced two context-type errors (agent baseline).
3–4. Synthetic shortcut audit, offline-only training, stored research and removal of fixed superiority claims replace misleading evaluation behavior.
5. Missing DOM/DNS/TLS now returns UNKNOWN with null authenticity/model outputs.
6. Every legacy/versioned investigation route shares session and ownership checks.
7. Tutorial brand mention regression passes.
8. Isolated passive collector supplies bounded HTML to downstream analyzers.
9–10. No invented domain age; identity context supplied; raw/calibrated outputs and log-odds attribution separated.
11–13. Extension defects and browser evidence are recorded in its work log; no assurance from backend failure is intended.

## Remaining GA gates

No licensed real dataset/model artifact, authorized deployment destination, Docker runtime, configured visual/OCR/reference dataset, operational restore rehearsal or store account is established. Full runtime isolation, real queue integration, detection operating-point validation, and store publication cannot be inferred from builds/unit tests. Missing capabilities above remain partial rather than silently dropped from the requested scope.
