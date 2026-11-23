# 0.2.0 — local release candidate, not GA

- Replaced anonymous report access with authenticated, owner-scoped accounts, settings, history, exports and deletion; added origin-bound extension pairing and quotas.
- Added migrated durable jobs, outbox dispatch, leases, retries, cancellation and a separately isolated passive collector with bounded subprocess execution.
- Preserved analyzer families while separating availability, observations, rule risk and model probabilities. Unknown evidence remains UNKNOWN; optional AI cannot change policy or invent evidence.
- Replaced runtime training and synthetic success claims with offline, provenance-aware evaluation and checksum-pinned inference gates. No validated model is bundled.
- Rebuilt dashboard flows and MV3 consent/settings/message/intervention behavior; fixed script-triggered continuation and late responses after dismissal.
- Added locked builds, dependency audits, CI, source/extension packages, browser regressions and operational runbooks.

Verified locally: 44 backend tests, six dashboard API tests, 13 extension tests, nine controlled-API dashboard browser journeys and eight actual loaded-extension checks. Production topology, real model validation, optional visual/OCR, restore/load testing, deployment and store approval remain open gates. See docs/RELEASE_READINESS.md.
