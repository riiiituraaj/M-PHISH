# Verification evidence

Run `python scripts/verify.py` from a Python 3.12 environment. It installs pinned Python and npm lockfiles, checks Python lint/format, runs backend tests, tests/typechecks/builds the dashboard, and tests/typechecks/builds/packages the extension. Use `--skip-install` only when reporting verification of an existing environment. Per-command logs and JUnit results are written under `artifacts/verification/`.

Backend tests use migrated temporary SQLite databases and controlled collection/provider responses. They cover auth, ownership, pairing, origin rejection, expiry, redaction, quotas, lifecycle leases, duplicate/cancelled jobs, retention, exports, unavailable evidence, contextual regressions, ML shortcut/gate logic and collector timeout behavior. They do not establish PostgreSQL/Redis/Linux isolation behavior.

`python web/tests/browser_smoke.py` runs nine real Chromium journeys with a labelled controlled API: sign-in, queued completion, null/UNKNOWN, JSON export, persistent settings, research unavailable, demo labelling, mobile layout, permissions and outage presentation. Start the production dashboard first and set `WEB_TEST_URL` if different from localhost:3000. Results/screenshots: `web/artifacts/browser/`. Browser driver failure with system Edge was resolved by using installed Chromium; failed runs are not counted as passing.

`python extension/tests/browser.py` loads the actual MV3 extension and runs eight checks, including native form/download pause, trusted one-shot override, rejection of page-script overrides, pairing, origin-only observations and complete off-switch traffic suppression. API responses come from a harmless loopback fixture, not the production backend. Results: `extension/test-results/`.

The PDF export was rendered and visually inspected under `output/pdf/`. Mobile report screenshots were visually inspected. These are scoped checks, not comprehensive accessibility certification. Remaining gates: real queue/database integration, adversarial Linux network egress, worker termination/restart, backup restore, sustained load, independently labelled detection, optional Linux visual/OCR and remote deployment smoke tests.
