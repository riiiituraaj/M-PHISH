# M-PHISH X v0.2.0 — Hardening & Evidence Upgrade

## What changed

- Fixed the dashboard demo-scenario response contract.
- Fixed extension “full report” navigation so quick checks no longer route a raw URL into an investigation-ID path.
- Added configurable extension API endpoint and optional browser-client API key settings.
- Applied API-key enforcement consistently to `/api/*` when `M_PHISH_API_KEY` is configured.
- Reused the latest completed report for dynamic-trust interaction events instead of rebuilding the full investigation for every field focus.
- Added deterministic local-fixture handling so demos never depend on external DNS.
- Hardened SSRF target validation against embedded credentials, oversized URLs, multicast and unspecified IP ranges.
- Added SQLite WAL mode, foreign-key enforcement, and useful indexes.
- Prevented duplicate evidence/features/events during report replacement.
- Added an optional external CSV benchmark loader through `MPHISH_DATASET_PATH`.
- Added held-out validation metrics and model provenance to ML output.
- Replaced fake-looking group attribution with batched local probability-delta attribution.
- Reframed research UI and documentation so synthetic benchmark results are clearly identified as development evidence.
- Added ML provenance to the technical report view.
- Updated Chromium extension artifacts and added local TypeScript declarations for clean source type-checking.
- Included migration/data assets in the Docker build context and added `.dockerignore`.

## Validation

Backend test suite: **19 passed**.

Frontend production build could not be completed in the sandbox because the environment timed out while fetching npm dependencies. The extension TypeScript sources compile cleanly with the available global TypeScript compiler; bundled JS artifacts were regenerated from the updated sources.
