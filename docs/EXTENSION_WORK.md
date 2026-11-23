# Extension implementation evidence

TypeScript in `src/` is the source of truth; esbuild emits packaged scripts. Original duplicate `.bak` files were removed after the workflow became explicit. Settings, popup, service-worker broker and content observation/intervention paths share bounded origin-only contracts.

Implemented sender/frame/document validation, exact tab URL checks, generation-based invalidation, request cancellation, expiring session reports, opt-in cloud observations, session-only pairing, unavailable states and native one-shot intervention. Regression review corrected missing tabs permission, observation action limits, late responses after dismissal and untrusted override clicks.

`npm run package` passes typechecking, thirteen tests and bundling. `python extension/tests/browser.py` passes eight real-browser checks, recorded with timestamps in test-results/browser-results.json. Production service connectivity and store approval are separate outstanding gates; see EXTENSION_RELEASE.md.
