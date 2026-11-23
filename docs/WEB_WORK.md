# Dashboard implementation and verification log

## Verified update — 2026-11-04

Supersedes pending statuses in the initial inventory below: locked npm installation, six API-client tests, TypeScript and Next.js 15.5.28 production build passed. Nine Chromium journeys passed with a controlled API, including desktop session/queue/export/settings and mobile layout. No browser page errors were recorded. A system Edge driver shutdown failure was resolved using installed Chromium. Results/screenshots: `web/artifacts/browser/`. Origin-only normalization strips paths/query/fragment before submission. Registry-backed npm audit reported zero known advisories after dependency updates. Real service/queue and unlisted graph/pairing/cancellation journeys still require integration validation.

2026-11-03, Windows / Node v26.5.0 / npm 11.12.1.

Baseline: dependencies were absent. `npm ci --no-fund` failed with ENOTCACHED (sandbox network/cache restriction). An escalated retry waited for approval and was interrupted; baseline build was not run. Existing source inspection confirmed fixed reassuring metrics, local-only fake settings saves, default TRUSTED fallbacks, server-side report fetches unable to forward browser sessions, hardcoded remote API origin, and hardcoded research winner/improvement prose.

Implemented in `web/`: credentialed API client with bounded requests and structured errors; cookie session/sign-in/registration/sign-out; private paginated searchable history; durable queued scan navigation and polling, cancellation/retry/delete and authorized export; persisted settings/account deletion; operator-approved extension ID pairing; explicit isolated demo route; admin role view; visual consent; separate observation availability, coverage, raw/calibrated probability and risk severity; null-safe evidence, modality, graph and timeline panels; stored research comparisons with ties and unavailable metrics; privacy/limitations disclosure; mobile/reduced-motion/focus/empty/offline/expired states.

Reports display escaped text only. No arbitrary safe-route URL is rendered as a trusted navigation destination. All eight analyzer families remain visible, including unavailable capability states. Settings distinguish account preferences from extension controls. No automatic demo fallback or fabricated metrics remain.

Production Dockerfile uses npm ci/build and non-root npm start. API origin is a build argument, not a shipped service credential. Deploy API and dashboard on the same site for SameSite cookie sessions, with exact allowed browser origins.

Official dependency guidance checked: [Next.js support policy](https://nextjs.org/support-policy) marks 14 unsupported; [October 14 2026 security update](https://nextjs.org/blog/nextjs-security-update-october-14-2026) recommends patched 15.5.28 or 16.4.1. A compatible maintenance-line upgrade is intended, subject to actual registry availability and build verification. Do not claim the current lock is security-verified until installation/audit completes.

Remaining verification: dependency install, TypeScript and production build, real browser desktop/mobile auth/scan/settings/export journeys, integration contract alignment and dependency audit. Browser behavior is not verified merely by this source change. Backend operational and detection gates remain independent.

## Route acceptance inventory

| Surface | Implementation | Acceptance criterion | Verification status |
| --- | --- | --- | --- |
| Public overview / scan entry | app/page.tsx | No invented detection claims; validates target; visual consent explicit; accepted job opens status page | Source implemented; browser runner prepared |
| Account session | components/auth.tsx, app/signin/page.tsx | Cookie credentials on calls; expired session prompts sign-in; sign-out failures shown; no password persistence | Six API regression tests prepared; browser runner prepared |
| History | app/investigations/page.tsx | Owner-scoped API pagination/search/filter/sort; loading, empty and unavailable states | API boundary is server-owned; browser validation pending |
| Durable progress/report | app/investigations/[id]/page.tsx | Poll active jobs only; cancel/retry/delete; no prior-target result after navigation; expired result visibly stale | Source implemented; integration pending |
| Evidence report | components/report.tsx | Missing model probabilities remain unavailable; no inverted safety score; every analyzer family shows availability; evidence ID/source/time/rule weight | Browser null/unknown regression prepared |
| Graph/timeline | components/report.tsx | Only returned entities/events; bounded graph; keyboard-selectable provenance; no invented links | Source implemented |
| JSON/PDF export | lib/api.ts, report route | Authenticated download; server errors presented; no browser target-HTML renderer | JSON browser download test prepared; real PDF integration is backend-owned |
| Research | app/research/page.tsx | Stored metrics only; explicit criterion, ties and uncertainty; no claims when results missing | Browser unavailable-results check prepared |
| Settings | app/settings/page.tsx | Preferences persist via API; explanation detail changes default panels; notification preference controls completion notice; retention 1–30 days | Browser reload persistence check prepared |
| Pairing / deletion | app/settings/page.tsx | ID validation; one-use code visibly expires; account deletion explicit; operator approval errors shown | Source implemented; real identity integration pending |
| Demo | app/demo/page.tsx | Fixture API separate from investigation API; explicit synthetic label; no silent fallback | Browser demo-label check prepared |
| Operations | app/admin/page.tsx | Admin-only UI plus server authorization; queue/config status no health claims; explicit retention action | Ordinary-user denial check prepared |
| Disclosure | app/privacy/page.tsx | Collection, origin-only coverage, external processing, retention and legal/operator configuration limits are stated | Reviewed against current backend contracts |
| Accessibility/responsiveness | app/globals.css | Labelled inputs, keyboard focus, skip link, reduced motion, 390px no horizontal overflow | Browser desktop/mobile runner prepared |

The browser runner uses real installed Edge/Chromium and deterministic intercepted API responses. Its screenshots show actual rendered implementation with labelled fixture data; they are not live deployment evidence. Real backend sign-in, ownership, queue workers and PDF rendering must pass separate integration gates.
