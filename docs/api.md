# API contract

Run the API and inspect `/openapi.json` for exact request schemas. JSON responses carry `success`, `data` or `error`, and a request correlation ID. Unknown fields are rejected. Request bodies are bounded to 32 KiB; protected responses are not cached.

All business routes require a session. Web mutations require an exact configured Origin; extension bearer requests require the bound allowlisted extension Origin. Health, login, development registration and pairing-code exchange are the limited unauthenticated exceptions. No API key belongs in client source.

| Route under `/api/v1` | Operation |
| --- | --- |
| `/auth/register`, `/auth/login`, `/auth/logout` | POST account/session actions |
| `/auth/session` | GET signed-in identity |
| `/auth/account` | DELETE current account and owned data |
| `/auth/pair`, `/auth/pair/exchange` | POST single-use extension pairing |
| `/settings` | GET/PATCH account preferences |
| `/investigations` | POST queued job; GET owned, filtered/paginated history |
| `/investigations/{id}` | GET status/report; DELETE owned job |
| `/investigations/{id}/cancel`, `/retry` | POST bounded lifecycle action |
| `/investigations/{id}/evidence`, `/timeline`, `/graph` | GET authorized report sections |
| `/investigations/{id}/export?format=json` | GET authorized JSON or PDF export |
| `/dynamic-trust/evaluate` | POST bounded contextual observations; no training or target fetching |
| `/research/experiments` | GET stored evaluations only; force rerun forbidden |
| `/demo/scenarios` | GET fixtures; POST selected fixture route to run an isolated demo |
| `/admin/status`, `/admin/retention` | Administrator-only operations |

URLs are reduced to their origin, deliberately losing path-specific coverage. Observation fields describe categories and destinations, never credential values. Report contract 2.0 distinguishes rule risk, observation coverage, raw model probability, calibrated probability and unknown authenticity. Model and authenticity fields may be null. Consumers must preserve null rather than show 0% or 100%.
