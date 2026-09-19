# API

The stable API namespace is `/api/v1`. Responses from new endpoints use `{success, data, request_id}`. The unversioned `/api` routes remain local compatibility routes for the current dashboard and extension.

- `GET /api/v1/health`
- `POST /api/v1/quick-check`
- `POST /api/v1/investigations`
- `GET /api/v1/investigations/{id}`
- `GET /api/v1/investigations`
- `GET /api/v1/investigations/{id}/evidence`
- `GET /api/v1/investigations/{id}/timeline`
- `GET /api/v1/investigations/{id}/graph`
- `GET /api/v1/investigations/{id}/report`

The quick check is URL-only and returns a tier plus `deep_required`. Deep investigations return evidence, risk, context graph, timeline events, and fallback guidance.

If `M_PHISH_API_KEY` is configured, versioned routes require the `X-API-Key` header. Leave it empty for local development only.

`POST /api/v1/investigations` is asynchronous and returns a short-lived job record with `status: QUEUED`. Poll the investigation endpoint until it returns `ANALYZING`, `COMPLETED`, or `FAILED`; completed reports are then available from the evidence, timeline, graph, and report endpoints.
