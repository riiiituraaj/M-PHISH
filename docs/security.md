# Security operations

Use the threat model and deployment runbook before exposing the service. Keep PostgreSQL/Redis private, use TLS and scoped credentials, close production registration, configure exact HTTPS origins and allowlisted extension IDs, and deploy the collector without secrets behind host egress rules.

Runtime Python dependencies were audited after dependency upgrades; the recorded `dependency-audit-final.json` reported no known advisories at scan time. Initial findings are retained for traceability. Node audits and final verification results belong in release artifacts. Scanner output is advisory-database coverage, not proof that code or transitives are secure.

Do not place credentials, reports or private datasets in source, CI logs or release archives. A public reporting contact must be configured by the operator before distribution. For an incident, restrict ingress, disable the optional provider, stop collector/worker execution if necessary, revoke affected sessions and rotate compromised secrets; preserve sanitized request IDs and operational evidence. See OPERATIONS.md for recovery steps.
