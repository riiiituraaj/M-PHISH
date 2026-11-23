# Threat model and residual risks

Assets: account credentials/sessions, private reports, provider secrets, service network, queue capacity and users' interpretation of evidence. Untrusted boundaries include target URLs/DNS/redirects/content, browser messages, model artifacts and provider output.

Controls implemented and regression-tested include owner-scoped access, exact-origin checks, opaque hashed sessions, bounded schemas/quotas, single-use pairing, DNS/redirect/IP restrictions, peer verification, subprocess deadline, escaped exports, safe output rendering, client/server provenance separation, stale-result invalidation, offline model training and provider output grounding.

Deployment must independently enforce collector egress. Application URL checks alone are insufficient against network/configuration mistakes. Real Linux firewall behavior, PostgreSQL locking, Redis crash recovery and restore rehearsal remain unverified. Aggregate queue admission has a residual race across different owners; enforce infrastructure capacity and monitor depth until this is load-tested and hardened.

A malicious page can remove or spoof page-injected warnings and transmit data outside native submissions. Trusted-click checks prevent programmatic use of the extension's override button but do not turn the page into a trusted UI. DOM categories and client observations are claims with separate provenance. Synthetic language, brand mentions, TLS and shared infrastructure alone do not establish fraud or legitimacy.

No real-world detection operating point, independent penetration test, uptime commitment or legal certification is claimed. See FEATURE_MATRIX.md for incomplete feature-specific validation.
