# Threat Model

## SSRF

User URLs are limited to HTTP(S). Localhost, loopback, private, link-local, and reserved addresses are rejected, including DNS resolutions that return those ranges. Redirect validation must be repeated inside any future remote crawler.

## Untrusted pages

The current local analyzer reads only bundled harmless samples. A remote Playwright worker must use a disposable browser context, timeouts, redirect and response-size limits, a non-root restricted container, and no host mounts before enablement.

## Abuse

Investigation endpoints have a configurable in-process rate limit for local protection. Production deployments should enforce authenticated tenant/IP quotas at the gateway and retain structured audit events.
