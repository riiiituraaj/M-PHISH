# Operations runbook

## Routine operation

Monitor API health and error/latency percentiles, authenticated admin job counts, PostgreSQL disk/connections, Redis memory/persistence, queue depth/oldest age, worker heartbeats, timeouts/retries, collector rejection/unavailability and optional provider fallback rate. Structured request IDs support correlation without target URLs or bodies. Metrics export/alert routing is not yet integrated with a hosted monitoring service; configure it and prove alerts in staging.

Schedule `python -m backend.app.manage retention` at least daily in the backend environment. Record only counts/status. It removes expired jobs/reports and expired sessions/pairing records. Settings limit history to 1–30 days. Test account deletion and expiry against restored staging data as well as the live schema. Apply matching retention to backups and exported artifacts.

## Backup and restore rehearsal (required before launch)

1. Take a consistent PostgreSQL custom-format backup with `pg_dump --format=custom --file=backup.dump` using injected connection credentials; do not echo a DSN. Encrypt, restrict access and record schema/image revision and checksum. Redis AOF is enabled in local Compose; production Redis persistence must be configured separately. Database jobs are the durable outbox; a queue loss should be recoverable by dispatch.
2. Restore into a newly provisioned private staging database using `pg_restore --no-owner --dbname=STAGING_DATABASE backup.dump`. Keep API/dispatcher/workers stopped during restore. Use dedicated staging credentials and no production provider access.
3. Run migrations at the intended application revision. Check table counts, account ownership, session expiry and a controlled job lifecycle. Invalidate restored sessions before making the service reachable. Restart dispatcher/worker and prove queued or expired leases recover without duplicate report publication.
4. Record measured recovery time, recovered-data timestamp and verification results. RPO/RTO are not established until this rehearsal is performed. Destroy the temporary copy according to policy.

## Rollout and rollback

Keep the previous immutable backend/web digests, extension ZIP, checksums, configuration and pre-migration backup. Migrate first, then start the API, dispatcher and workers, and smoke-test a harmless target. If gates fail, restrict ingress and stop dispatch/collection; revert images only when schema compatibility is confirmed. Do not blindly downgrade Alembic on live data. Restore a backup into a replacement private database when schema rollback requires it, then verify ownership and invalidate sessions before switching traffic.

## Incident and provider shutdown

Set AI_PROVIDER=fallback and remove the provider secret from the runtime to disable optional provider use. Stop collector/worker services to halt network investigation while retaining account/history access. Restrict ingress during auth compromise, revoke sessions with an audited database operation scoped to affected users, rotate secrets and inspect sanitized request IDs. Do not publish target URLs or user report payloads in incident logs. Deleting an account revokes its sessions but is not an incident-response substitute for scoped revocation.

## Known operational gaps

No Docker host, private production services, deployment account, DNS, monitoring destination, backup store, support/security contact or store publisher account is established in this workspace. PostgreSQL/Redis crash recovery and host firewall checks have not run here. Capacity, restore times and uptime are unmeasured. These are explicit release blockers, not implied assurances from unit tests.
