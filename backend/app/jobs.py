"""Durable database outbox plus RQ execution; never crawl in the API process."""

import json
import os
import time
from uuid import uuid4

from sqlalchemy import and_, or_, select, update

from .core.storage import jobs, purge_expired, reports, transaction


def run_job(job_id):
    stamp, lease = time.time(), str(uuid4())
    with transaction() as conn:
        claimed = conn.execute(
            update(jobs)
            .where(
                jobs.c.id == job_id,
                jobs.c.expires_at > stamp,
                or_(
                    jobs.c.status == "QUEUED",
                    and_(jobs.c.status == "ANALYZING", jobs.c.lease_until < stamp),
                ),
                jobs.c.attempts < 3,
            )
            .values(
                status="ANALYZING",
                attempts=jobs.c.attempts + 1,
                lease_until=stamp + 40,
                lease_token=lease,
                updated_at=stamp,
            )
        )
        if not claimed.rowcount:
            return
        job = dict(conn.execute(select(jobs).where(jobs.c.id == job_id)).mappings().one())
    try:
        from .main import build_report

        with transaction() as conn:
            rows = conn.execute(
                select(reports.c.payload)
                .join(jobs, reports.c.id == jobs.c.id)
                .where(
                    reports.c.owner_id == job["owner_id"],
                    jobs.c.history.is_(True),
                    jobs.c.expires_at > time.time(),
                )
                .order_by(jobs.c.created_at.desc())
                .limit(100)
            ).all()
        recent = [json.loads(row[0]) | {"owner_id": job["owner_id"]} for row in rows]
        report = build_report(
            job["url"],
            job_id,
            json.loads(job["context"]),
            owner_id=job["owner_id"],
            recent_reports=recent,
        )
        report["request_id"] = job["request_id"]
        with transaction() as conn:
            finished = conn.execute(
                update(jobs)
                .where(
                    jobs.c.id == job_id,
                    jobs.c.status == "ANALYZING",
                    jobs.c.lease_token == lease,
                )
                .values(
                    status="COMPLETED",
                    updated_at=time.time(),
                    lease_until=None,
                    lease_token=None,
                )
            )
            if finished.rowcount:
                conn.execute(
                    reports.insert().values(
                        id=job_id, owner_id=job["owner_id"], payload=json.dumps(report)
                    )
                )
    except Exception as error:
        with transaction() as conn:
            conn.execute(
                update(jobs)
                .where(
                    jobs.c.id == job_id,
                    jobs.c.status == "ANALYZING",
                    jobs.c.lease_token == lease,
                )
                .values(
                    status="FAILED" if job["attempts"] >= 3 else "QUEUED",
                    error=type(error).__name__,
                    updated_at=time.time(),
                    lease_until=None,
                    lease_token=None,
                )
            )
        raise


def dispatch_once():
    from redis import Redis
    from rq import Queue, Retry
    from rq.exceptions import NoSuchJobError
    from rq.job import Job

    redis = Redis.from_url(os.environ["REDIS_URL"], socket_timeout=3)
    queue = Queue("investigations", connection=redis)
    with transaction() as conn:
        stamp = time.time()
        conn.execute(
            update(jobs)
            .where(
                jobs.c.status == "ANALYZING",
                jobs.c.lease_until < stamp,
                jobs.c.attempts >= 3,
            )
            .values(status="FAILED", error="LeaseExpired")
        )
        rows = conn.execute(
            select(jobs.c.id)
            .where(
                jobs.c.expires_at > stamp,
                jobs.c.attempts < 3,
                or_(
                    jobs.c.status == "QUEUED",
                    and_(jobs.c.status == "ANALYZING", jobs.c.lease_until < stamp),
                ),
            )
            .limit(200)
        ).all()
    for (job_id,) in rows:
        try:
            existing = Job.fetch(job_id, connection=redis)
            if existing.get_status() in ("queued", "started", "scheduled", "deferred"):
                continue
            existing.delete()
        except NoSuchJobError:
            pass
        queue.enqueue(
            run_job,
            job_id,
            job_id=job_id,
            job_timeout=30,
            result_ttl=60,
            failure_ttl=86400,
            retry=Retry(max=2, interval=[5, 15]),
        )
    purge_expired()


if __name__ == "__main__":
    import logging

    while True:
        try:
            dispatch_once()
        except Exception as error:  # noqa: BLE001 -- preserve outbox recovery on DB/provider outages
            logging.getLogger("m_phish.jobs").warning(
                "dispatcher unavailable: %s", type(error).__name__
            )
        time.sleep(2)
