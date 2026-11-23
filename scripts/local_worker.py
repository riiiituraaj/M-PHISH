"""Development-only job runner that works without Redis (for example on Windows).

The real deployment uses the dispatcher (backend.app.jobs) + RQ worker, which need
Redis, and RQ's worker does not run on Windows. This script polls the database for
queued investigations and runs them in-process with the same run_job() function.

Usage (from the project root, with DATABASE_URL set the same way as for the API):
    python scripts/local_worker.py
Optionally set CRAWLER_URL=http://127.0.0.1:8001 and run the collector so that
real page HTML is fetched; without it, reports contain URL-only evidence.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import and_, or_, select  # noqa: E402

from backend.app.core.storage import jobs, transaction  # noqa: E402
from backend.app.jobs import run_job  # noqa: E402


def pending_ids():
    stamp = time.time()
    with transaction() as conn:
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
            .order_by(jobs.c.created_at)
            .limit(20)
        ).all()
    return [row[0] for row in rows]


def main():
    print("Local worker running (no Redis). Press Ctrl+C to stop.", flush=True)
    while True:
        for job_id in pending_ids():
            print(f"Running investigation {job_id} ...", flush=True)
            try:
                run_job(job_id)
                print(f"  done: {job_id}", flush=True)
            except Exception as error:  # noqa: BLE001 -- keep polling; run_job records failure
                print(f"  failed: {job_id} ({type(error).__name__}: {error})", flush=True)
        time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
