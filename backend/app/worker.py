"""Run the durable queue using the explicitly configured Redis connection."""

import os

from redis import Redis
from rq import Queue, Worker


def main():
    connection = Redis.from_url(os.environ["REDIS_URL"])
    Worker([Queue("investigations", connection=connection)], connection=connection).work(
        with_scheduler=True
    )


if __name__ == "__main__":
    main()
