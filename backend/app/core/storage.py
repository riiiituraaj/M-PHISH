"""Transactional storage. Schema changes are performed only by Alembic."""

import os
import time
from contextlib import contextmanager

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    delete,
    select,
)

metadata = MetaData()
users = Table(
    "account_users",
    metadata,
    Column("id", String(36), primary_key=True),
    Column("email", String(254), unique=True, nullable=False),
    Column("password_hash", Text, nullable=False),
    Column("role", String(10), nullable=False),
    Column("settings", Text, nullable=False),
    Column("created_at", Float, nullable=False),
)
sessions = Table(
    "account_sessions",
    metadata,
    Column("digest", String(64), primary_key=True),
    Column(
        "user_id",
        String(36),
        ForeignKey(users.c.id, ondelete="CASCADE"),
        nullable=False,
    ),
    Column("expires_at", Float, nullable=False),
    Column("kind", String(20), nullable=False),
    Column("extension_id", String(32)),
)
pairs = Table(
    "extension_pairs",
    metadata,
    Column("digest", String(64), primary_key=True),
    Column(
        "user_id",
        String(36),
        ForeignKey(users.c.id, ondelete="CASCADE"),
        nullable=False,
    ),
    Column("extension_id", String(32), nullable=False),
    Column("expires_at", Float, nullable=False),
)
jobs = Table(
    "owned_jobs",
    metadata,
    Column("id", String(36), primary_key=True),
    Column(
        "owner_id",
        String(36),
        ForeignKey(users.c.id, ondelete="CASCADE"),
        nullable=False,
    ),
    Column("url", Text, nullable=False),
    Column("status", String(20), nullable=False),
    Column("context", Text, nullable=False),
    Column("created_at", Float, nullable=False),
    Column("updated_at", Float, nullable=False),
    Column("expires_at", Float, nullable=False),
    Column("history", Boolean, nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("lease_until", Float),
    Column("lease_token", String(36)),
    Column("error", String(120)),
    Column("request_id", String(36), nullable=False),
)
Index("ix_owned_jobs_owner_created", jobs.c.owner_id, jobs.c.created_at)
reports = Table(
    "owned_reports",
    metadata,
    Column("id", String(36), ForeignKey(jobs.c.id, ondelete="CASCADE"), primary_key=True),
    Column(
        "owner_id",
        String(36),
        ForeignKey(users.c.id, ondelete="CASCADE"),
        nullable=False,
    ),
    Column("payload", Text, nullable=False),
)
quotas = Table(
    "request_quotas",
    metadata,
    Column("key", String(100), primary_key=True),
    Column("count", Integer, nullable=False),
    Column("expires_at", Float, nullable=False),
)

_engine = None


def engine():
    global _engine
    if _engine is None:
        url = os.getenv("DATABASE_URL", "sqlite:///backend/m_phish.db")
        _engine = create_engine(
            url,
            pool_pre_ping=True,
            connect_args={"check_same_thread": False} if url.startswith("sqlite") else {},
        )
        if url.startswith("sqlite"):
            from sqlalchemy import event

            @event.listens_for(_engine, "connect")
            def configure_sqlite(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=10000")

    return _engine


@contextmanager
def transaction():
    with engine().begin() as connection:
        yield connection


def purge_expired():
    with transaction() as connection:
        stamp = time.time()
        result = connection.execute(delete(jobs).where(jobs.c.expires_at < stamp))
        for table in (sessions, pairs, quotas):
            connection.execute(delete(table).where(table.c.expires_at < stamp))
        return result.rowcount


def owned_job(connection, job_id, owner_id):
    return (
        connection.execute(
            select(jobs).where(
                jobs.c.id == job_id,
                jobs.c.owner_id == owner_id,
                jobs.c.expires_at > time.time(),
            )
        )
        .mappings()
        .first()
    )
