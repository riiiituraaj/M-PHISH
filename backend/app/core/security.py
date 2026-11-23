"""Opaque revocable sessions with pwdlib's recommended Argon2 password hashing."""

import hashlib
import os
import secrets
import time

from fastapi import HTTPException, Request
from pwdlib import PasswordHash
from sqlalchemy import delete, select

from .storage import sessions, transaction, users

password_hash = PasswordHash.recommended()
DEFAULT_SETTINGS = {
    "knowledge_level": "standard",
    "history_enabled": True,
    "ai_enabled": False,
    "notifications_enabled": True,
    "retention_days": 7,
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def public_user(row):
    return {key: row[key] for key in ("id", "email", "role")}


def issue_session(user_id, kind="web", extension_id=None):
    token = secrets.token_urlsafe(32)
    duration = 1800 if kind == "extension" else 28800
    with transaction() as conn:
        conn.execute(
            sessions.insert().values(
                digest=digest(token),
                user_id=user_id,
                expires_at=time.time() + duration,
                kind=kind,
                extension_id=extension_id,
            )
        )
    return token, duration


def token_from(request):
    authorization = request.headers.get("authorization", "")
    return (
        authorization[7:]
        if authorization.startswith("Bearer ")
        else request.cookies.get("m_phish_session", "")
    )


def origins():
    return [
        value.strip()
        for value in os.getenv("WEB_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(
            ","
        )
        if value.strip()
    ]


def extensions():
    return [value.strip() for value in os.getenv("EXTENSION_IDS", "").split(",") if value.strip()]


def current_user(request: Request):
    token = token_from(request)
    if not token:
        raise HTTPException(401, "Sign in to continue.")
    with transaction() as conn:
        row = (
            conn.execute(
                select(users, sessions.c.kind, sessions.c.extension_id)
                .join(sessions, sessions.c.user_id == users.c.id)
                .where(
                    sessions.c.digest == digest(token),
                    sessions.c.expires_at > time.time(),
                )
            )
            .mappings()
            .first()
        )
    if not row:
        raise HTTPException(401, "Session expired or revoked.")
    if row["kind"] == "extension":
        if (
            request.headers.get("origin") != "chrome-extension://" + row["extension_id"]
            or row["extension_id"] not in extensions()
        ):
            raise HTTPException(403, "Extension origin is not authorized.")
    elif (
        request.method not in ("GET", "HEAD", "OPTIONS")
        and request.headers.get("origin") not in origins()
    ):
        raise HTTPException(403, "A permitted Origin header is required.")
    return dict(row)


def require_admin(user):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required.")


def revoke(request):
    with transaction() as conn:
        conn.execute(delete(sessions).where(sessions.c.digest == digest(token_from(request))))
