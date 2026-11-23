"""Authenticated API and equivalent legacy aliases over owner-scoped queries."""

import hashlib
import json
import logging
import os
import secrets
import time
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from starlette.middleware.base import BaseHTTPMiddleware

from .contracts import (
    Credentials,
    DynamicTrustRequest,
    ExchangeRequest,
    InvestigationRequest,
    PairRequest,
    UserSettings,
)
from .core import security as auth
from .core import storage as db

logger = logging.getLogger("m_phish.api")
PUBLIC = {
    "/api/health",
    "/api/v1/health",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/pair/exchange",
}


def envelope(request, data):
    return {"success": True, "data": data, "request_id": request.state.request_id}


def fail(request, status, message):
    return JSONResponse(
        {
            "success": False,
            "error": {"code": str(status), "message": message},
            "request_id": request.state.request_id,
        },
        status_code=status,
    )


def iso(stamp):
    return datetime.fromtimestamp(stamp, UTC).isoformat()


def quota(key, limit):
    stamp = time.time()
    bucket = int(stamp // 60)
    key = hashlib.sha256(key.encode()).hexdigest() + ":" + str(bucket)
    with db.transaction() as conn:
        if conn.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        stmt = insert(db.quotas).values(key=key, count=1, expires_at=stamp + 120)
        stmt = stmt.on_conflict_do_update(
            index_elements=["key"], set_={"count": db.quotas.c.count + 1}
        )
        conn.execute(stmt)
        count = conn.execute(select(db.quotas.c.count).where(db.quotas.c.key == key)).scalar_one()
    if count > limit:
        raise HTTPException(429, "Request quota exceeded; retry in one minute.")


class Boundary(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request.state.request_id = str(uuid4())
        started = time.perf_counter()
        try:
            if request.method in ("POST", "PATCH", "PUT"):
                size = 0
                chunks = []
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 32768:
                        raise HTTPException(413, "Payload exceeds 32 KiB.")
                    chunks.append(chunk)
                request._body = b"".join(chunks)
            if request.url.path.startswith("/api/") and request.method != "OPTIONS":
                client = request.client.host if request.client else "unknown"
                if request.url.path not in PUBLIC:
                    request.state.user = auth.current_user(request)
                    quota("user:" + request.state.user["id"], 120)
                elif request.url.path.endswith(("/login", "/register", "/exchange")):
                    quota("auth:" + client, 10)
                if request.method == "POST" or request.url.path.endswith("/export"):
                    quota(
                        "expensive:" + getattr(request.state, "user", {}).get("id", client),
                        30,
                    )
            response = await call_next(request)
        except HTTPException as error:
            response = fail(request, error.status_code, error.detail)
        except Exception as error:  # noqa: BLE001 -- final API boundary; no error text leaks
            logger.error(
                "request_failed type=%s request_id=%s",
                type(error).__name__,
                request.state.request_id,
            )
            response = fail(request, 503, "Service temporarily unavailable.")
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        logger.info(
            "request_id=%s method=%s status=%s duration_ms=%.1f",
            request.state.request_id,
            request.method,
            response.status_code,
            (time.perf_counter() - started) * 1000,
        )
        return response


def install(app, build_report, quick_check):
    app.add_middleware(Boundary)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=auth.origins() + ["chrome-extension://" + v for v in auth.extensions()],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
        expose_headers=["X-Request-ID"],
    )

    @app.exception_handler(HTTPException)
    async def http_error(request, error):
        return fail(request, error.status_code, error.detail)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        # Never echo invalid input: it can include credentials and tokens.
        return fail(request, 422, "Input does not match the request contract.")

    @app.get("/api/health")
    @app.get("/api/v1/health")
    def health(request: Request):
        data = {"status": "ok", "service": "m-phish", "version": "0.2.0"}
        return envelope(request, data) if "/v1/" in request.url.path else data

    def login_response(request, user):
        token, duration = auth.issue_session(user["id"])
        response = JSONResponse(envelope(request, {"user": auth.public_user(user)}))
        response.set_cookie(
            "m_phish_session",
            token,
            max_age=duration,
            httponly=True,
            secure=os.getenv("APP_ENV") == "production",
            samesite="strict",
            path="/",
        )
        return response

    @app.post("/api/v1/auth/register")
    def register(payload: Credentials, request: Request):
        if (
            os.getenv(
                "ALLOW_REGISTRATION",
                "true" if os.getenv("APP_ENV", "development") != "production" else "false",
            )
            != "true"
        ):
            raise HTTPException(403, "Registration is closed. Contact the service operator.")
        if request.headers.get("origin") not in auth.origins():
            raise HTTPException(403, "Origin is not permitted.")
        user = {
            "id": str(uuid4()),
            "email": payload.email.lower(),
            "password_hash": auth.password_hash.hash(payload.password),
            "role": "user",
            "settings": json.dumps(auth.DEFAULT_SETTINGS),
            "created_at": time.time(),
        }
        try:
            with db.transaction() as conn:
                conn.execute(db.users.insert().values(**user))
        except IntegrityError:
            raise HTTPException(409, "Account cannot be created with these details.") from None
        return login_response(request, user)

    @app.post("/api/v1/auth/login")
    def login(payload: Credentials, request: Request):
        if request.headers.get("origin") not in auth.origins():
            raise HTTPException(403, "Origin is not permitted.")
        with db.transaction() as conn:
            user = (
                conn.execute(select(db.users).where(db.users.c.email == payload.email.lower()))
                .mappings()
                .first()
            )
        stored = (
            user["password_hash"] if user else auth.password_hash.hash(secrets.token_urlsafe(24))
        )
        valid = auth.password_hash.verify(payload.password, stored)
        if not user or not valid:
            raise HTTPException(401, "Invalid email or password.")
        return login_response(request, user)

    @app.get("/api/v1/auth/session")
    def session(request: Request):
        return envelope(request, {"user": auth.public_user(request.state.user)})

    @app.post("/api/v1/auth/logout")
    def logout(request: Request):
        auth.revoke(request)
        response = JSONResponse(envelope(request, {"revoked": True}))
        response.delete_cookie("m_phish_session", path="/")
        return response

    @app.delete("/api/v1/auth/account")
    def delete_account(request: Request):
        with db.transaction() as conn:
            conn.execute(delete(db.users).where(db.users.c.id == request.state.user["id"]))
        response = JSONResponse(envelope(request, {"deleted": True}))
        response.delete_cookie("m_phish_session", path="/")
        return response

    @app.post("/api/v1/auth/pair")
    def pair(payload: PairRequest, request: Request):
        if request.state.user["kind"] != "web" or payload.extension_id not in auth.extensions():
            raise HTTPException(403, "Extension ID must first be approved by the operator.")
        code = secrets.token_urlsafe(32)
        with db.transaction() as conn:
            conn.execute(
                db.pairs.insert().values(
                    digest=auth.digest(code),
                    user_id=request.state.user["id"],
                    extension_id=payload.extension_id,
                    expires_at=time.time() + 300,
                )
            )
        return envelope(request, {"code": code, "expires_in": 300})

    @app.post("/api/v1/auth/pair/exchange")
    def exchange(payload: ExchangeRequest, request: Request):
        if (
            payload.extension_id not in auth.extensions()
            or request.headers.get("origin") != "chrome-extension://" + payload.extension_id
        ):
            raise HTTPException(403, "Extension origin is not permitted.")
        with db.transaction() as conn:
            row = conn.execute(
                delete(db.pairs)
                .where(
                    db.pairs.c.digest == auth.digest(payload.code),
                    db.pairs.c.extension_id == payload.extension_id,
                    db.pairs.c.expires_at > time.time(),
                )
                .returning(db.pairs.c.user_id)
            ).first()
        if not row:
            raise HTTPException(401, "Pairing code expired or already used.")
        token, duration = auth.issue_session(row[0], "extension", payload.extension_id)
        return envelope(
            request,
            {"access_token": token, "token_type": "bearer", "expires_in": duration},
        )

    @app.get("/api/v1/settings")
    def get_settings(request: Request):
        return envelope(request, json.loads(request.state.user["settings"]))

    @app.patch("/api/v1/settings")
    def set_settings(payload: UserSettings, request: Request):
        values = json.loads(request.state.user["settings"]) | payload.model_dump(exclude_none=True)
        with db.transaction() as conn:
            conn.execute(
                update(db.users)
                .where(db.users.c.id == request.state.user["id"])
                .values(settings=json.dumps(values))
            )
        return envelope(request, values)

    def response_data(request, value):
        return envelope(request, value) if "/v1/" in request.url.path else value

    @app.post("/api/quick-check")
    @app.post("/api/v1/quick-check")
    def quick(payload: InvestigationRequest, request: Request):
        data = quick_check(payload.url)
        data.update(
            contract_version="2.0",
            coverage={"url": "available", "page": "unavailable"},
            protection_status="partial",
            limitations=[
                "URL path and query are omitted for privacy. URL-only checks cannot assess page behavior."
            ],
        )
        if payload.context.observations and payload.context.observations.consent:
            data["deep_required"] = data["deep_required"] or bool(
                payload.context.observations.fields
            )
        return response_data(request, data)

    @app.post("/api/investigations")
    @app.post("/api/v1/investigations")
    def create(payload: InvestigationRequest, request: Request):
        stamp, iid = time.time(), str(uuid4())
        settings = json.loads(request.state.user["settings"])
        with db.transaction() as conn:
            # Serialize enqueue limits for the same owner on PostgreSQL.
            conn.execute(
                select(db.users.c.id)
                .where(db.users.c.id == request.state.user["id"])
                .with_for_update()
            ).first()
            active = conn.execute(
                select(func.count())
                .select_from(db.jobs)
                .where(
                    db.jobs.c.owner_id == request.state.user["id"],
                    db.jobs.c.status.in_(["QUEUED", "ANALYZING"]),
                )
            ).scalar_one()
            total = conn.execute(
                select(func.count())
                .select_from(db.jobs)
                .where(db.jobs.c.status.in_(["QUEUED", "ANALYZING"]))
            ).scalar_one()
            if active >= 3 or total >= 200:
                raise HTTPException(429, "Investigation queue is at capacity.")
            context = payload.context.model_dump(exclude_none=True) | {
                "_ai_enabled": settings["ai_enabled"]
            }
            conn.execute(
                db.jobs.insert().values(
                    id=iid,
                    owner_id=request.state.user["id"],
                    url=payload.url,
                    status="QUEUED",
                    context=json.dumps(context),
                    created_at=stamp,
                    updated_at=stamp,
                    expires_at=stamp
                    + (settings["retention_days"] * 86400 if settings["history_enabled"] else 3600),
                    history=settings["history_enabled"],
                    attempts=0,
                    request_id=request.state.request_id,
                )
            )
        return response_data(
            request,
            {
                "id": iid,
                "url": payload.url,
                "status": "QUEUED",
                "created_at": iso(stamp),
            },
        )

    def read_owned(iid, request, report_only=False):
        with db.transaction() as conn:
            job = db.owned_job(conn, iid, request.state.user["id"])
            if not job:
                raise HTTPException(404, "Investigation not found.")
            row = conn.execute(
                select(db.reports.c.payload).where(
                    db.reports.c.id == iid,
                    db.reports.c.owner_id == request.state.user["id"],
                )
            ).first()
        if row:
            return json.loads(row[0])
        if report_only:
            raise HTTPException(409, "Report is not ready.")
        return {
            "id": job["id"],
            "url": job["url"],
            "status": job["status"],
            "error": job["error"],
            "created_at": iso(job["created_at"]),
            "updated_at": iso(job["updated_at"]),
        }

    @app.get("/api/investigations")
    @app.get("/api/v1/investigations")
    def listing(
        request: Request,
        limit: int = Query(25, ge=1, le=100),
        offset: int = Query(0, ge=0, le=10000),
        q: str = Query("", max_length=200),
        classification: str = Query("", max_length=30),
        sort: str = Query("newest", pattern="^(newest|oldest)$"),
    ):
        with db.transaction() as conn:
            stmt = (
                select(db.jobs, db.reports.c.payload)
                .outerjoin(db.reports, and_owner())
                .where(
                    db.jobs.c.owner_id == request.state.user["id"],
                    db.jobs.c.expires_at > time.time(),
                    db.jobs.c.history.is_(True),
                )
            )
            if q:
                stmt = stmt.where(db.jobs.c.url.contains(q, autoescape=True))
            if classification:
                if conn.dialect.name == "postgresql":
                    from sqlalchemy import JSON, cast

                    stmt = stmt.where(
                        cast(db.reports.c.payload, JSON)["classification"].as_string()
                        == classification
                    )
                else:
                    stmt = stmt.where(
                        func.json_extract(db.reports.c.payload, "$.classification")
                        == classification
                    )
            stmt = (
                stmt.order_by(
                    db.jobs.c.created_at.desc() if sort == "newest" else db.jobs.c.created_at.asc()
                )
                .offset(offset)
                .limit(limit)
            )
            rows = conn.execute(stmt).mappings().all()
        values = [
            json.loads(row["payload"])
            if row["payload"]
            else {
                "id": row["id"],
                "url": row["url"],
                "status": row["status"],
                "created_at": iso(row["created_at"]),
            }
            for row in rows
        ]
        return response_data(request, values)

    def and_owner():
        from sqlalchemy import and_

        return and_(db.reports.c.id == db.jobs.c.id, db.reports.c.owner_id == db.jobs.c.owner_id)

    @app.get("/api/investigations/{iid}")
    @app.get("/api/v1/investigations/{iid}")
    def read(iid: str, request: Request):
        return response_data(request, read_owned(iid, request))

    @app.get("/api/investigations/{iid}/{section}")
    @app.get("/api/v1/investigations/{iid}/{section}")
    def section(
        iid: str,
        section: str,
        request: Request,
        format: str = Query("json", pattern="^(json|pdf)$"),
    ):
        if section not in ("report", "evidence", "timeline", "graph", "export"):
            raise HTTPException(404, "Unknown report section.")
        value = read_owned(iid, request, True)
        if section == "export":
            if format == "pdf":
                from .exports import report_pdf

                return Response(
                    report_pdf(value),
                    media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="m-phish-{iid}.pdf"'},
                )
            return Response(
                json.dumps(value, indent=2),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="m-phish-{iid}.json"'},
            )
        field = {
            "evidence": "evidence",
            "timeline": "events",
            "graph": "context_graph",
        }.get(section)
        return response_data(request, value[field] if field else value)

    @app.delete("/api/investigations/{iid}")
    @app.delete("/api/v1/investigations/{iid}")
    def remove(iid: str, request: Request):
        with db.transaction() as conn:
            result = conn.execute(
                delete(db.jobs).where(
                    db.jobs.c.id == iid, db.jobs.c.owner_id == request.state.user["id"]
                )
            )
        if not result.rowcount:
            raise HTTPException(404, "Investigation not found.")
        return response_data(request, {"deleted": True})

    @app.post("/api/investigations/{iid}/{action}")
    @app.post("/api/v1/investigations/{iid}/{action}")
    def job_action(iid: str, action: str, request: Request):
        if action not in ("cancel", "retry"):
            raise HTTPException(404, "Unknown action.")
        with db.transaction() as conn:
            job = db.owned_job(conn, iid, request.state.user["id"])
            if not job:
                raise HTTPException(404, "Investigation not found.")
            allowed = ["QUEUED", "ANALYZING"] if action == "cancel" else ["FAILED", "CANCELLED"]
            if job["status"] not in allowed:
                raise HTTPException(409, "Action not valid for this job state.")
            state = "CANCELLED" if action == "cancel" else "QUEUED"
            conn.execute(
                update(db.jobs)
                .where(
                    db.jobs.c.id == iid,
                    db.jobs.c.owner_id == request.state.user["id"],
                    db.jobs.c.status.in_(allowed),
                )
                .values(
                    status=state,
                    attempts=0,
                    lease_until=None,
                    lease_token=None,
                    updated_at=time.time(),
                )
            )
        return response_data(request, {"id": iid, "status": state})

    @app.post("/api/v1/dynamic-trust/evaluate")
    def dynamic(payload: DynamicTrustRequest, request: Request):
        from dataclasses import asdict

        from .services.trust.engine import (
            DigitalTrustProfile,
            evaluate_dynamic_interaction,
        )

        details = payload.action_details.model_dump(exclude_none=True)
        details["page_url"] = payload.url
        details["form_action_url"] = (
            details.get("form_action")
            or details.get("form_action_url")
            or details.get("destination")
        )
        context = payload.context.model_dump(exclude_none=True)
        # Local rules only: dynamic requests never initiate network inspection or training.
        report = build_report(payload.url, context=context, remote=False)
        transition = evaluate_dynamic_interaction(
            DigitalTrustProfile(**report["digital_trust_profile"]),
            payload.action_type,
            details,
        )
        return envelope(
            request,
            {
                "transition": asdict(transition),
                "digital_trust_profile": report["digital_trust_profile"],
                "identity_analysis": report["identity_analysis"],
                "evidence": report["evidence"],
                "safe_route": None,
                "requires_intervention": transition.requires_intervention,
                "protection_status": "partial",
                "intervention_modal": {
                    "title": "Review this action",
                    "message": transition.reason,
                    "recommended_action": transition.recommended_action,
                },
            },
        )

    @app.get("/api/v1/research/experiments")
    def research(request: Request, force_rerun: bool = False):
        if force_rerun:
            raise HTTPException(
                403,
                "Training is available only through the offline administrative command.",
            )
        from .services.ml.experiments import run_multimodal_experiments

        values = run_multimodal_experiments()
        return envelope(
            request,
            {
                "experiments": values,
                "availability": "available" if values else "unavailable",
                "benchmark_dataset_samples": None,
                "evaluated_at": None,
                "primary_model": None,
                "limitations": ["No independent detection validation is bundled."],
            },
        )

    @app.get("/api/v1/demo/scenarios")
    def demos(request: Request):
        from pathlib import Path

        return envelope(
            request,
            [
                {
                    "id": p.stem,
                    "title": p.stem.replace("-", " "),
                    "description": "Isolated synthetic fixture; excluded from history and evaluation.",
                }
                for p in (Path(__file__).resolve().parents[2] / "data" / "samples").glob("*.html")
            ],
        )

    @app.post("/api/v1/demo/scenarios/{scenario}")
    def demo(scenario: str, request: Request):
        from pathlib import Path

        folder = Path(__file__).resolve().parents[2] / "data" / "samples"
        candidates = {p.stem: p for p in folder.glob("*.html")}
        if scenario not in candidates:
            raise HTTPException(404, "Scenario not found.")
        report = build_report(
            "https://demo.example/",
            fixture_html=candidates[scenario].read_text(encoding="utf-8"),
            remote=False,
        )
        report["demo"] = True
        report["limitations"].append(
            "Synthetic demonstration only; not a live observation or detection benchmark."
        )
        return envelope(request, report)

    @app.get("/api/v1/admin/status")
    def admin(request: Request):
        auth.require_admin(request.state.user)
        with db.transaction() as conn:
            counts = dict(
                conn.execute(
                    select(db.jobs.c.status, func.count()).group_by(db.jobs.c.status)
                ).all()
            )
        return envelope(
            request,
            {
                "queue": counts,
                "crawler_configured": bool(os.getenv("CRAWLER_URL")),
                "ml_artifact_configured": bool(os.getenv("ML_ARTIFACT_PATH")),
            },
        )

    @app.post("/api/v1/admin/retention")
    def retention(request: Request):
        auth.require_admin(request.state.user)
        return envelope(request, {"deleted_jobs": db.purge_expired()})
