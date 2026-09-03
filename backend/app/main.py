from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlparse
import ipaddress
import json
import re
import sqlite3
import socket
import os
import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import logging
import time

from .core.config import settings
from .core.logging import configure_logging
from .services.context.engine import build_relationships
from .services.risk.engine import assess
from .services.webpage.analyzer import analyze_sync
from .services.domain.analyzer import analyze as analyze_domain

app = FastAPI(title="M-PHISH X API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["https://m-phish.vercel.app"], allow_origin_regex=r"chrome-extension://.*", allow_methods=["*"], allow_headers=["*"])
configure_logging(settings.log_level)
logger = logging.getLogger("m_phish.api")
request_counts: dict[str, list[float]] = {}
JOBS: dict[str, dict] = {}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid4())
        started = time.perf_counter()
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        logger.info(json.dumps({"request_id": request_id, "method": request.method, "path": request.url.path, "status": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 2)}))
        return response


class InvestigationRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and request.url.path.endswith(("/investigations", "/quick-check")):
            client = request.client.host if request.client else "unknown"
            now_value = time.time()
            recent = [stamp for stamp in request_counts.get(client, []) if now_value - stamp < settings.rate_window_seconds]
            if len(recent) >= settings.investigation_rate_limit:
                return JSONResponse({"success": False, "error": {"code": "RATE_LIMITED", "message": "Too many investigations. Try again shortly."}, "request_id": str(uuid4())}, status_code=429)
            request_counts[client] = recent + [now_value]
        return await call_next(request)


class OptionalAPIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if settings.api_key and request.url.path.startswith("/api/v1") and request.headers.get("X-API-Key") != settings.api_key:
            return JSONResponse({"success": False, "error": {"code": "UNAUTHORIZED", "message": "A valid API key is required."}, "request_id": str(uuid4())}, status_code=401)
        return await call_next(request)


app.add_middleware(RequestContextMiddleware)
app.add_middleware(InvestigationRateLimitMiddleware)
app.add_middleware(OptionalAPIKeyMiddleware)

INVESTIGATIONS: dict[str, dict] = {}
DB_PATH = Path(os.getenv("SQLITE_DB_PATH", Path(__file__).resolve().parents[1] / "m_phish.db"))


def db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.execute("CREATE TABLE IF NOT EXISTS investigations (id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT, risk_score INTEGER, classification TEXT, summary TEXT, report TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT)")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(investigations)").fetchall()}
    if "summary" not in columns: connection.execute("ALTER TABLE investigations ADD COLUMN summary TEXT")
    if "report" not in columns: connection.execute("ALTER TABLE investigations ADD COLUMN report TEXT")
    if "completed_at" not in columns: connection.execute("ALTER TABLE investigations ADD COLUMN completed_at TEXT")
    connection.execute("CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, category TEXT, title TEXT, description TEXT, source TEXT, confidence REAL, severity TEXT, created_at TEXT)")
    connection.execute("CREATE TABLE IF NOT EXISTS features (id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, feature_name TEXT, feature_value TEXT, source TEXT)")
    connection.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, event_type TEXT, message TEXT, timestamp TEXT)")
    connection.execute("CREATE TABLE IF NOT EXISTS user_profile (id INTEGER PRIMARY KEY, knowledge_level TEXT DEFAULT 'standard', created_at TEXT, updated_at TEXT)")
    connection.commit()
    return connection


def save_report(report: dict) -> None:
    connection = db()
    connection.execute("INSERT OR REPLACE INTO investigations (id, url, status, risk_score, classification, summary, report, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (report["id"], report["url"], report["status"], report["risk_score"], report["classification"], report["summary"], json.dumps(report), report["created_at"], report.get("completed_at")))
    connection.executemany("INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", [(item["id"], report["id"], item["category"], item["title"], item["description"], item["source"], item["confidence"], item["severity"], item["created_at"]) for item in report["evidence"]])
    connection.executemany("INSERT INTO features (investigation_id, feature_name, feature_value, source) VALUES (?, ?, ?, ?)", [(report["id"], name, json.dumps(value), "url_analyzer") for name, value in report["features"].items()])
    connection.executemany("INSERT INTO events (investigation_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)", [(report["id"], event["event_type"], event["message"], event["timestamp"]) for event in report["events"]])
    connection.commit()
    connection.close()


def load_report(investigation_id: str) -> dict | None:
    if investigation_id in INVESTIGATIONS:
        return INVESTIGATIONS[investigation_id]
    connection = db()
    row = connection.execute("SELECT report FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    connection.close()
    if not row:
        return None
    report = json.loads(row[0])
    INVESTIGATIONS[investigation_id] = report
    return report


class InvestigationRequest(BaseModel):
    url: HttpUrl
    context: dict = {}


class QuickCheckRequest(BaseModel):
    url: HttpUrl
    context: dict = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ai_explanation(evidence: list[dict], score: int, classification: str, fallback_summary: str, fallback_recommendation: str) -> dict:
    """Use Groq only to phrase supplied evidence; local rules remain the fallback."""
    if settings.ai_provider.lower() != "groq" or not settings.groq_api_key:
        return {"provider": "fallback", "model": None, "summary": fallback_summary, "recommended_action": fallback_recommendation, "uncertainty": "AI explanation is unavailable; this result uses deterministic evidence."}
    supplied = [{"category": item["category"], "title": item["title"], "description": item["description"], "confidence": item["confidence"], "severity": item["severity"]} for item in evidence]
    prompt = "Use only this JSON evidence. Return JSON with summary, recommended_action, uncertainty. Be calm and defensive; do not invent facts. Risk score: " + str(score) + ". Classification: " + classification + ". Evidence: " + json.dumps(supplied)
    try:
        response = httpx.post("https://api.groq.com/openai/v1/chat/completions", headers={"Authorization": f"Bearer {settings.groq_api_key}", "Content-Type": "application/json"}, json={"model": settings.ai_model, "temperature": 0.1, "response_format": {"type": "json_object"}, "messages": [{"role": "system", "content": "Explain only supplied web-security evidence. Never invent domain history, reputation, malware, intent, or attacker identity."}, {"role": "user", "content": prompt}]}, timeout=12.0)
        response.raise_for_status()
        result = json.loads(response.json()["choices"][0]["message"]["content"])
        return {"provider": "groq", "model": settings.ai_model, "summary": str(result.get("summary", fallback_summary)), "recommended_action": str(result.get("recommended_action", fallback_recommendation)), "uncertainty": str(result.get("uncertainty", "This is an evidence-based risk assessment, not a guarantee."))}
    except Exception:
        logger.warning("AI provider unavailable; using fallback explanation")
        return {"provider": "fallback", "model": None, "summary": fallback_summary, "recommended_action": fallback_recommendation, "uncertainty": "The AI provider was unavailable; this result uses deterministic evidence."}


def validate_target(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Only http and https URLs are supported.")
    host = parsed.hostname.lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise HTTPException(400, "Local network targets are not allowed.")
    try:
        address = ipaddress.ip_address(host)
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
            raise HTTPException(400, "Private and local network targets are not allowed.")
    except ValueError:
        try:
            resolved = socket.getaddrinfo(host, None)
            for item in resolved:
                address = ipaddress.ip_address(item[4][0])
                if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                    raise HTTPException(400, "The target resolves to a private network address.")
        except socket.gaierror:
            pass


def analyze_url(url: str) -> tuple[dict, list[dict]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    text = url.lower()
    features = {
        "url_length": len(url), "hostname_length": len(host), "path_length": len(parsed.path),
        "query_length": len(parsed.query), "subdomain_count": max(0, len(host.split(".")) - 2),
        "dot_count": host.count("."), "hyphen_count": host.count("-"),
        "special_character_count": len(re.findall(r"[^a-zA-Z0-9./?=_-]", url)),
        "percent_encoded": "%" in url, "ip_based_url": False, "unusual_port": parsed.port not in (None, 80, 443),
        "https": parsed.scheme == "https",
    }
    try:
        ipaddress.ip_address(host)
        features["ip_based_url"] = True
    except ValueError:
        pass
    suspicious = [word for word in ("login", "verify", "secure", "account", "password", "update", "wallet") if word in text]
    features["suspicious_keywords"] = suspicious
    evidence = []
    if features["ip_based_url"]:
        evidence.append(ev("URL", "IP-based website address", "The address uses a raw IP instead of a domain name.", "url_analyzer", .96, "HIGH", 14))
    if features["unusual_port"]:
        evidence.append(ev("URL", "Unusual connection port", "The URL uses a non-standard web port.", "url_analyzer", .9, "MEDIUM", 8))
    if len(suspicious) >= 2:
        evidence.append(ev("URL", "Sensitive-action keywords", f"The address contains several sensitive-action terms: {', '.join(suspicious)}.", "url_analyzer", .8, "MEDIUM", 7))
    if parsed.scheme != "https":
        evidence.append(ev("DOMAIN", "Connection is not encrypted", "The website does not use HTTPS.", "url_analyzer", .99, "MEDIUM", 8))
    return features, evidence


def quick_check(url: str) -> dict:
    """Fast stage: URL-only signals, with no page fetch or AI work."""
    parsed = urlparse(url)
    features, evidence = analyze_url(url)
    score = min(100, sum(item["weight"] for item in evidence))
    uncertain = len(features.get("suspicious_keywords", [])) >= 2 or features.get("ip_based_url") or features.get("unusual_port")
    if score >= 50:
        tier = "HIGH"
    elif score >= 25 or uncertain:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    return {"status": "complete", "url": url, "hostname": parsed.hostname, "score": score, "tier": tier, "deep_required": tier != "LOW", "top_reasons": [item["title"] for item in evidence[:3]], "features": features}


def analyze_page(url: str) -> tuple[dict, list[dict]]:
    """Safe, bounded prototype analyzer. Remote crawling is opt-in for a later worker."""
    parsed = urlparse(url)
    sample = ""
    sample_path = Path(__file__).resolve().parents[2] / ".." / "data" / "samples"
    if parsed.hostname == "m-phish.local":
        candidate = sample_path / (parsed.path.strip("/") or "simple-site.html")
        if candidate.exists():
            sample = candidate.read_text(encoding="utf-8")[:1_000_000].lower()
    if not sample and settings.enable_playwright:
        remote = analyze_sync(url, settings.crawler_timeout_seconds, settings.max_redirects, settings.max_crawler_requests)
        evidence = []
        if remote["password_inputs"]:
            evidence.append(ev("CONTENT", "Password field detected", "The webpage contains a password input.", "playwright_analyzer", .98, "HIGH", 21))
        if remote["external_form_action"]:
            evidence.append(ev("BEHAVIOR", "External form destination", "A form sends submitted information to another domain.", "playwright_analyzer", .97, "HIGH", 20))
        if remote["login_like"] and not remote["password_inputs"]:
            evidence.append(ev("CONTENT", "Login-like page", "The page presents language associated with account access.", "playwright_analyzer", .78, "MEDIUM", 9))
        return remote, evidence
    password = bool(re.search(r'type=["\']password', sample))
    forms = len(re.findall(r"<form\b", sample))
    external_action = bool(re.search(r'<form[^>]+action=["\']https?://', sample))
    login_like = password or any(word in sample for word in ("sign in", "log in", "verify your account"))
    data = {"title": (re.search(r"<title>(.*?)</title>", sample, re.S) or ["", ""])[1].strip() or "Unavailable", "forms": forms, "password_inputs": int(password), "login_like": login_like, "external_form_action": external_action, "redirect_count": 0, "external_domain_count": 0, "screenshot": None}
    evidence = []
    if password:
        evidence.append(ev("CONTENT", "Password field detected", "The webpage contains a password input.", "webpage_analyzer", .98, "HIGH", 21))
    if external_action:
        evidence.append(ev("BEHAVIOR", "External form destination", "A form sends submitted information to another domain.", "webpage_analyzer", .97, "HIGH", 20))
    if login_like and not password:
        evidence.append(ev("CONTENT", "Login-like page", "The page presents language associated with account access.", "webpage_analyzer", .78, "MEDIUM", 9))
    return data, evidence


def ev(category, title, description, source, confidence, severity, weight):
    return {"id": str(uuid4()), "category": category, "title": title, "description": description, "source": source, "confidence": confidence, "severity": severity, "weight": weight, "created_at": now()}


def build_report(url: str, investigation_id: str | None = None) -> dict:
    validate_target(url)
    features, url_evidence = analyze_url(url)
    domain = analyze_domain(url)
    page, page_evidence = analyze_page(url)
    evidence = url_evidence + page_evidence
    if page.get("login_like") and any(x["category"] == "URL" for x in evidence):
        evidence.append(ev("CONTEXT", "Suspicious login interaction", "A login-like page is combined with unusual website-address signals.", "context_engine", .84, "HIGH", 16))
    assessment = assess(evidence)
    score = assessment.score
    classification = assessment.level
    if score >= 50 and page["login_like"]:
        summary = "This page shows several signs of a suspicious login attempt."
        recommendation = "Don't enter your password here. Open the official service directly instead."
    elif score >= 25:
        summary = "Some details about this website deserve a closer look before you continue."
        recommendation = "Avoid entering sensitive information until you confirm the website address."
    else:
        summary = "No strong warning pattern was found in this initial investigation."
        recommendation = "Continue normally, but keep checking the address before sharing sensitive information."
    ai = ai_explanation(evidence, score, classification, summary, recommendation)
    summary = ai["summary"]
    recommendation = ai["recommended_action"]
    created = now()
    iid = investigation_id or str(uuid4())
    events = [{"event_type": "URL analyzed", "message": "Website address and URL structure reviewed.", "timestamp": created}, {"event_type": "Page analyzed", "message": "Page structure and interaction indicators reviewed.", "timestamp": created}, {"event_type": "Risk assessment completed", "message": "Evidence combined into a transparent risk score.", "timestamp": created}, {"event_type": "Explanation generated", "message": "Fallback evidence-based guidance is ready.", "timestamp": created}]
    return {"id": iid, "url": url, "hostname": urlparse(url).hostname, "status": "completed", "risk_score": score, "classification": classification, "confidence": assessment.confidence, "top_factors": assessment.top_factors, "summary": summary, "recommendation": recommendation, "ai_report": ai, "evidence": evidence, "features": features, "domain_analysis": domain, "page_analysis": page, "events": events, "context_graph": build_relationships(urlparse(url).hostname or "", page), "created_at": created, "completed_at": created}


@app.get("/api/health")
def health(): return {"status": "ok", "service": "m-phish-x"}


@app.get("/api/v1/health")
def versioned_health(): return {"success": True, "data": health(), "request_id": str(uuid4())}


@app.post("/api/investigations")
def create_investigation(payload: InvestigationRequest):
    report = build_report(str(payload.url))
    report["context"] = payload.context
    INVESTIGATIONS[report["id"]] = report
    save_report(report)
    return report


@app.post("/api/quick-check")
def create_quick_check(payload: QuickCheckRequest):
    validate_target(str(payload.url))
    return quick_check(str(payload.url))


@app.get("/api/investigations")
def list_investigations():
    connection = db()
    rows = connection.execute("SELECT report FROM investigations ORDER BY created_at DESC").fetchall()
    connection.close()
    return [json.loads(row[0]) for row in rows]


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    report = load_report(investigation_id)
    if report is None: raise HTTPException(404, "Investigation not found")
    return report


@app.get("/api/investigations/{investigation_id}/evidence")
def get_evidence(investigation_id: str): return get_investigation(investigation_id)["evidence"]


@app.get("/api/investigations/{investigation_id}/report")
def get_report(investigation_id: str): return get_investigation(investigation_id)


@app.get("/api/investigations/{investigation_id}/graph")
def get_graph(investigation_id: str):
    report = get_investigation(investigation_id)
    return {"nodes": [{"id": "source", "label": "Interaction", "type": "source"}, {"id": "link", "label": report["hostname"], "type": "domain"}, {"id": "page", "label": "Website", "type": "page"}, {"id": "action", "label": "Login request", "type": "action"}], "edges": [["source", "link"], ["link", "page"], ["page", "action"]]}


@app.post("/api/v1/quick-check")
def versioned_quick_check(payload: QuickCheckRequest):
    validate_target(str(payload.url))
    return {"success": True, "data": quick_check(str(payload.url)), "request_id": str(uuid4())}


@app.post("/api/v1/investigations")
def versioned_investigation(payload: InvestigationRequest, background_tasks: BackgroundTasks):
    investigation_id = str(uuid4())
    JOBS[investigation_id] = {"id": investigation_id, "url": str(payload.url), "status": "QUEUED", "created_at": now()}
    background_tasks.add_task(run_investigation_job, investigation_id, str(payload.url), payload.context)
    return {"success": True, "data": {"id": investigation_id, "url": str(payload.url), "status": "QUEUED"}, "request_id": str(uuid4())}


def run_investigation_job(investigation_id: str, url: str, context: dict) -> None:
    JOBS[investigation_id]["status"] = "ANALYZING"
    try:
        report = build_report(url, investigation_id)
        report["context"] = context
        INVESTIGATIONS[investigation_id] = report
        save_report(report)
        JOBS[investigation_id] = {"id": investigation_id, "url": url, "status": "COMPLETED", "risk_score": report["risk_score"], "classification": report["classification"], "completed_at": report["completed_at"]}
    except Exception as error:
        logger.exception("investigation job failed")
        JOBS[investigation_id] = {"id": investigation_id, "url": url, "status": "FAILED", "error": type(error).__name__}


@app.get("/api/v1/investigations/{investigation_id}")
def versioned_get_investigation(investigation_id: str):
    if investigation_id in JOBS and JOBS[investigation_id]["status"] != "COMPLETED":
        return {"success": True, "data": JOBS[investigation_id], "request_id": str(uuid4())}
    report = dict(get_investigation(investigation_id))
    report["status"] = report.get("status", "COMPLETED").upper()
    return {"success": True, "data": report, "request_id": str(uuid4())}


@app.get("/api/v1/investigations")
def versioned_list_investigations():
    return {"success": True, "data": list_investigations(), "request_id": str(uuid4())}


@app.get("/api/v1/investigations/{investigation_id}/evidence")
def versioned_get_evidence(investigation_id: str):
    return {"success": True, "data": get_evidence(investigation_id), "request_id": str(uuid4())}


@app.get("/api/v1/investigations/{investigation_id}/timeline")
def versioned_get_timeline(investigation_id: str):
    return {"success": True, "data": get_investigation(investigation_id)["events"], "request_id": str(uuid4())}


@app.get("/api/v1/investigations/{investigation_id}/graph")
def versioned_get_graph(investigation_id: str):
    report = get_investigation(investigation_id)
    return {"success": True, "data": report.get("context_graph", get_graph(investigation_id)), "request_id": str(uuid4())}


@app.get("/api/v1/investigations/{investigation_id}/report")
def versioned_get_report(investigation_id: str):
    return {"success": True, "data": get_report(investigation_id), "request_id": str(uuid4())}
