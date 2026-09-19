from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlparse
from dataclasses import asdict
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

# Digital Trust & Web Safety Services
from .services.ml.model import get_threat_model
from .services.ml.experiments import run_multimodal_experiments
from .services.trust.engine import (
    compute_authenticity,
    compute_digital_trust_profile,
    evaluate_dynamic_interaction,
)
from .services.identity.analyzer import analyze_identity
from .services.privacy.analyzer import analyze_privacy
from .services.synthetic.analyzer import analyze_synthetic_content
from .services.claims.analyzer import analyze_deceptive_claims
from .services.download.analyzer import analyze_download
from .services.campaign.analyzer import analyze_campaign_similarity

app = FastAPI(
    title="M-PHISH X · Intelligent Digital Trust & Web Safety Platform",
    version="1.0.0",
    description="Multimodal digital trust, authenticity, and web safety layer.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://m-phish.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_origin_regex=r"(?:chrome-extension://.*|https://m-phish-[a-z0-9-]+\.vercel\.app)",
    allow_methods=["*"],
    allow_headers=["*"],
)
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
        logger.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                }
            )
        )
        return response


class InvestigationRateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and request.url.path.endswith(("/investigations", "/quick-check")):
            client = request.client.host if request.client else "unknown"
            now_value = time.time()
            recent = [
                stamp for stamp in request_counts.get(client, [])
                if now_value - stamp < settings.rate_window_seconds
            ]
            if len(recent) >= settings.investigation_rate_limit:
                return JSONResponse(
                    {
                        "success": False,
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many investigations. Try again shortly.",
                        },
                        "request_id": str(uuid4()),
                    },
                    status_code=429,
                )
            request_counts[client] = recent + [now_value]
        return await call_next(request)


class OptionalAPIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if (
            settings.api_key
            and request.url.path.startswith("/api/")
            and request.headers.get("X-API-Key") != settings.api_key
        ):
            return JSONResponse(
                {
                    "success": False,
                    "error": {"code": "UNAUTHORIZED", "message": "A valid API key is required."},
                    "request_id": str(uuid4()),
                },
                status_code=401,
            )
        return await call_next(request)


app.add_middleware(RequestContextMiddleware)
app.add_middleware(InvestigationRateLimitMiddleware)
app.add_middleware(OptionalAPIKeyMiddleware)

INVESTIGATIONS: dict[str, dict] = {}
DB_PATH = Path(os.getenv("SQLITE_DB_PATH", settings.database_path))


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS investigations ("
        "id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT, risk_score INTEGER, "
        "classification TEXT, summary TEXT, report TEXT NOT NULL, created_at TEXT NOT NULL, "
        "completed_at TEXT)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS investigation_jobs ("
        "id TEXT PRIMARY KEY, url TEXT NOT NULL, status TEXT NOT NULL, context TEXT NOT NULL, "
        "error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT)"
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(investigations)").fetchall()}
    if "summary" not in columns:
        connection.execute("ALTER TABLE investigations ADD COLUMN summary TEXT")
    if "report" not in columns:
        connection.execute("ALTER TABLE investigations ADD COLUMN report TEXT")
    if "completed_at" not in columns:
        connection.execute("ALTER TABLE investigations ADD COLUMN completed_at TEXT")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS evidence ("
        "id TEXT PRIMARY KEY, investigation_id TEXT NOT NULL, category TEXT, title TEXT, "
        "description TEXT, source TEXT, confidence REAL, severity TEXT, created_at TEXT)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS features ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, "
        "feature_name TEXT, feature_value TEXT, source TEXT)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, investigation_id TEXT NOT NULL, "
        "event_type TEXT, message TEXT, timestamp TEXT)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS user_profile ("
        "id INTEGER PRIMARY KEY, knowledge_level TEXT DEFAULT 'standard', created_at TEXT, updated_at TEXT)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_investigations_created_at ON investigations(created_at DESC)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_investigations_url_created_at ON investigations(url, created_at DESC)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_updated_at ON investigation_jobs(status, updated_at DESC)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_evidence_investigation_id ON evidence(investigation_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_features_investigation_id ON features(investigation_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_events_investigation_id ON events(investigation_id)")
    connection.commit()
    return connection


def save_report(report: dict) -> None:
    connection = db()
    connection.execute(
        "INSERT OR REPLACE INTO investigations (id, url, status, risk_score, classification, summary, report, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            report["id"],
            report["url"],
            report["status"],
            report["risk_score"],
            report["classification"],
            report["summary"],
            json.dumps(report),
            report["created_at"],
            report.get("completed_at"),
        ),
    )
    connection.execute("DELETE FROM evidence WHERE investigation_id = ?", (report["id"],))
    connection.execute("DELETE FROM features WHERE investigation_id = ?", (report["id"],))
    connection.execute("DELETE FROM events WHERE investigation_id = ?", (report["id"],))
    connection.executemany(
        "INSERT OR REPLACE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                item["id"],
                report["id"],
                item["category"],
                item["title"],
                item["description"],
                item["source"],
                item["confidence"],
                item["severity"],
                item["created_at"],
            )
            for item in report["evidence"]
        ],
    )
    connection.executemany(
        "INSERT INTO features (investigation_id, feature_name, feature_value, source) VALUES (?, ?, ?, ?)",
        [
            (report["id"], name, json.dumps(value), "url_analyzer")
            for name, value in report.get("features", {}).items()
        ],
    )
    connection.executemany(
        "INSERT INTO events (investigation_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)",
        [
            (report["id"], event["event_type"], event["message"], event["timestamp"])
            for event in report.get("events", [])
        ],
    )
    connection.commit()
    connection.close()


def load_report(investigation_id: str) -> dict | None:
    if investigation_id in INVESTIGATIONS:
        return INVESTIGATIONS[investigation_id]
    connection = db()
    row = connection.execute(
        "SELECT report FROM investigations WHERE id = ?", (investigation_id,)
    ).fetchone()
    connection.close()
    if not row:
        return None
    report = json.loads(row[0])
    INVESTIGATIONS[investigation_id] = report
    return report


def load_latest_report_for_url(url: str) -> dict | None:
    connection = db()
    row = connection.execute(
        "SELECT report FROM investigations WHERE url = ? ORDER BY created_at DESC LIMIT 1", (url,)
    ).fetchone()
    connection.close()
    return json.loads(row[0]) if row else None


def save_job(job: dict) -> None:
    connection = db()
    connection.execute(
        "INSERT OR REPLACE INTO investigation_jobs (id, url, status, context, error, created_at, updated_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            job["id"],
            job["url"],
            job["status"],
            json.dumps(job.get("context", {})),
            job.get("error"),
            job["created_at"],
            job.get("updated_at", job["created_at"]),
            job.get("completed_at"),
        ),
    )
    connection.commit()
    connection.close()


def load_job(investigation_id: str) -> dict | None:
    connection = db()
    row = connection.execute(
        "SELECT id, url, status, context, error, created_at, updated_at, completed_at FROM investigation_jobs WHERE id = ?",
        (investigation_id,),
    ).fetchone()
    connection.close()
    if not row:
        return None
    job = {
        "id": row[0],
        "url": row[1],
        "status": row[2],
        "context": json.loads(row[3] or "{}"),
        "created_at": row[5],
        "updated_at": row[6],
    }
    if row[4]:
        job["error"] = row[4]
    if row[7]:
        job["completed_at"] = row[7]
    return job


class InvestigationRequest(BaseModel):
    url: HttpUrl
    context: dict = Field(default_factory=dict)


class QuickCheckRequest(BaseModel):
    url: HttpUrl
    context: dict = Field(default_factory=dict)


class DynamicTrustRequest(BaseModel):
    url: HttpUrl
    action_type: str = "password_focused"  # form_focused, password_focused, card_focused, download_attempt
    action_details: dict = Field(default_factory=dict)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ev(category, title, description, source, confidence, severity, weight):
    return {
        "id": str(uuid4()),
        "category": category,
        "title": title,
        "description": description,
        "source": source,
        "confidence": confidence,
        "severity": severity,
        "weight": weight,
        "created_at": now(),
    }


def ai_explanation(
    evidence: list[dict],
    score: int,
    classification: str,
    fallback_summary: str,
    fallback_recommendation: str,
    what_happened: str = "",
    why_it_matters: str = "",
    what_to_do: str = "",
) -> dict:
    """Ground explanations defensively in structured evidence without inventing facts."""
    if settings.ai_provider.lower() != "groq" or not settings.groq_api_key:
        return {
            "provider": "fallback",
            "model": None,
            "summary": fallback_summary,
            "recommended_action": fallback_recommendation,
            "what_happened": what_happened or fallback_summary,
            "why_it_matters": why_it_matters or "Understanding who receives your data protects against credential theft.",
            "what_to_do": what_to_do or fallback_recommendation,
            "uncertainty": "This digital trust assessment combines deterministic signals with a calibrated model trained on the configured development benchmark. It is not a guarantee of intent or safety.",
        }
    supplied = [
        {
            "category": item["category"],
            "title": item["title"],
            "description": item["description"],
            "confidence": item["confidence"],
            "severity": item["severity"],
        }
        for item in evidence
    ]
    prompt = (
        "Explain this digital trust evidence using three sections: 'what_happened', 'why_it_matters', 'what_to_do', and 'summary'. "
        "Be calm, protective, and non-alarmist. Never invent domain history, reputation, attacker identities, or malware. "
        f"Trust score: {score}. Status: {classification}. Evidence: {json.dumps(supplied)}"
    )
    try:
        response = httpx.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {settings.groq_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.ai_model,
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [
                    {
                        "role": "system",
                        "content": "You are M-PHISH X's calm explanation layer. Explain only supplied web-security evidence. Never invent external facts.",
                    },
                    {"role": "user", "content": prompt},
                ],
            },
            timeout=10.0,
        )
        response.raise_for_status()
        result = json.loads(response.json()["choices"][0]["message"]["content"])
        return {
            "provider": "groq",
            "model": settings.ai_model,
            "summary": str(result.get("summary", fallback_summary)),
            "recommended_action": str(result.get("what_to_do", fallback_recommendation)),
            "what_happened": str(result.get("what_happened", what_happened or fallback_summary)),
            "why_it_matters": str(result.get("why_it_matters", why_it_matters)),
            "what_to_do": str(result.get("what_to_do", what_to_do or fallback_recommendation)),
            "uncertainty": str(result.get("uncertainty", "This is an evidence-based digital trust assessment.")),
        }
    except Exception:
        logger.warning("AI provider unavailable; falling back to deterministic phrasing")
        return {
            "provider": "fallback",
            "model": None,
            "summary": fallback_summary,
            "recommended_action": fallback_recommendation,
            "what_happened": what_happened or fallback_summary,
            "why_it_matters": why_it_matters or "Understanding who receives your data protects against credential theft.",
            "what_to_do": what_to_do or fallback_recommendation,
            "uncertainty": "This digital trust assessment combines deterministic signals with a calibrated model trained on the configured development benchmark. It is not a guarantee of intent or safety.",
        }


def validate_target(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "Only http and https URLs are supported.")
    if len(url) > 2048:
        raise HTTPException(400, "The target URL is too long.")
    if parsed.username or parsed.password:
        raise HTTPException(400, "URLs containing embedded credentials are not supported.")
    host = parsed.hostname.lower().rstrip(".")
    # Allow m-phish.local for safe, sandboxed local fixtures
    if host == "m-phish.local":
        return
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise HTTPException(400, "Local network targets are not allowed.")
    try:
        address = ipaddress.ip_address(host)
        if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified:
            raise HTTPException(400, "Private and local network targets are not allowed.")
    except ValueError:
        try:
            resolved = socket.getaddrinfo(host, None)
            for item in resolved:
                address = ipaddress.ip_address(item[4][0])
                if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified:
                    raise HTTPException(400, "The target resolves to a private network address.")
        except socket.gaierror:
            pass


def analyze_url(url: str) -> tuple[dict, list[dict]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    text = url.lower()
    features = {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "subdomain_count": max(0, len(host.split(".")) - 2),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "special_character_count": len(re.findall(r"[^a-zA-Z0-9./?=_-]", url)),
        "percent_encoded": "%" in url,
        "ip_based_url": False,
        "unusual_port": parsed.port not in (None, 80, 443),
        "https": parsed.scheme == "https",
    }
    try:
        ipaddress.ip_address(host)
        features["ip_based_url"] = True
    except ValueError:
        pass
    suspicious = [
        word
        for word in ("login", "verify", "secure", "account", "password", "update", "wallet", "banking", "signin")
        if word in text
    ]
    features["suspicious_keywords"] = suspicious
    evidence = []
    if features["ip_based_url"]:
        evidence.append(
            ev("URL", "IP-based website address", "The address uses a raw IP address instead of a domain name.", "url_analyzer", 0.96, "HIGH", 16)
        )
    if features["unusual_port"]:
        evidence.append(
            ev("URL", "Unusual connection port", "The website connects via a non-standard port.", "url_analyzer", 0.9, "MEDIUM", 8)
        )
    if len(suspicious) >= 2:
        evidence.append(
            ev("URL", "Sensitive action terms in address", f"The address includes multiple authentication terms: {', '.join(suspicious)}.", "url_analyzer", 0.8, "MEDIUM", 9)
        )
    if parsed.scheme != "https":
        evidence.append(
            ev("DOMAIN", "Connection is not encrypted (HTTP)", "The website does not employ transport layer security (HTTPS).", "url_analyzer", 0.99, "HIGH", 12)
        )
    return features, evidence


def quick_check(url: str) -> dict:
    """Fast stage: URL-only assessment with deterministic tier and reasons."""
    parsed = urlparse(url)
    features, evidence = analyze_url(url)
    score = min(100, sum(item["weight"] for item in evidence))
    uncertain = len(features.get("suspicious_keywords", [])) >= 2 or features.get("ip_based_url") or features.get("unusual_port")
    if score >= 50:
        tier = "HIGH"
    elif score >= 20 or uncertain:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    return {
        "status": "complete",
        "url": url,
        "hostname": parsed.hostname,
        "score": score,
        "tier": tier,
        "deep_required": tier != "LOW",
        "top_reasons": [item["title"] for item in evidence[:3]],
        "features": features,
    }


def analyze_page(url: str) -> tuple[dict, list[dict], str]:
    """Safe, bounded prototype analyzer supporting local fixtures and optional sandboxed crawler."""
    parsed = urlparse(url)
    sample = ""
    sample_path = Path(__file__).resolve().parents[2] / "data" / "samples"
    if parsed.hostname == "m-phish.local":
        path_candidate = parsed.path.strip("/") or "simple-site.html"
        candidate = sample_path / path_candidate
        if candidate.exists():
            sample = candidate.read_text(encoding="utf-8")[:1_000_000]

    if not sample and settings.enable_playwright:
        remote = analyze_sync(
            url,
            settings.crawler_timeout_seconds,
            settings.max_redirects,
            settings.max_crawler_requests,
        )
        evidence = []
        if remote.get("password_inputs"):
            evidence.append(ev("CONTENT", "Password field detected", "The webpage contains a credential password field.", "playwright_analyzer", 0.98, "HIGH", 21))
        if remote.get("external_form_action"):
            evidence.append(ev("BEHAVIOR", "External credential destination", "Form action sends submitted credentials to an external domain.", "playwright_analyzer", 0.97, "HIGH", 24))
        if remote.get("login_like") and not remote.get("password_inputs"):
            evidence.append(ev("CONTENT", "Account access language", "The page presents authentication terminology.", "playwright_analyzer", 0.78, "MEDIUM", 9))
        return remote, evidence, ""

    sample_lower = sample.lower()
    password = bool(re.search(r'type=["\']password', sample_lower))
    forms = len(re.findall(r"<form\b", sample_lower))
    action_match = re.search(r'<form[^>]+action=["\'](https?://[^"\']+)["\']', sample_lower)
    form_action_url = action_match.group(1) if action_match else ""
    external_action = bool(form_action_url and urlparse(form_action_url).hostname != parsed.hostname)
    login_like = password or any(w in sample_lower for w in ("sign in", "log in", "verify your account", "verify your credentials"))
    has_urgency = any(w in sample_lower for w in ("immediate", "suspended", "urgent", "critical update", "voucher"))
    has_download = bool(re.search(r'href=["\'][^"\']+\.(exe|msi|bat|zip)["\']', sample_lower))

    title_match = re.search(r"<title>(.*?)</title>", sample, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else "Unavailable"

    data = {
        "title": title or "Unavailable",
        "forms": forms,
        "password_inputs": int(password),
        "text_inputs": len(re.findall(r'<input\b(?![^>]*type=["\'](?:hidden|submit|button|password)["\'])', sample_lower)),
        "hidden_inputs": len(re.findall(r'type=["\']hidden', sample_lower)),
        "login_like": login_like,
        "external_form_action": external_action,
        "form_action_url": form_action_url,
        "urgency_text": has_urgency,
        "initiates_download": has_download,
        "redirect_count": 0,
        "external_domain_count": 1 if external_action else 0,
        "screenshot": None,
    }
    evidence = []
    if password:
        evidence.append(ev("CONTENT", "Password field detected", "The webpage asks for sensitive password credentials.", "webpage_analyzer", 0.98, "HIGH", 21))
    if external_action:
        evidence.append(ev("BEHAVIOR", "Cross-origin form destination", f"Submitted data is dispatched to an external domain ({urlparse(form_action_url).hostname}).", "webpage_analyzer", 0.97, "HIGH", 24))
    if login_like and not password:
        evidence.append(ev("CONTENT", "Login-like page", "The page uses account verification and sign-in language.", "webpage_analyzer", 0.78, "MEDIUM", 9))
    if has_urgency:
        evidence.append(ev("CONTENT", "Urgency language detected", "The page employs high-pressure messaging to induce immediate action.", "webpage_analyzer", 0.75, "MEDIUM", 8))

    return data, evidence, sample


def build_report(url: str, investigation_id: str | None = None, context: dict | None = None) -> dict:
    validate_target(url)
    features, url_evidence = analyze_url(url)
    domain = analyze_domain(url)
    page, page_evidence, raw_html = analyze_page(url)

    # 1. Identity Analysis ("Who am I giving this to?" & Safe Route)
    identity_res = analyze_identity(url, page, raw_html)

    # 2. Privacy Risk Assessment
    privacy_res = analyze_privacy(raw_html, page)

    # 3. Synthetic Web Analysis (AI-assisted content indicators)
    synthetic_res = analyze_synthetic_content(raw_html, page)

    # 4. Deceptive Claim Analysis
    claim_res = analyze_deceptive_claims(url, page, raw_html)

    # 5. ML Model Inference
    # Feed model-derived context too, so brand/organization consistency is not dependent on
    # whether a browser client happened to provide those flags.
    enriched_context = dict(context or {})
    enriched_context.setdefault("brand_name_mismatch", identity_res.is_impersonation_suspected)
    enriched_context.setdefault("claimed_org_unverified", identity_res.identity_consistency in {"LOW", "UNKNOWN"})
    ml_model = get_threat_model()
    ml_pred = ml_model.predict_multimodal(
        features,
        domain_analysis=domain,
        page_analysis=page,
        context=enriched_context,
    )

    # 6. Website Authenticity
    authenticity = compute_authenticity(
        identity_consistency=identity_res.identity_consistency,
        domain_data=domain,
        page_data=page,
        synthetic_data=asdict(synthetic_res),
    )

    # 7. Digital Trust Profile
    trust_profile = compute_digital_trust_profile(
        url_features=features,
        domain_data=domain,
        page_data=page,
        authenticity=authenticity,
        privacy_risk_score=privacy_res.privacy_risk_score,
        calibrated_ml_prob=ml_pred.calibrated_probability,
        evidence=url_evidence + page_evidence,
    )

    # 8. Download Assessment
    download_res = analyze_download(url, page, raw_html, overall_trust=trust_profile.overall_trust)

    # 9. Campaign Similarity (against stored recent investigations)
    recent_invs = list_investigations()[:10]
    campaign_res = analyze_campaign_similarity(url, page, features, recent_invs)

    # Combine Evidence across all dimensions
    evidence = list(url_evidence + page_evidence)

    if identity_res.is_impersonation_suspected:
        evidence.append(
            ev(
                "IDENTITY",
                f"Identity mismatch with {identity_res.claimed_service}",
                identity_res.explanation,
                "identity_engine",
                0.94,
                "HIGH",
                25,
            )
        )

    if privacy_res.sensitive_count >= 2:
        evidence.append(
            ev(
                "PRIVACY",
                f"High-sensitivity personal data collection ({privacy_res.sensitive_count} categories)",
                privacy_res.summary,
                "privacy_engine",
                0.89,
                "HIGH",
                18,
            )
        )
    elif privacy_res.sensitive_count == 1:
        evidence.append(
            ev(
                "PRIVACY",
                "Sensitive credential field requested",
                privacy_res.summary,
                "privacy_engine",
                0.85,
                "MEDIUM",
                10,
            )
        )

    if synthetic_res.is_synthetic_likely:
        evidence.append(
            ev(
                "CONTENT",
                "Possible AI-assisted or templated web content",
                f"{synthetic_res.explanation} (Note: AI-assisted creation is not inherently malicious).",
                "synthetic_analyzer",
                synthetic_res.confidence,
                "LOW",
                6,
            )
        )

    if download_res.has_download and download_res.is_executable_or_script:
        evidence.append(
            ev(
                "BEHAVIOR",
                f"Executable download target ({download_res.file_extension})",
                download_res.explanation,
                "download_analyzer",
                0.92,
                "HIGH",
                22,
            )
        )

    if page.get("login_like") and any(x["category"] == "URL" for x in evidence):
        evidence.append(
            ev(
                "CONTEXT",
                "Suspicious login interaction context",
                "A login page is hosted on an address exhibiting technical anomalies.",
                "context_engine",
                0.88,
                "HIGH",
                16,
            )
        )

    # Risk Assessment (Evidence Fusion with Calibrated ML Probability)
    assessment = assess(evidence, calibrated_ml_prob=ml_pred.calibrated_probability)
    risk_score = assessment.score
    classification = assessment.level

    # Formulate Human Explanations: What Happened? Why Does It Matter? What Should I Do?
    if trust_profile.trust_state == "STOP":
        what_happened = (
            f"This page requests sensitive information (such as passwords or payment data), "
            f"but its identity does not match the service it presents ({identity_res.claimed_service})."
        )
        why_it_matters = (
            "Submitting credentials or personal information to an unverified destination exposes you to account takeover and data theft."
        )
        what_to_do = (
            f"Do not enter passwords or personal data here. "
            + (f"Open the verified official portal instead: {identity_res.safe_route}." if identity_res.safe_route else "Verify the website address directly.")
        )
        summary = f"Severe trust concern: {identity_res.claimed_service} authentication imitation detected."
        recommendation = what_to_do

    elif trust_profile.trust_state == "HIGH_RISK":
        what_happened = (
            "This website exhibits multiple trust warnings, including sensitive interaction requests without confirmed identity."
        )
        why_it_matters = (
            "Unconfirmed websites asking for personal details present significant risks of identity harvesting or deceit."
        )
        what_to_do = "Avoid entering credentials until you confirm the exact website address."
        summary = "This website shows notable trust concerns. Exercise heightened vigilance."
        recommendation = what_to_do

    elif trust_profile.trust_state == "CAUTION":
        what_happened = "Some details about this website warrant careful attention before continuing."
        why_it_matters = "Unusual address parameters or minor technical anomalies require standard caution."
        what_to_do = "Proceed carefully. Avoid sharing private information unless you recognize this domain."
        summary = "Proceed with caution. Check the website address before continuing."
        recommendation = what_to_do

    else:
        what_happened = "The website address, security certificate, and structure are consistent with legitimate web services."
        why_it_matters = "No deceptive harvesting, cross-origin credential routing, or anomalous transport signals were observed."
        what_to_do = "You can interact with this website normally."
        summary = "Website appears trustworthy based on available evidence."
        recommendation = what_to_do

    ai = ai_explanation(
        evidence,
        risk_score,
        classification,
        summary,
        recommendation,
        what_happened=what_happened,
        why_it_matters=why_it_matters,
        what_to_do=what_to_do,
    )

    created = now()
    iid = investigation_id or str(uuid4())

    # Incident Timeline Events
    events = [
        {"event_type": "URL opened", "message": f"Navigation to {urlparse(url).hostname} evaluated.", "timestamp": created},
        {"event_type": "Transport security reviewed", "message": f"TLS and connection parameters assessed (HTTPS: {features.get('https')}).", "timestamp": created},
        {"event_type": "Page structure inspected", "message": f"Forms ({page.get('forms')}) and inputs ({page.get('password_inputs')} passwords) analyzed.", "timestamp": created},
        {"event_type": "Website identity evaluated", "message": f"Claimed service: {identity_res.claimed_service}; Consistency: {identity_res.identity_consistency}.", "timestamp": created},
        {"event_type": "Trust profile computed", "message": f"Assigned state: {trust_profile.trust_state} (Trust score: {trust_profile.overall_trust}/100).", "timestamp": created},
    ]
    if identity_res.is_impersonation_suspected:
        events.append({"event_type": "Risk escalated", "message": "Identity mismatch escalated trust state to protective alert.", "timestamp": created})

    return {
        "id": iid,
        "url": url,
        "hostname": urlparse(url).hostname,
        "status": "completed",
        "risk_score": risk_score,
        "classification": classification,
        "confidence": assessment.confidence,
        "top_factors": assessment.top_factors,
        "summary": ai.get("summary", summary),
        "recommendation": ai.get("recommended_action", recommendation),
        "what_happened": ai.get("what_happened", what_happened),
        "why_it_matters": ai.get("why_it_matters", why_it_matters),
        "what_to_do": ai.get("what_to_do", what_to_do),
        "ai_report": ai,
        "evidence": evidence,
        "features": features,
        "domain_analysis": domain,
        "page_analysis": page,
        "events": events,
        "context_graph": build_relationships(urlparse(url).hostname or "", page, context),
        "context": context or {},
        "model_context": enriched_context,
        "created_at": created,
        "completed_at": created,

        # Extended Intelligence Profiles
        "digital_trust_profile": asdict(trust_profile),
        "website_authenticity": asdict(authenticity),
        "identity_analysis": asdict(identity_res),
        "privacy_assessment": asdict(privacy_res),
        "synthetic_web_analysis": asdict(synthetic_res),
        "deceptive_claim_analysis": asdict(claim_res),
        "download_safety": asdict(download_res),
        "campaign_similarity": asdict(campaign_res),
        "ml_prediction": asdict(ml_pred),
        "ml_model_status": {
            "deployment_status": "production-approved" if ml_pred.production_ready else ("externally-benchmarked-unapproved" if ml_pred.training_data.startswith("external-csv:") else "development-only"),
            "training_data": ml_pred.training_data,
            "validation": ml_pred.validation,
        },
        "safe_route": identity_res.safe_route,
        "trust_before_you_act": {
            "requires_intervention": trust_profile.trust_state in ("HIGH_RISK", "STOP"),
            "banner_title": "Before you enter credentials" if trust_profile.trust_state == "STOP" else "Caution advised",
            "banner_message": what_happened,
            "recommended_action": what_to_do,
            "safe_route": identity_res.safe_route,
            "actions": ["Go back", "Open trusted site", "Continue anyway", "Why am I seeing this?"],
        },
    }


# Standard Health Endpoints
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "m-phish-x", "capabilities": ["trust-engine", "calibrated-ml", "identity-verification"]}


@app.get("/api/v1/health")
def versioned_health():
    return {"success": True, "data": health(), "request_id": str(uuid4())}


# Core Investigation Endpoints
@app.post("/api/investigations")
def create_investigation(payload: InvestigationRequest):
    report = build_report(str(payload.url), context=payload.context)
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
    if report is None:
        raise HTTPException(404, "Investigation not found")
    return report


@app.get("/api/investigations/{investigation_id}/evidence")
def get_evidence(investigation_id: str):
    return get_investigation(investigation_id)["evidence"]


@app.get("/api/investigations/{investigation_id}/report")
def get_report(investigation_id: str):
    return get_investigation(investigation_id)


@app.get("/api/investigations/{investigation_id}/graph")
def get_graph(investigation_id: str):
    report = get_investigation(investigation_id)
    return report.get(
        "context_graph",
        {
            "nodes": [
                {"id": "source", "label": "Interaction", "type": "source"},
                {"id": "link", "label": report["hostname"], "type": "domain"},
                {"id": "page", "label": "Website", "type": "page"},
                {"id": "action", "label": "Login request", "type": "action"},
            ],
            "edges": [["source", "link"], ["link", "page"], ["page", "action"]],
        },
    )


# Versioned Endpoints (/api/v1/)
@app.post("/api/v1/quick-check")
def versioned_quick_check(payload: QuickCheckRequest):
    validate_target(str(payload.url))
    return {"success": True, "data": quick_check(str(payload.url)), "request_id": str(uuid4())}


@app.post("/api/v1/investigations")
def versioned_investigation(payload: InvestigationRequest, background_tasks: BackgroundTasks):
    investigation_id = str(uuid4())
    created = now()
    job = {
        "id": investigation_id,
        "url": str(payload.url),
        "status": "QUEUED",
        "context": payload.context,
        "created_at": created,
        "updated_at": created,
    }
    JOBS[investigation_id] = job
    save_job(job)
    background_tasks.add_task(run_investigation_job, investigation_id, str(payload.url), payload.context)
    return {
        "success": True,
        "data": {"id": investigation_id, "url": str(payload.url), "status": "QUEUED"},
        "request_id": str(uuid4()),
    }


def run_investigation_job(investigation_id: str, url: str, context: dict) -> None:
    job = load_job(investigation_id) or JOBS.get(
        investigation_id, {"id": investigation_id, "url": url, "context": context, "created_at": now()}
    )
    job.update({"status": "ANALYZING", "updated_at": now()})
    JOBS[investigation_id] = job
    save_job(job)
    try:
        report = build_report(url, investigation_id, context)
        INVESTIGATIONS[investigation_id] = report
        save_report(report)
        job.update(
            {
                "status": "COMPLETED",
                "updated_at": now(),
                "risk_score": report["risk_score"],
                "classification": report["classification"],
                "completed_at": report["completed_at"],
            }
        )
    except Exception as error:
        logger.exception("investigation job failed")
        job.update({"status": "FAILED", "error": type(error).__name__, "updated_at": now()})
    JOBS[investigation_id] = job
    save_job(job)


@app.get("/api/v1/investigations/{investigation_id}")
def versioned_get_investigation(investigation_id: str):
    job = load_job(investigation_id) or JOBS.get(investigation_id)
    if job and job["status"] != "COMPLETED":
        return {"success": True, "data": job, "request_id": str(uuid4())}
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
    return {"success": True, "data": get_investigation(investigation_id).get("events", []), "request_id": str(uuid4())}


@app.get("/api/v1/investigations/{investigation_id}/graph")
def versioned_get_graph(investigation_id: str):
    report = get_investigation(investigation_id)
    return {"success": True, "data": report.get("context_graph", get_graph(investigation_id)), "request_id": str(uuid4())}


@app.get("/api/v1/investigations/{investigation_id}/report")
def versioned_get_report(investigation_id: str):
    return {"success": True, "data": get_report(investigation_id), "request_id": str(uuid4())}


# Dynamic Trust & Real-time Action Evaluation
@app.post("/api/v1/dynamic-trust/evaluate")
def evaluate_dynamic_trust(payload: DynamicTrustRequest):
    validate_target(str(payload.url))
    # Reuse the most recent completed report for the URL. Interaction checks can fire
    # repeatedly while a user moves through a form; rebuilding the crawler/ML stack for
    # every focus event creates avoidable latency and load.
    url_str = str(payload.url)
    report = load_latest_report_for_url(url_str) or build_report(url_str)
    trust_prof_dict = report["digital_trust_profile"]

    from .services.trust.engine import DigitalTrustProfile
    profile = DigitalTrustProfile(**trust_prof_dict)

    transition = evaluate_dynamic_interaction(
        current_profile=profile,
        action_type=payload.action_type,
        action_details=payload.action_details,
    )
    return {
        "success": True,
        "data": {
            "transition": asdict(transition),
            "digital_trust_profile": trust_prof_dict,
            "identity_analysis": report["identity_analysis"],
            "safe_route": report.get("safe_route"),
            "requires_intervention": transition.requires_intervention,
            "intervention_modal": {
                "title": "Before you enter credentials" if transition.current_state == "STOP" else "Caution advised",
                "message": transition.reason,
                "recommended_action": transition.recommended_action,
                "safe_route": report.get("safe_route"),
                "actions": ["Go back", "Open trusted site", "Continue anyway", "Why am I seeing this?"],
            },
        },
        "request_id": str(uuid4()),
    }


# Research & Academic Ablation Study Experiments (Section 17)
@app.get("/api/v1/research/experiments")
def get_multimodal_experiments(force_rerun: bool = False):
    """
    Returns empirical evaluation results across Experiments A to E:
    Exp A (URL only), Exp B (URL + Domain), Exp C (URL + Domain + Web),
    Exp D (URL + Domain + Web + Behavior), Exp E (Full M-PHISH).
    Evaluates: Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC, FPR, FNR, Brier score, Latency.
    """
    experiments = run_multimodal_experiments(force_rerun=force_rerun)
    return {
        "success": True,
        "data": {
            "research_question": "Can a multimodal digital trust assessment approach provide more useful and interpretable protection against modern web-based deception than conventional URL-only phishing detection?",
            "experiments": experiments,
            "primary_model": "Calibrated XGBoost (Platt Scaling)",
            "benchmark_dataset_samples": 1200,
            "dataset_provenance": "synthetic-development-benchmark; not a substitute for an independently sourced phishing corpus",
            "evaluation_scope": "development / reproducibility benchmark",
            "evaluated_at": now(),
        },
        "request_id": str(uuid4()),
    }


# Demo Scenarios Catalog (Section 34)
@app.get("/api/v1/demo/scenarios")
def get_demo_scenarios():
    """Return verified safe local demo scenarios for presentation & walkthroughs."""
    scenarios = [
        {
            "id": "scenario-1-safe",
            "title": "Scenario 1: Normal Website",
            "url": "http://m-phish.local/simple-site.html",
            "expected_state": "TRUSTED",
            "description": "Standard legitimate portal with coherent structure, HTTPS, and zero credential harvesting indicators.",
        },
        {
            "id": "scenario-2-fake-login",
            "title": "Scenario 2: Fake Login & Credential Harvesting",
            "url": "http://m-phish.local/suspicious-login.html",
            "expected_state": "STOP",
            "description": "Simulates credential theft where a password input submits directly to an external, unrelated collector domain.",
        },
        {
            "id": "scenario-3-identity-mismatch",
            "title": "Scenario 3: Identity Mismatch & Impersonation",
            "url": "http://m-phish.local/identity-mismatch.html",
            "expected_state": "STOP",
            "description": "Page claims to represent Google Account Login but is hosted on an unverified domain with cross-origin collection.",
            "safe_route": "https://accounts.google.com",
        },
        {
            "id": "scenario-4-synthetic-content",
            "title": "Scenario 4: AI-Assisted / Synthetic Web Content",
            "url": "http://m-phish.local/synthetic-content.html",
            "expected_state": "CAUTION",
            "description": "Identifies automated website construction indicators and generic AI discourse markers without false malicious labeling.",
        },
        {
            "id": "scenario-5-privacy-heavy",
            "title": "Scenario 5: Privacy-Heavy Harvesting Form",
            "url": "http://m-phish.local/privacy-heavy.html",
            "expected_state": "STOP",
            "description": "Form asks for 8 sensitive fields including Phone, Address, Government ID/Aadhaar, Bank details, PIN, and OTP.",
        },
        {
            "id": "scenario-6-download-risk",
            "title": "Scenario 6: Risky Executable Download",
            "url": "http://m-phish.local/download-risk.html",
            "expected_state": "STOP",
            "description": "Simulates browser security scare attempting to prompt a direct .exe executable download from an untrusted source.",
        },
    ]
    return {"success": True, "data": scenarios, "request_id": str(uuid4())}
