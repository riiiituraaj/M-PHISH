"""Versioned evidence fusion; collection availability is independent from severity."""

import ipaddress
import re
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5

from .core.network import parse_target, redact_url
from .services.campaign.analyzer import analyze_campaign_similarity
from .services.claims.analyzer import analyze_deceptive_claims
from .services.context.engine import build_relationships
from .services.domain.analyzer import analyze as domain_unavailable
from .services.download.analyzer import analyze_download
from .services.identity.analyzer import analyze_identity
from .services.ml.model import get_threat_model
from .services.observations import page_available, registrable_domain
from .services.privacy.analyzer import analyze_privacy
from .services.risk.engine import assess
from .services.synthetic.analyzer import analyze_synthetic_content
from .services.trust.engine import compute_authenticity, compute_digital_trust_profile
from .services.webpage.analyzer import analyze_sync, parse_html, unavailable


def now():
    return datetime.now(UTC).isoformat()


def ev(category, title, description, source, confidence, severity, weight):
    return {
        "id": str(uuid5(NAMESPACE_URL, source + ":" + category + ":" + title)),
        "category": category,
        "title": title,
        "description": description,
        "source": source,
        "confidence": confidence,
        "severity": severity,
        "weight": weight,
        "created_at": now(),
        "observed_at": now(),
        "availability": "available",
        "reliability": "client_reported" if source == "client_reported" else "observed",
        "rule_version": "evidence-policy-v2",
        "redacted_value": None,
        "contribution": {"scale": "rule_weight", "value": weight},
    }


def analyze_url(url):
    parsed, host = parse_target(url)
    try:
        ipaddress.ip_address(host)
        ip_host = True
    except ValueError:
        ip_host = False
    features = {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "subdomain_count": max(0, len(host.split(".")) - len(registrable_domain(host).split("."))),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "special_character_count": len(re.findall(r"[^a-zA-Z0-9./?=_-]", url)),
        "percent_encoded": "%" in url,
        "ip_based_url": ip_host,
        "unusual_port": False,
        "https": parsed.scheme == "https",
        "suspicious_keywords": [
            w
            for w in (
                "login",
                "verify",
                "secure",
                "account",
                "password",
                "wallet",
                "banking",
                "signin",
            )
            if w in host
        ],
    }
    evidence = []
    if ip_host:
        evidence.append(
            ev(
                "URL",
                "IP-based address",
                "This address uses an IP rather than a domain. This is not proof of phishing.",
                "url_analyzer",
                0.95,
                "MEDIUM",
                12,
            )
        )
    if len(features["suspicious_keywords"]) >= 2:
        evidence.append(
            ev(
                "URL",
                "Authentication terms in hostname",
                "Multiple authentication terms warrant checking the intended destination.",
                "url_analyzer",
                0.7,
                "MEDIUM",
                9,
            )
        )
    if parsed.scheme != "https":
        evidence.append(
            ev(
                "DOMAIN",
                "Unencrypted connection",
                "HTTP does not protect data in transit; HTTPS alone would not prove legitimacy.",
                "url_analyzer",
                1.0,
                "MEDIUM",
                12,
            )
        )
    return features, evidence


def quick_check(url):
    url = redact_url(url)
    features, evidence = analyze_url(url)
    score = min(100, sum(item["weight"] for item in evidence))
    warning = bool(evidence)
    return {
        "status": "complete",
        "url": url,
        "hostname": urlsplit(url).hostname,
        "score": score,
        "tier": "MEDIUM" if warning else "UNKNOWN",
        "deep_required": warning,
        "top_reasons": [e["title"] for e in evidence[:3]],
        "features": features,
        "assessment_state": "INSUFFICIENT_EVIDENCE",
        "summary": "URL-only checks cannot establish page safety.",
    }


def build_report(
    url,
    investigation_id=None,
    context=None,
    *,
    fixture_html=None,
    remote=True,
    owner_id=None,
    recent_reports=None,
):
    url = redact_url(url)
    context = context or {}
    features, evidence = analyze_url(url)
    domain = domain_unavailable(url)
    page = (
        analyze_sync(url, visual_consent=context.get("visual_consent", False))
        if remote
        else unavailable("not_requested")
    )
    visual = page.pop(
        "visual_analysis",
        {
            "availability": "unavailable",
            "reason": "collector_unavailable"
            if context.get("visual_consent")
            else "consent_absent",
        },
    )
    raw_html = page.pop("raw_html", "")
    domain = page.pop("domain_analysis", domain)
    if fixture_html is not None:
        raw_html = fixture_html[:1_000_000]
        page = parse_html(url, raw_html, "fixture")
    observation = context.get("observations")
    client_page = None
    if observation and observation.get("consent"):
        # Values, HTML, page text and free-form arbitrary fields are not accepted.
        client_page = {
            k: observation[k]
            for k in (
                "fields",
                "form_actions",
                "password_inputs",
                "forms",
                "frame_coverage",
            )
            if k in observation
        }
        client_page.update(availability="partial", available=True, source="client_reported")
        from .services.observations import destination_relationship

        actions = client_page.get("form_actions", [])
        client_page["form_action_url"] = next(
            (a for a in actions if destination_relationship(url, a) == "unrelated"),
            actions[0] if actions else None,
        )
        if not page_available(page):
            page = client_page
        else:
            # Lower-trust negative observations must never erase collected danger.
            page["client_observations"] = client_page
            if (
                client_page.get("password_inputs")
                and destination_relationship(url, client_page["form_action_url"] or "")
                == "unrelated"
            ):
                evidence.append(
                    ev(
                        "BEHAVIOR",
                        "Browser reports an unrelated sensitive destination",
                        "This client-reported destination has not been independently verified.",
                        "client_reported",
                        0.7,
                        "HIGH",
                        25,
                    )
                )
    identity = analyze_identity(url, page, raw_html)
    page["destination_relationship"] = identity.destination_relationship
    if page.get("password_inputs") and identity.destination_relationship == "unrelated":
        evidence.append(
            ev(
                "BEHAVIOR",
                "Sensitive form has an unrelated destination",
                "A password form destination differs from this site and known identity providers. Verify the destination before submitting.",
                page.get("source", "webpage_analyzer"),
                0.9,
                "CRITICAL",
                40,
            )
        )
    if identity.is_impersonation_suspected:
        evidence.append(
            ev(
                "IDENTITY",
                "Authentication branding and destination mismatch",
                identity.explanation,
                "identity_engine",
                0.85,
                "HIGH",
                25,
            )
        )
    privacy = analyze_privacy(raw_html, page)
    synthetic = analyze_synthetic_content(raw_html, page)
    claims = analyze_deceptive_claims(url, page, raw_html)
    identity_context = context | {
        "brand_name_mismatch": identity.is_impersonation_suspected
        if page_available(page)
        else None,
        "claimed_org_unverified": identity.identity_consistency == "LOW"
        if page_available(page)
        else None,
    }
    prediction = get_threat_model().predict_multimodal(
        features, domain_analysis=domain, page_analysis=page, context=identity_context
    )
    authenticity = compute_authenticity(
        identity.identity_consistency, domain, page, asdict(synthetic)
    )
    profile = compute_digital_trust_profile(
        features,
        domain,
        page,
        authenticity,
        privacy.privacy_risk_score,
        prediction.calibrated_probability,
        evidence,
        model_threshold=prediction.threshold,
    )
    download = analyze_download(url, page, raw_html, overall_trust=profile.overall_trust)
    if download.has_download and download.is_executable_or_script:
        evidence.append(
            ev(
                "BEHAVIOR",
                "Executable or script link observed",
                download.explanation,
                "download_analyzer",
                0.9,
                "HIGH",
                22,
            )
        )
    coverage = (
        1
        + int(bool(domain.get("a_records") or domain.get("aaaa_records")))
        + int(
            bool(
                domain.get("tls", {}).get("available")
                or domain.get("tls", {}).get("reason") == "http_transport"
            )
        )
        + int(page.get("availability") == "available")
    ) / 4
    assessment = assess(
        evidence, prediction.calibrated_probability, coverage, model_threshold=prediction.threshold
    )
    profile.coverage = coverage
    if assessment.level in ("HIGH", "CRITICAL") and profile.trust_state not in (
        "HIGH_RISK",
        "STOP",
    ):
        profile.trust_state = "HIGH_RISK"
    profile.decision_evidence_ids = assessment.decision_evidence_ids
    if assessment.level in ("HIGH", "CRITICAL"):
        summary = "Observed warning signs warrant pausing this interaction."
        why = "; ".join(assessment.top_factors)
        action = "Verify the destination independently before submitting sensitive data or downloading files."
    elif coverage < 1:
        summary = "Insufficient evidence to assess this page fully."
        why = (
            "Some observations are unavailable or limited. Missing checks do not establish safety."
        )
        action = "Check the address and intended recipient before sharing sensitive information."
    else:
        summary = "No significant risk observed in the checks completed."
        why = "These checks cannot establish the site owner, intent, or all dynamic behavior."
        action = "Continue to check recipients before sharing sensitive information."
    created = now()
    page["observed_at"] = created
    limitations = [
        "Advisory assessment, not a safety guarantee or malware scan.",
        "Target paths, query strings and fragments are omitted for privacy; only the origin is inspected.",
        "Client observations are unverified. No entered field values are collected.",
        "Detection performance has not been independently validated.",
    ]
    from .services.ai.grounded import explain

    ai = explain(
        evidence,
        {
            "provider": "fallback",
            "summary": summary,
            "recommended_action": action,
            "what_happened": summary,
            "why_it_matters": why,
            "what_to_do": action,
            "uncertainty": limitations[0],
        },
        consent=context.get("_ai_enabled", False),
    )
    public_context = {k: v for k, v in context.items() if not k.startswith("_")}
    return {
        "id": investigation_id or str(uuid4()),
        "contract_version": "2.0",
        "policy_version": "evidence-policy-v2",
        "url": url,
        "hostname": urlsplit(url).hostname,
        "status": "COMPLETED",
        "risk_score": assessment.score,
        "classification": assessment.level,
        "confidence": assessment.confidence,
        "confidence_semantics": assessment.confidence_semantics,
        "top_factors": assessment.top_factors,
        "assessment_state": "INSUFFICIENT_EVIDENCE" if coverage < 1 else "ASSESSED",
        "coverage": {
            "fraction": coverage,
            "url": "available",
            "domain": domain.get("availability", "unavailable"),
            "page": page.get("availability", "unavailable"),
        },
        "summary": summary,
        "recommendation": action,
        "what_happened": summary,
        "why_it_matters": why,
        "what_to_do": action,
        "ai_report": ai,
        "evidence": evidence,
        "decision_evidence_ids": assessment.decision_evidence_ids,
        "features": features,
        "domain_analysis": domain,
        "page_analysis": page,
        "events": [
            {
                "event_type": "Assessment completed",
                "message": summary,
                "timestamp": created,
            },
            {
                "event_type": "Observation coverage",
                "message": f"Page: {page.get('availability')}; domain: {domain.get('availability')}",
                "timestamp": created,
            },
        ],
        "context_graph": build_relationships(urlsplit(url).hostname or "", page, public_context),
        "context": public_context,
        "created_at": created,
        "completed_at": created,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "digital_trust_profile": asdict(profile),
        "website_authenticity": asdict(authenticity),
        "identity_analysis": asdict(identity),
        "privacy_assessment": asdict(privacy),
        "synthetic_web_analysis": asdict(synthetic),
        "deceptive_claim_analysis": asdict(claims),
        "download_safety": asdict(download),
        "campaign_similarity": asdict(
            analyze_campaign_similarity(
                url, page, features, recent_reports or [], owner_id=owner_id
            )
        ),
        "ml_prediction": asdict(prediction),
        "safe_route": identity.safe_route,
        "limitations": limitations,
        "visual_analysis": visual,
        "trust_before_you_act": {
            "requires_intervention": assessment.level in ("HIGH", "CRITICAL"),
            "banner_title": "Review this interaction",
            "banner_message": summary,
            "recommended_action": action,
            "safe_route": identity.safe_route,
        },
    }
