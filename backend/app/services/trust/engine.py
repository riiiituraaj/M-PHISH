"""Deterministic policy v2. Scores are warning indicators, not safety probabilities."""

from dataclasses import dataclass, field
from typing import Literal

from ..observations import destination_relationship, page_available

TrustState = Literal[
    "UNKNOWN", "NO_SIGNIFICANT_RISK_OBSERVED", "TRUSTED", "CAUTION", "HIGH_RISK", "STOP"
]


@dataclass
class WebsiteAuthenticity:
    identity_score: int | None
    content_score: int | None
    behavior_score: int | None
    consistency_score: int | None
    overall_score: int | None
    level: str
    explanation: str
    availability: str = "partial"


@dataclass
class DigitalTrustProfile:
    identity_trust: int | None
    security_trust: int | None
    content_trust: int | None
    interaction_trust: int | None
    privacy_trust: int | None
    behavioral_trust: int | None
    authenticity: int | None
    overall_trust: int | None
    trust_state: TrustState
    state_reason: str
    coverage: float = 0.0
    decision_evidence_ids: list[str] = field(default_factory=list)
    policy_version: str = "evidence-policy-v2"


@dataclass
class DynamicTrustTransition:
    previous_state: TrustState
    current_state: TrustState
    trigger_event: str
    reason: str
    requires_intervention: bool
    recommended_action: str
    observation_source: str = "client_reported"


def _external_credentials(page: dict) -> bool:
    relation = page.get("destination_relationship")
    return bool(
        page.get("password_inputs", 0)
        and (relation == "unrelated" or (relation is None and page.get("external_form_action")))
    )


def compute_authenticity(
    identity_consistency: str, domain_data: dict, page_data: dict, synthetic_data: dict
) -> WebsiteAuthenticity:
    available = page_available(page_data)
    identity = 20 if identity_consistency == "LOW" else None
    behavior = 15 if _external_credentials(page_data) else None
    concerns = identity is not None or behavior is not None
    return WebsiteAuthenticity(
        identity,
        None,
        behavior,
        identity,
        min([v for v in (identity, behavior) if v is not None], default=None),
        "CONCERN_OBSERVED" if concerns else "INSUFFICIENT_EVIDENCE",
        "Observed identity or submission concerns warrant review; scores are rule indicators, not probabilities."
        if concerns
        else "Authenticity has not been established. Completed checks cannot certify ownership or intent.",
        "partial" if available else "unavailable",
    )


def compute_digital_trust_profile(
    url_features: dict,
    domain_data: dict,
    page_data: dict,
    authenticity: WebsiteAuthenticity,
    privacy_risk_score: int | None,
    calibrated_ml_prob: float | None,
    evidence: list[dict],
    model_threshold: float | None = None,
) -> DigitalTrustProfile:
    observed = page_available(page_data)
    dns_observed = bool(domain_data.get("a_records") or domain_data.get("aaaa_records"))
    tls_observed = domain_data.get("tls", {}).get("available") is True
    coverage = round((1 + observed + dns_observed + tls_observed) / 4, 2)
    danger = _external_credentials(page_data)
    mismatch = authenticity.identity_score is not None and authenticity.identity_score <= 20
    severe = [
        e
        for e in evidence
        if e.get("severity") in {"HIGH", "CRITICAL"} and e.get("weight", 0) >= 20
    ]
    warning_ids = [e.get("id", "") for e in severe if e.get("id")]
    state: TrustState = "UNKNOWN"
    reason = "Insufficient observations to assess this page. Missing information does not establish safety."
    overall = None
    if danger:
        state, overall = "STOP", 15
        reason = "An observed password form targets an unrelated destination. Review that destination before submitting."
    elif mismatch:
        state, overall = "STOP", 20
        reason = "Authentication branding conflicts with the catalogued service domain."
    elif severe:
        state, overall = "HIGH_RISK", 30
        reason = "Completed checks produced a high-severity warning even though other observations may be unavailable."
    elif (
        calibrated_ml_prob is not None
        and model_threshold is not None
        and calibrated_ml_prob >= model_threshold
    ):
        state, overall = "HIGH_RISK", 30
        reason = "The configured validated model exceeded its warning threshold; review the report scope and limitations."
    elif (
        page_data.get("availability") == "available"
        and dns_observed
        and (tls_observed or domain_data.get("tls", {}).get("reason") == "http_transport")
    ):
        state = "CAUTION" if page_data.get("urgency_text") else "NO_SIGNIFICANT_RISK_OBSERVED"
        reason = "No significant risk observed in the checks completed. This does not certify the page or its owner."
    return DigitalTrustProfile(
        authenticity.identity_score,
        None,
        None,
        15 if danger else None,
        None,
        authenticity.behavior_score,
        authenticity.overall_score,
        overall,
        state,
        reason,
        coverage,
        warning_ids,
    )


def evaluate_dynamic_interaction(
    current_profile: DigitalTrustProfile,
    action_type: str,
    action_details: dict | None = None,
) -> DynamicTrustTransition:
    details = action_details or {}
    state = current_profile.trust_state
    reason = current_profile.state_reason
    intervene = state in {"STOP", "HIGH_RISK"}
    action = "Review the destination before sharing sensitive information."
    source = str(details.get("page_url") or details.get("url") or "")
    destination = str(
        details.get("form_action")
        or details.get("form_action_url")
        or details.get("destination")
        or ""
    )
    relation = (
        destination_relationship(source, destination) if source and destination else "unknown"
    )
    sensitive = action_type in {
        "password_focused",
        "otp_focused",
        "banking_focused",
        "card_focused",
    }
    sensitive = sensitive or (
        action_type in {"form_submit", "form_focused"}
        and bool(set(details.get("field_categories", [])) & {"password", "otp", "card", "banking"})
    )
    if sensitive and relation == "unrelated":
        state, intervene = "STOP", True
        reason = "The browser reports a sensitive form submitting to an unrelated destination. This observation has not been independently verified."
        action = "Pause and verify the destination before submitting."
    elif action_type == "download_attempt" and details.get("is_executable"):
        state, intervene = "CAUTION", True
        reason = "The browser reports a download whose file extension can execute code. Its contents have not been scanned."
        action = "Continue only if you intended to download it and recognize the source."
    elif sensitive and not intervene:
        state = "UNKNOWN" if current_profile.trust_state == "UNKNOWN" else "CAUTION"
        reason = (
            "Sensitive input was reported. A field type alone does not establish credential theft."
        )
    return DynamicTrustTransition(
        current_profile.trust_state, state, action_type, reason, intervene, action
    )
