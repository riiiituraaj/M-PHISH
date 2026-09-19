from dataclasses import dataclass, asdict
from typing import Literal

TrustState = Literal["TRUSTED", "CAUTION", "HIGH_RISK", "STOP"]


@dataclass
class WebsiteAuthenticity:
    identity_score: int       # 0 - 100
    content_score: int        # 0 - 100
    behavior_score: int       # 0 - 100
    consistency_score: int    # 0 - 100
    overall_score: int        # 0 - 100
    level: str                # HIGH, MODERATE, LOW
    explanation: str          # Evidence-backed disclaimer


@dataclass
class DigitalTrustProfile:
    identity_trust: int       # 0 - 100
    security_trust: int       # 0 - 100
    content_trust: int        # 0 - 100
    interaction_trust: int    # 0 - 100
    privacy_trust: int        # 0 - 100
    behavioral_trust: int     # 0 - 100
    authenticity: int         # 0 - 100
    overall_trust: int        # 0 - 100
    trust_state: TrustState   # TRUSTED, CAUTION, HIGH_RISK, STOP
    state_reason: str         # Clear human reason why this state was assigned


@dataclass
class DynamicTrustTransition:
    previous_state: TrustState
    current_state: TrustState
    trigger_event: str
    reason: str
    requires_intervention: bool
    recommended_action: str


def compute_authenticity(
    identity_consistency: str,
    domain_data: dict,
    page_data: dict,
    synthetic_data: dict,
) -> WebsiteAuthenticity:
    """Compute multidimensional website authenticity."""
    # 1. Identity score (alignment between claimed identity and domain)
    if identity_consistency == "HIGH":
        identity_score = 92
    elif identity_consistency == "MEDIUM":
        identity_score = 58
    elif identity_consistency == "LOW":
        identity_score = 22
    else:
        identity_score = 75  # neutral/unclaimed

    # Deductions for suspicious domain signals
    if domain_data.get("tls_mismatch"):
        identity_score = max(10, identity_score - 30)

    # 2. Content score (coherence, lack of generic spam / high synthetic penalties)
    content_score = 85
    if synthetic_data.get("is_synthetic_likely"):
        content_score -= 25
    if page_data.get("urgency_text"):
        content_score -= 20
    content_score = max(15, min(100, content_score))

    # 3. Behavior score (forms, redirects, clean navigation)
    behavior_score = 90
    if page_data.get("external_form_action"):
        behavior_score -= 65
    if page_data.get("redirect_count", 0) > 2:
        behavior_score -= 20
    behavior_score = max(10, min(100, behavior_score))

    # 4. Consistency score (visual/branding vs technical domain)
    consistency_score = 85
    if identity_consistency == "LOW":
        consistency_score -= 50
    elif identity_consistency == "MEDIUM":
        consistency_score -= 20
    if page_data.get("external_form_action") and page_data.get("password_inputs", 0) > 0:
        consistency_score -= 25
    consistency_score = max(10, min(100, consistency_score))

    # Overall authenticity
    overall_score = round(
        identity_score * 0.35 +
        content_score * 0.20 +
        behavior_score * 0.25 +
        consistency_score * 0.20
    )
    overall_score = max(0, min(100, overall_score))

    if overall_score >= 75:
        level = "HIGH AUTHENTICITY"
    elif overall_score >= 45:
        level = "MODERATE AUTHENTICITY"
    else:
        level = "LOW AUTHENTICITY"

    explanation = (
        f"Based on the available evidence, this website demonstrates {level.lower()} "
        f"across its domain identity, content coherence, and technical form destinations."
    )

    return WebsiteAuthenticity(
        identity_score=identity_score,
        content_score=content_score,
        behavior_score=behavior_score,
        consistency_score=consistency_score,
        overall_score=overall_score,
        level=level,
        explanation=explanation,
    )


def compute_digital_trust_profile(
    url_features: dict,
    domain_data: dict,
    page_data: dict,
    authenticity: WebsiteAuthenticity,
    privacy_risk_score: int,
    calibrated_ml_prob: float,
    evidence: list[dict],
) -> DigitalTrustProfile:
    """
    Calculate an explainable, 7-dimensional Digital Trust Profile.
    Each dimension is normalized between 0 and 100 (100 = maximum trust).
    """
    # 1. Identity Trust
    id_trust = authenticity.identity_score
    if url_features.get("ip_based_url"):
        id_trust = min(id_trust, 25)

    # 2. Security Trust (Transport & standard network security)
    sec_trust = 90
    if not url_features.get("https"):
        sec_trust -= 45
    if url_features.get("unusual_port"):
        sec_trust -= 30
    tls = domain_data.get("tls", {})
    if tls and not tls.get("available") and url_features.get("https"):
        sec_trust -= 35
    sec_trust = max(10, min(100, sec_trust))

    # 3. Content Trust
    cnt_trust = authenticity.content_score

    # 4. Interaction Trust (How safe is it to interact with fields?)
    has_pwd = page_data.get("password_inputs", 0) > 0
    ext_action = page_data.get("external_form_action", False)
    if ext_action and has_pwd:
        int_trust = 15
    elif ext_action:
        int_trust = 35
    elif has_pwd and id_trust < 50:
        int_trust = 30
    elif has_pwd:
        int_trust = 80
    else:
        int_trust = 95

    # 5. Privacy Trust (Derived from user data collection burden)
    priv_trust = max(15, 100 - privacy_risk_score)

    # 6. Behavioral Trust (Clean network / redirection behavior)
    beh_trust = authenticity.behavior_score

    # 7. Authenticity Composite
    auth_trust = authenticity.overall_score

    # Overall Trust Score (0 - 100)
    # Balanced blend: 25% Identity, 20% Security, 20% Interaction, 15% Behavioral, 10% Privacy, 10% Authenticity
    raw_overall = (
        id_trust * 0.25 +
        sec_trust * 0.20 +
        int_trust * 0.20 +
        beh_trust * 0.15 +
        priv_trust * 0.10 +
        auth_trust * 0.10
    )

    # Strong penalty if ML detects high calibrated phishing probability
    if calibrated_ml_prob >= 0.70:
        raw_overall = min(raw_overall, 22.0)
    elif calibrated_ml_prob >= 0.45:
        raw_overall = min(raw_overall, 48.0)

    overall_trust = round(max(0, min(100, raw_overall)))

    # Determine state and plain-language reason
    if ext_action and has_pwd:
        state = "STOP"
        reason = "A password input sends submitted information to an external, unrelated website address."
    elif overall_trust < 30 or calibrated_ml_prob >= 0.75:
        state = "STOP"
        reason = "Multiple high-severity risk signals indicate this page presents a severe digital safety hazard."
    elif overall_trust < 55 or has_pwd and id_trust < 50:
        state = "HIGH_RISK"
        reason = "This website presents sensitive interaction requirements without verifiable identity consistency."
    elif overall_trust < 80:
        state = "CAUTION"
        reason = "Some aspects of this website warrant review before sharing personal details."
    else:
        state = "TRUSTED"
        reason = "Observed website identity, security posture, and behavior appear consistent and trustworthy."

    return DigitalTrustProfile(
        identity_trust=id_trust,
        security_trust=sec_trust,
        content_trust=cnt_trust,
        interaction_trust=int_trust,
        privacy_trust=priv_trust,
        behavioral_trust=beh_trust,
        authenticity=auth_trust,
        overall_trust=overall_trust,
        trust_state=state,
        state_reason=reason,
    )


def evaluate_dynamic_interaction(
    current_profile: DigitalTrustProfile,
    action_type: str,  # e.g., 'page_loaded', 'form_focused', 'password_focused', 'payment_focused', 'download_attempt'
    action_details: dict | None = None,
) -> DynamicTrustTransition:
    """
    Evaluate user interaction step and dynamically adjust trust state:
    Website opened -> LOW CONCERN / TRUSTED
    Login form appears -> CAUTION
    Password field active -> HIGH RISK
    External destination detected -> STOP
    """
    details = action_details or {}
    prev = current_profile.trust_state
    curr = prev
    reason = current_profile.state_reason
    intervene = False
    action = "Continue normally."

    if action_type in ("password_focused", "otp_focused", "banking_focused"):
        if current_profile.overall_trust < 55 or current_profile.interaction_trust < 50:
            curr = "STOP"
            reason = "You are entering sensitive credentials on a page whose identity could not be verified."
            intervene = True
            action = "We strongly recommend not entering your credentials here. Open the official service directly."
        elif current_profile.overall_trust < 80:
            curr = "HIGH_RISK"
            reason = "Sensitive credentials requested on an unfamiliar page. Confirm the web address carefully."
            intervene = True
            action = "Verify the website address before continuing."
        else:
            curr = "CAUTION"
            reason = "Sensitive credentials field active. Website appears consistent."
            intervene = False
            action = "Proceed with awareness."

    elif action_type in ("card_focused", "payment_focused"):
        if current_profile.overall_trust < 60:
            curr = "STOP"
            reason = "Payment information requested by an unverified website."
            intervene = True
            action = "Do not enter card or payment details on this website."
        else:
            curr = "CAUTION"
            reason = "Payment input detected. Ensure you recognize the payment gateway."
            intervene = False
            action = "Check checkout details before paying."

    elif action_type == "download_attempt":
        if current_profile.overall_trust < 60 or details.get("is_executable"):
            curr = "STOP"
            reason = "This website is attempting to download an executable file while having low trust indicators."
            intervene = True
            action = "Cancel this download. Only download executables from verified official sources."
        else:
            curr = "CAUTION"
            reason = "File download initiated."
            intervene = False
            action = "Confirm file type before opening."

    elif action_type == "form_focused":
        if current_profile.overall_trust < 50:
            curr = "HIGH_RISK"
            reason = "Web form detected on a low-trust domain."
            intervene = True
            action = "Check what information is being asked before typing."

    return DynamicTrustTransition(
        previous_state=prev,
        current_state=curr,
        trigger_event=action_type,
        reason=reason,
        requires_intervention=intervene,
        recommended_action=action,
    )

