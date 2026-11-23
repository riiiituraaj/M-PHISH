"""Risk policy v2: independent warnings, explicit missingness, no assurance probability."""

from dataclasses import dataclass, field

WEIGHTS = {
    "URL": 0.15,
    "DOMAIN": 0.1,
    "CONTENT": 0.2,
    "BEHAVIOR": 0.2,
    "IDENTITY": 0.15,
    "PRIVACY": 0.1,
    "CONTEXT": 0.1,
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    confidence: float | None
    top_factors: list[str]
    evidence_score: int = 0
    ml_contribution: int = 0
    attribution: dict[str, int] = field(default_factory=dict)
    decision_evidence_ids: list[str] = field(default_factory=list)
    coverage: float | None = None
    policy_version: str = "evidence-policy-v2"
    confidence_semantics: str = "rule reliability; not calibrated phishing probability"


def assess(
    evidence: list[dict],
    calibrated_ml_prob: float | None = None,
    coverage: float | None = None,
    model_threshold: float | None = None,
) -> RiskAssessment:
    # One strongest observation per category prevents correlated, repeated signals
    # from being counted repeatedly. Context combinations do not add to source facts.
    strongest = {}
    for item in evidence:
        category = str(item.get("category", "")).upper()
        source = str(item.get("source", ""))
        if (
            category == "CONTEXT"
            or source == "synthetic_analyzer"
            or item.get("availability") == "unavailable"
        ):
            continue
        if category == "PRIVACY" and not item.get("destination_concern"):
            continue
        if category == "CONTENT" and item.get("severity") not in {"HIGH", "CRITICAL"}:
            continue
        if category not in WEIGHTS or item.get("weight", 0) <= 0:
            continue
        if category not in strongest or item.get("weight", 0) > strongest[category].get(
            "weight", 0
        ):
            strongest[category] = item
    attribution = {
        category: min(40, max(0, int(item.get("weight", 0))))
        for category, item in strongest.items()
    }
    evidence_score = min(100, sum(attribution.values()))
    severe = [
        item
        for item in strongest.values()
        if item.get("severity") in {"HIGH", "CRITICAL"} and item.get("weight", 0) >= 20
    ]
    if severe:
        evidence_score = max(
            evidence_score,
            75 if any(i.get("severity") == "CRITICAL" for i in severe) else 50,
        )
    score = evidence_score
    ml_contribution = 0
    # Do not add correlated model evidence to rules; a model can only raise the warning floor.
    if calibrated_ml_prob is not None and model_threshold is not None:
        model_floor = 50 if calibrated_ml_prob >= model_threshold else 0
        ml_contribution = max(0, model_floor - score)
        score = max(score, model_floor)
    level = (
        "CRITICAL"
        if score >= 75
        else "HIGH"
        if score >= 50
        else "MEDIUM"
        if score >= 25
        else "LOW"
        if coverage is not None and coverage >= 1
        else "UNKNOWN"
    )
    selected = sorted(strongest.values(), key=lambda item: item.get("weight", 0), reverse=True)
    reliability = min([float(item.get("confidence", 0)) for item in selected], default=None)
    return RiskAssessment(
        score,
        level,
        reliability,
        [str(item.get("title", "Observed warning")) for item in selected[:5]],
        evidence_score,
        ml_contribution,
        attribution,
        [str(item["id"]) for item in selected if item.get("id")],
        coverage,
    )
