from dataclasses import dataclass, field


WEIGHTS = {
    "URL": 0.15,
    "DOMAIN": 0.10,
    "CONTENT": 0.20,
    "BEHAVIOR": 0.20,
    "IDENTITY": 0.15,
    "PRIVACY": 0.10,
    "CONTEXT": 0.10,
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    confidence: float
    top_factors: list[str]
    evidence_score: int = 0
    ml_contribution: int = 0
    attribution: dict[str, int] = field(default_factory=dict)


def assess(
    evidence: list[dict],
    calibrated_ml_prob: float | None = None,
) -> RiskAssessment:
    """
    Evidence Fusion Engine:
    Combines deterministic category evidence weights with calibrated ML probability.
    The category breakdown is an evidence attribution, not a claim of model-specific feature importance.
    """
    category_totals = {category: 0.0 for category in WEIGHTS}
    attribution = {}

    for item in evidence:
        cat = item.get("category", "URL").upper()
        weight = float(item.get("weight", 0))
        if cat in category_totals:
            category_totals[cat] = min(100.0, category_totals[cat] + weight / max(WEIGHTS[cat], 0.01))

    # Base deterministic evidence score (0 - 100)
    evidence_score = round(
        sum(min(100.0, val) * WEIGHTS[cat] for cat, val in category_totals.items())
    )

    for cat, val in category_totals.items():
        attribution[cat] = round(min(100.0, val) * WEIGHTS[cat])

    # Calibrated ML contribution
    if calibrated_ml_prob is not None:
        ml_score = round(calibrated_ml_prob * 100)
        # Fused score: 75% evidence + 25% calibrated ML probability
        fused = round(evidence_score * 0.75 + ml_score * 0.25)
        # If severe credential theft indicators are present, maintain floor
        if evidence_score >= 70:
            fused = max(fused, evidence_score)
        score = max(0, min(100, fused))
        ml_contrib = round(ml_score * 0.25)
    else:
        score = min(100, evidence_score)
        ml_contrib = 0

    level = (
        "CRITICAL" if score >= 75
        else "HIGH" if score >= 50
        else "MEDIUM" if score >= 25
        else "LOW"
    )

    confidence = (
        round(sum(item.get("confidence", 0) for item in evidence) / len(evidence), 2)
        if evidence else 0.25
    )

    sorted_factors = [
        item["title"]
        for item in sorted(evidence, key=lambda x: x.get("weight", 0), reverse=True)
    ][:5]

    return RiskAssessment(
        score=score,
        level=level,
        confidence=confidence,
        top_factors=sorted_factors,
        evidence_score=evidence_score,
        ml_contribution=ml_contrib,
        attribution=attribution,
    )
