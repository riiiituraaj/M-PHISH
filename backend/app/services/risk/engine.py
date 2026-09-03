from dataclasses import dataclass


WEIGHTS = {"URL": .15, "DOMAIN": .15, "CONTENT": .25, "BEHAVIOR": .25, "VISUAL": .10, "CONTEXT": .10}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    confidence: float
    top_factors: list[str]


def assess(evidence: list[dict]) -> RiskAssessment:
    category_totals = {category: 0.0 for category in WEIGHTS}
    for item in evidence:
        category_totals[item["category"]] = min(100.0, category_totals[item["category"]] + float(item.get("weight", 0)) / max(WEIGHTS[item["category"]], .01))
    score = round(sum(min(100, value) * WEIGHTS[category] for category, value in category_totals.items()))
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    confidence = round(sum(item.get("confidence", 0) for item in evidence) / len(evidence), 2) if evidence else .25
    return RiskAssessment(score, level, confidence, [item["title"] for item in sorted(evidence, key=lambda x: x.get("weight", 0), reverse=True)[:5]])
