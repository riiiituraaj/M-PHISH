import re
from dataclasses import dataclass

from ..observations import page_available


@dataclass
class SyntheticWebAnalysis:
    is_synthetic_likely: bool
    confidence: float | None
    indicators: list[str]
    explanation: str
    context_note: str
    availability: str = "available"
    indicator_type: str = "templated_language"
    confidence_semantics: str = "heuristic pattern strength; not an authorship probability"
    authorship: str = "not_determined"


PATTERNS = {
    "Placeholder text": [
        r"\blorem ipsum\b",
        r"\[insert company name\]",
        r"\[your brand here\]",
    ],
    "Generic promotional phrases": [
        r"\bin this comprehensive guide\b",
        r"\bdelve into the world of\b",
        r"\bseamlessly integrate\b",
        r"\brevolutionize the way we\b",
    ],
    "Repeated promotional headings": [r"why choose us\?.{0,3000}why choose us\?"],
}


def analyze_synthetic_content(
    html_sample: str = "", page_data: dict | None = None
) -> SyntheticWebAnalysis:
    available = bool(html_sample) or page_available(page_data or {})
    text = (html_sample or (page_data or {}).get("text_sample", ""))[:250000].lower()
    indicators = [
        name
        for name, patterns in PATTERNS.items()
        if any(re.search(p, text, re.DOTALL) for p in patterns)
    ]
    return SyntheticWebAnalysis(
        bool(indicators),
        min(0.75, 0.25 * len(indicators)) if available else None,
        indicators,
        "Templated language patterns were observed."
        if indicators
        else "No listed patterns observed in the inspected text."
        if available
        else "Text unavailable for pattern inspection.",
        "These weak indicators do not determine AI authorship, authenticity, or malicious intent and do not increase risk scores.",
        "available" if available else "unavailable",
    )
