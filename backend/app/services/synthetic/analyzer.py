from dataclasses import dataclass, field
import re


@dataclass
class SyntheticWebAnalysis:
    is_synthetic_likely: bool
    confidence: float
    indicators: list[str]
    explanation: str
    context_note: str


# Heuristic patterns for automated site generation, generic AI boilerplates, and template repetitive structures
SYNTHETIC_PATTERNS = [
    (
        "Generic AI-assist discourse markers",
        [
            r"in this comprehensive guide",
            r"delve into the world of",
            r"it is important to remember that",
            r"in summary, whether you are looking for",
            r"testament to the power of",
            r"revolutionize the way we",
            r"seamlessly integrate",
            r"as an ai language model",
        ],
        0.35,
    ),
    (
        "Automated placeholder or boilerplate tokens",
        [
            r"lorem ipsum",
            r"\[insert company name\]",
            r"\[your brand here\]",
            r"sample description text for demonstration",
            r"designed by generic theme generator",
        ],
        0.40,
    ),
    (
        "Repetitive machine-generated claim headers",
        [
            r"why choose us\?.*why choose us\?",
            r"best solution for all your.*best solution for all your",
        ],
        0.25,
    ),
    (
        "High generic buzzword density without specific organization registration",
        [
            r"cutting-edge state-of-the-art solution",
            r"ultimate premier trusted platform for all your needs",
        ],
        0.20,
    ),
]


def analyze_synthetic_content(html_sample: str = "", page_data: dict | None = None) -> SyntheticWebAnalysis:
    """
    Identify signals associated with AI-assisted or automatically generated content.
    Crucial: AI-assisted creation is presented strictly as a contextual characteristic,
    NOT as proof of malicious intent.
    """
    text = (html_sample or "").lower()
    indicators = []
    accumulated_confidence = 0.0

    # Scan pattern groups
    for label, patterns, weight in SYNTHETIC_PATTERNS:
        matches = [p for p in patterns if re.search(p, text)]
        if matches:
            indicators.append(f"{label} (e.g., '{matches[0]}')")
            accumulated_confidence += weight

    # Check for empty or near-empty pages with generic title
    title = (page_data or {}).get("title", "").lower()
    if title in ("home", "index", "welcome to our website", "new site"):
        indicators.append("Default scaffold page title")
        accumulated_confidence += 0.15

    confidence = round(min(0.95, accumulated_confidence), 2)
    is_likely = confidence >= 0.35

    if is_likely:
        explanation = (
            "This website contains linguistic patterns and structural characteristics commonly "
            "associated with automatically generated, heavily templated, or AI-assisted content."
        )
    else:
        explanation = "No strong indicators of automated or synthetic content generation were observed."

    context_note = (
        "AI-assisted website creation is widely used for legitimate development and content publishing. "
        "These indicators serve as contextual signals and do not by themselves imply malicious intent."
    )

    return SyntheticWebAnalysis(
        is_synthetic_likely=is_likely,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        context_note=context_note,
    )

