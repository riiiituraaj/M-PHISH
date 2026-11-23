import re
from dataclasses import dataclass, field

from ..observations import page_available


@dataclass
class DeceptiveClaimAnalysis:
    claimed_category: str
    asserted_claim: str
    observed_characteristics: str
    claim_consistency: str
    explanation: str
    availability: str = "available"
    pressure_patterns: list[str] = field(default_factory=list)


PATTERNS = {
    "Account suspension pressure": r"account.{0,35}(suspend|closed|deactivat)",
    "Urgent action request": r"(act now|immediate action|urgent verification|within 24 hours)",
    "Guaranteed reward claim": r"(guaranteed.{0,25}(profit|return|reward)|you have won)",
    "Upfront release fee": r"(pay.{0,35}(release|claim).{0,35}(prize|funds)|processing fee.{0,30}reward)",
}


def analyze_deceptive_claims(
    url: str, page_data: dict, html_sample: str = ""
) -> DeceptiveClaimAnalysis:
    available = bool(html_sample) or page_available(page_data)
    text = (
        str(page_data.get("title", ""))
        + " "
        + html_sample
        + " "
        + str(page_data.get("text_sample", ""))
    )[:250000].lower()
    patterns = [name for name, pattern in PATTERNS.items() if re.search(pattern, text)]
    return DeceptiveClaimAnalysis(
        "Observed pressure/claim language" if patterns else "No supported claim pattern",
        ", ".join(patterns) or "No factual assertion was verified.",
        f"{len(patterns)} listed language patterns observed."
        if available
        else "Text observation unavailable.",
        "UNVERIFIED",
        "Pattern matching does not fact-check the statements or establish fraud. Domain suffixes do not establish institutional identity.",
        "available" if available else "unavailable",
        patterns,
    )
