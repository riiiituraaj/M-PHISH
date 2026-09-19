from dataclasses import dataclass
from urllib.parse import urlparse
import re


@dataclass
class DeceptiveClaimAnalysis:
    claimed_category: str
    asserted_claim: str
    observed_characteristics: str
    claim_consistency: str  # HIGH, MEDIUM, LOW, UNVERIFIED
    explanation: str


CLAIM_CATEGORIES = [
    (
        "Banking / Financial Service",
        [r"bank", r"credit union", r"wire transfer", r"netbanking", r"account balance", r"card services"],
        [r"\.bank$", r"\.com$", r"\.co\.in$", r"\.co\.uk$"],
    ),
    (
        "Government / Official Portal",
        [r"government", r"ministry", r"official portal", r"tax refund", r"passport service", r"national portal"],
        [r"\.gov$", r"\.gov\.[a-z]{2}$", r"\.nic\.in$"],
    ),
    (
        "University / Student Scholarship",
        [r"university", r"scholarship portal", r"student aid", r"admissions", r"exam results", r"campus portal"],
        [r"\.edu$", r"\.ac\.[a-z]{2}$", r"\.edu\.[a-z]{2}$"],
    ),
    (
        "Parcel Delivery / Courier",
        [r"parcel delivery", r"courier service", r"package tracking", r"reschedule delivery", r"customs clearance"],
        [r"fedex\.com", r"dhl\.com", r"ups\.com", r"usps\.com", r"indiapost\.gov\.in"],
    ),
    (
        "Tech Support / Account Security",
        [r"security verification", r"account suspended", r"urgent security notice", r"support desk", r"customer care"],
        [],
    ),
]


def analyze_deceptive_claims(
    url: str,
    page_data: dict,
    html_sample: str = "",
) -> DeceptiveClaimAnalysis:
    """Compare what the page asserts to be against observable domain evidence."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    text = f"{url.lower()} {page_data.get('title', '').lower()} {html_sample.lower()}"
    
    detected_cat = "General Web Presence"
    asserted_claim = page_data.get("title") or host or "Independent Service"
    consistency = "UNVERIFIED"

    for cat_name, keywords, official_patterns in CLAIM_CATEGORIES:
        if any(re.search(kw, text) for kw in keywords):
            detected_cat = cat_name
            asserted_claim = f"Appears to represent or claim association with: {cat_name}"
            
            # Check domain against official patterns
            if official_patterns:
                matches_tld = any(re.search(pat, host) for pat in official_patterns)
                if matches_tld:
                    consistency = "HIGH"
                else:
                    consistency = "LOW"
            else:
                # Tech support / general claims
                if page_data.get("password_inputs", 0) > 0 and page_data.get("external_form_action"):
                    consistency = "LOW"
                else:
                    consistency = "MEDIUM"
            break

    if consistency == "LOW":
        explanation = (
            f"The website asserts characteristics of a {detected_cat}, but we could not establish "
            f"consistency between that claim and the observed domain address ({host})."
        )
        observed = f"Domain '{host}' lacks the expected institutional registration or domain hierarchy for {detected_cat}."
    elif consistency == "HIGH":
        explanation = (
            f"Observed domain architecture is consistent with legitimate {detected_cat} representations."
        )
        observed = f"Domain '{host}' matches expected institutional registration patterns."
    else:
        explanation = (
            f"General claims detected without definitive official affiliation markers."
        )
        observed = f"Domain '{host}' presents standard generic web content."

    return DeceptiveClaimAnalysis(
        claimed_category=detected_cat,
        asserted_claim=asserted_claim,
        observed_characteristics=observed,
        claim_consistency=consistency,
        explanation=explanation,
    )

