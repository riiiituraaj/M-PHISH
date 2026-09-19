from dataclasses import dataclass
from urllib.parse import urlparse
import re

# Known legitimate service catalog with official primary domains and human brands
KNOWN_SERVICES = [
    {
        "brand": "Google Account",
        "keywords": ["google", "gmail", "youtube", "google drive"],
        "official_domains": ["google.com", "accounts.google.com", "youtube.com", "gmail.com"],
        "safe_route": "https://accounts.google.com",
    },
    {
        "brand": "Microsoft Account",
        "keywords": ["microsoft", "office365", "outlook", "live.com", "onedrive", "azure"],
        "official_domains": ["microsoft.com", "login.microsoftonline.com", "live.com", "outlook.com"],
        "safe_route": "https://login.microsoftonline.com",
    },
    {
        "brand": "Apple ID / iCloud",
        "keywords": ["apple id", "icloud", "apple account"],
        "official_domains": ["apple.com", "appleid.apple.com", "icloud.com"],
        "safe_route": "https://appleid.apple.com",
    },
    {
        "brand": "PayPal",
        "keywords": ["paypal", "paypal balance", "paypal security"],
        "official_domains": ["paypal.com"],
        "safe_route": "https://www.paypal.com/signin",
    },
    {
        "brand": "Amazon",
        "keywords": ["amazon", "amazon prime", "aws"],
        "official_domains": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
        "safe_route": "https://www.amazon.com",
    },
    {
        "brand": "Netflix",
        "keywords": ["netflix", "netflix membership", "netflix streaming"],
        "official_domains": ["netflix.com"],
        "safe_route": "https://www.netflix.com/login",
    },
    {
        "brand": "State Bank of India (SBI)",
        "keywords": ["state bank of india", "sbi online", "onlinesbi", "yono"],
        "official_domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
        "safe_route": "https://www.onlinesbi.sbi",
    },
    {
        "brand": "Chase Bank",
        "keywords": ["chase bank", "chase online", "jpmorgan chase"],
        "official_domains": ["chase.com"],
        "safe_route": "https://www.chase.com",
    },
    {
        "brand": "National Scholarship Portal",
        "keywords": ["scholarship portal", "national scholarship", "student scholarship"],
        "official_domains": ["scholarships.gov.in"],
        "safe_route": "https://scholarships.gov.in",
    },
    {
        "brand": "GitHub",
        "keywords": ["github", "github login"],
        "official_domains": ["github.com"],
        "safe_route": "https://github.com/login",
    },
]


@dataclass
class IdentityAnalysis:
    claimed_service: str
    current_website: str
    credential_destination: str
    identity_consistency: str  # HIGH, MEDIUM, LOW, UNKNOWN
    explanation: str
    safe_route: str | None
    is_impersonation_suspected: bool


def extract_base_domain(host: str) -> str:
    """Extract standard second-level domain (e.g., login.example.com -> example.com)."""
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def analyze_identity(
    url: str,
    page_data: dict,
    html_sample: str = "",
) -> IdentityAnalysis:
    """
    Evaluate:
    1. What does the page claim to be?
    2. What is the current website domain?
    3. Where does submitted information actually appear to go?
    """
    parsed = urlparse(url)
    current_host = (parsed.hostname or "").lower()
    current_base = extract_base_domain(current_host)
    
    title = page_data.get("title", "").lower()
    forms = page_data.get("forms", 0)
    has_password = page_data.get("password_inputs", 0) > 0
    form_action = page_data.get("form_action_url") or ""
    
    # Destination domain
    if form_action and form_action.startswith("http"):
        dest_host = (urlparse(form_action).hostname or "").lower()
    elif page_data.get("external_form_action"):
        dest_host = "external-unrelated-domain.com"
    else:
        dest_host = current_host

    # Search for claimed brand in title, URL, or sample text
    matched_brand = None
    search_corpus = f"{title} {url.lower()} {html_sample.lower()}"
    
    for service in KNOWN_SERVICES:
        for kw in service["keywords"]:
            if kw in search_corpus:
                matched_brand = service
                break
        if matched_brand:
            break

    if matched_brand:
        claimed_service = matched_brand["brand"]
        # Check if current host matches official domains
        is_official = any(
            current_host == d or current_host.endswith(f".{d}")
            for d in matched_brand["official_domains"]
        )

        dest_is_official = any(
            dest_host == d or dest_host.endswith(f".{d}")
            for d in matched_brand["official_domains"]
        )

        if is_official and dest_is_official:
            consistency = "HIGH"
            explanation = (
                f"The website address ({current_host}) and credential submission destination "
                f"match the official verified infrastructure for {claimed_service}."
            )
            safe_route = None
            suspected = False
        else:
            consistency = "LOW"
            explanation = (
                f"This page appears to represent {claimed_service}, but the website address "
                f"({current_host}) does not belong to {claimed_service}."
            )
            if dest_host != current_host:
                explanation += f" Furthermore, credentials appear to be submitted to an external destination ({dest_host})."
            safe_route = matched_brand["safe_route"]
            suspected = True

    else:
        # Generic or independent website
        claimed_service = page_data.get("title") or current_host or "Independent Website"
        if dest_host != current_host and (forms > 0 or has_password):
            consistency = "LOW"
            explanation = (
                f"This website ({current_host}) contains forms that submit your information "
                f"to a different website ({dest_host})."
            )
            suspected = True
            safe_route = None
        else:
            consistency = "HIGH" if (forms == 0 or dest_host == current_host) else "MEDIUM"
            explanation = (
                f"Based on available evidence, the website address ({current_host}) "
                f"is consistent with its internal resource destinations."
            )
            suspected = False
            safe_route = None

    return IdentityAnalysis(
        claimed_service=claimed_service,
        current_website=current_host,
        credential_destination=dest_host,
        identity_consistency=consistency,
        explanation=explanation,
        safe_route=safe_route,
        is_impersonation_suspected=suspected,
    )

