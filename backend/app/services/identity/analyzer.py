import re
from dataclasses import dataclass
from html.parser import HTMLParser

from ..observations import (
    destination_relationship,
    host_matches,
    normalized_host,
    page_available,
    registrable_domain,
)

CATALOG_VERSION = "2026-11-03.1"
CATALOG_SOURCES = {
    "Google Account": "https://developers.google.com/identity/protocols/oauth2/web-server",
    "Microsoft Account": "https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc",
}

# Known legitimate service catalog with official primary domains and human brands
KNOWN_SERVICES = [
    {
        "brand": "Google Account",
        "keywords": ["google", "gmail", "youtube", "google drive"],
        "official_domains": [
            "google.com",
            "accounts.google.com",
            "youtube.com",
            "gmail.com",
        ],
        "safe_route": "https://accounts.google.com",
    },
    {
        "brand": "Microsoft Account",
        "keywords": [
            "microsoft",
            "office365",
            "outlook",
            "live.com",
            "onedrive",
            "azure",
        ],
        "official_domains": [
            "microsoft.com",
            "login.microsoftonline.com",
            "live.com",
            "outlook.com",
        ],
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
        "official_domains": [
            "amazon.com",
            "amazon.in",
            "amazon.co.uk",
            "aws.amazon.com",
        ],
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
        "keywords": [
            "scholarship portal",
            "national scholarship",
            "student scholarship",
        ],
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
    availability: str = "available"
    destination_relationship: str = "unknown"
    catalog_version: str = CATALOG_VERSION
    catalog_source: str | None = None


def extract_base_domain(host: str) -> str:
    """Return a registrable domain using the bundled Public Suffix List."""
    return registrable_domain(host)


class _BrandText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"h1", "h2", "title", "button"}:
            self.depth += 1

    def handle_endtag(self, tag):
        if tag in {"h1", "h2", "title", "button"}:
            self.depth = max(0, self.depth - 1)

    def handle_data(self, data):
        if self.depth:
            self.parts.append(data[:500])


def analyze_identity(url: str, page_data: dict, html_sample: str = "") -> IdentityAnalysis:
    host = normalized_host(url)
    observed = page_available(page_data) or bool(html_sample)
    action = page_data.get("form_action_url") or ""
    relation = destination_relationship(url, action) if observed else "unknown"
    dest_host = (
        normalized_host(__import__("urllib.parse", fromlist=["urljoin"]).urljoin(url, action))
        if observed
        else ""
    )
    has_password = (page_data.get("password_inputs") or 0) > 0
    parser = _BrandText()
    parser.feed((html_sample or "")[:250000])
    purpose = " ".join([str(page_data.get("title", ""))] + parser.parts).lower()
    # Body text and URL mentions alone do not establish an identity assertion.
    brand = next(
        (
            service
            for service in KNOWN_SERVICES
            if any(
                re.search(r"\b" + re.escape(keyword) + r"\b", purpose)
                for keyword in service["keywords"]
            )
        ),
        None,
    )
    claimed = brand["brand"] if brand else page_data.get("title") or host
    source = CATALOG_SOURCES.get(claimed)
    official = bool(brand and any(host_matches(host, d) for d in brand["official_domains"]))
    authentication_claim = has_password and bool(
        re.search(r"sign in|log ?in|account|verify|password", purpose)
    )
    suspected = bool(
        observed
        and brand
        and authentication_claim
        and not official
        and relation not in {"known_identity_provider", "known_payment_provider"}
    )
    if not observed:
        consistency, explanation = (
            "UNKNOWN",
            "Page content was unavailable; no identity claim or destination was evaluated.",
        )
    elif suspected:
        consistency = "LOW"
        explanation = f"An authentication form presents {claimed} branding on {host}, outside the catalogued domains. This is a suspected identity mismatch, not proof of ownership or intent."
    elif official:
        consistency = "HIGH"
        explanation = "The hostname matches a catalogued service domain. This does not certify the page or any transaction."
    elif relation in {"known_identity_provider", "known_payment_provider"}:
        consistency = "MEDIUM"
        explanation = "The form destination matches a known identity/payment provider. Cross-domain submission alone is not evidence of theft; the integration has not been verified."
    else:
        consistency = "UNKNOWN"
        explanation = "No supported authentication-brand mismatch was observed. An independent site's identity has not been verified."
    # Only currently sourced catalog entries may produce navigation guidance.
    route = brand["safe_route"] if suspected and source else None
    return IdentityAnalysis(
        claimed,
        host,
        dest_host,
        consistency,
        explanation,
        route,
        suspected,
        "available" if observed else "unavailable",
        relation,
        CATALOG_VERSION,
        source,
    )
