"""Shared observation semantics. Missing data must never be a benign observation."""

from urllib.parse import urljoin, urlsplit, urlunsplit


def page_available(page: dict) -> bool:
    if page.get("availability") in {"unavailable", "disabled", "failed", "unknown"}:
        return False
    if page.get("status") in {"unavailable", "disabled", "failed", "skipped"}:
        return False
    return page.get("availability") in {"available", "partial"} or bool(
        page.get("inspected")
        or page.get("source") in {"fixture", "browser", "extension", "client_reported"}
        or page.get("html_available")
    )


def host_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def normalized_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return ""


def registrable_domain(host: str) -> str:
    """Bundled PSL, no network fetch. Conservative exact-host fallback if unavailable."""
    try:
        import tldextract

        result = tldextract.TLDExtract(
            suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
        )(host)
        return result.top_domain_under_public_suffix or host
    except ImportError:
        return host


def redacted_endpoint(url: str, base: str = "") -> str:
    try:
        parsed = urlsplit(urljoin(base, url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ""
        host = normalized_host(urljoin(base, url))
        if ":" in host:
            host = "[" + host + "]"
        port = parsed.port
        authority = host + (":" + str(port) if port and port not in {80, 443} else "")
        # Paths may contain account identifiers and reset tokens; omit them here.
        return urlunsplit((parsed.scheme, authority, "/", "", ""))
    except (ValueError, UnicodeError):
        return ""


# Reviewed provider endpoints, not a general proof of legitimacy or a consent grant.
IDENTITY_DESTINATIONS = (
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "account.apple.com",
)
PAYMENT_DESTINATIONS = (
    "checkout.stripe.com",
    "www.paypal.com",
    "www.sandbox.paypal.com",
)


def destination_relationship(page_url: str, action: str) -> str:
    source = normalized_host(page_url)
    target_url = urljoin(page_url, action or page_url)
    target = normalized_host(target_url)
    if not source or not target or urlsplit(target_url).scheme not in {"http", "https"}:
        return "unknown"
    if source == target:
        return (
            "same_origin"
            if urlsplit(page_url).scheme == urlsplit(target_url).scheme
            and urlsplit(page_url).port == urlsplit(target_url).port
            else "same_site"
        )
    if registrable_domain(source) == registrable_domain(target):
        return "same_site"
    if target in IDENTITY_DESTINATIONS:
        return "known_identity_provider"
    if target in PAYMENT_DESTINATIONS:
        return "known_payment_provider"
    return "unrelated"
