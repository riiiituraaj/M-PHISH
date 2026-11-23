"""Domain observations come from the isolated collector, never API egress."""

from urllib.parse import urlsplit


def analyze(url, timeout=3.0):
    return {
        "hostname": urlsplit(url).hostname,
        "availability": "unavailable",
        "reason": "collector_not_run",
        "a_records": None,
        "aaaa_records": None,
        "mx_records": None,
        "ns_records": None,
        "age_days": None,
        "registration": {
            "availability": "unavailable",
            "reason": "provider_not_configured",
        },
        "tls": {"available": False, "reason": "not_observed"},
    }
