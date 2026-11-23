from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urljoin, urlsplit

from ..observations import normalized_host


@dataclass
class CampaignSimilarity:
    has_related_campaign: bool
    confidence: float | None
    shared_characteristics: list[str]
    potential_relationship_note: str
    related_targets: list[str]
    availability: str = "available"
    algorithm_version: str = "endpoint-fingerprint-v2"


def _fingerprint(url, action):
    parsed = urlsplit(urljoin(url, action))
    # The path hash permits exact comparison without disclosing identifiers/tokens.
    return (
        normalized_host(urljoin(url, action)),
        sha256(parsed.path.encode()).hexdigest(),
    )


def analyze_campaign_similarity(
    current_url: str,
    page_data: dict,
    features: dict,
    recent_investigations: list[dict],
    owner_id: str | None = None,
) -> CampaignSimilarity:
    if not owner_id:
        return CampaignSimilarity(
            False,
            None,
            [],
            "Comparison unavailable without an explicit owner scope.",
            [],
            "unavailable",
        )
    host = normalized_host(current_url)
    action = page_data.get("form_action_url")
    related, shared = [], []
    if (
        action
        and page_data.get("destination_relationship") == "unrelated"
        and page_data.get("password_inputs", 0)
    ):
        fingerprint = page_data.get("endpoint_fingerprints", {}).get(action)
        if not fingerprint:
            return CampaignSimilarity(
                False,
                None,
                [],
                "Specific endpoint fingerprint unavailable; generic forms are not campaign evidence.",
                [],
                "partial",
            )
        for investigation in recent_investigations[:100]:
            if investigation.get("owner_id") != owner_id:
                continue
            target = investigation.get("url", "")
            other = investigation.get("page_analysis", {})
            other_action = other.get("form_action_url")
            if (
                target
                and normalized_host(target) != host
                and other_action
                and other.get("password_inputs", 0)
                and other.get("destination_relationship") == "unrelated"
                and fingerprint == other.get("endpoint_fingerprints", {}).get(other_action)
            ):
                related.append(normalized_host(target))
                shared.append(
                    "Same external password-submission endpoint fingerprint: " + fingerprint[:16]
                )
    return CampaignSimilarity(
        bool(related),
        None,
        sorted(set(shared))[:5],
        "Exact endpoint reuse observed within your history. This does not identify an attacker or establish common ownership."
        if related
        else "No matching endpoint fingerprint observed within the available owner-scoped history.",
        sorted(set(related))[:5],
    )
