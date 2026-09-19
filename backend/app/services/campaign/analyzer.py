from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class CampaignSimilarity:
    has_related_campaign: bool
    confidence: float
    shared_characteristics: list[str]
    potential_relationship_note: str
    related_targets: list[str]


def analyze_campaign_similarity(
    current_url: str,
    page_data: dict,
    features: dict,
    recent_investigations: list[dict],
) -> CampaignSimilarity:
    """
    Evaluate whether the current website shares observable structural or infrastructure
    characteristics with previously investigated targets.
    Uses strict, cautious language: 'Potential relationship' or 'Shared characteristics detected'.
    """
    current_host = (urlparse(current_url).hostname or "").lower()
    has_ext_action = page_data.get("external_form_action", False)
    has_pwd = page_data.get("password_inputs", 0) > 0
    form_dest = page_data.get("form_action_url") or ""

    shared = []
    related = []

    for inv in recent_investigations:
        target_url = inv.get("url", "")
        target_host = (urlparse(target_url).hostname or "").lower()
        if target_host == current_host or not target_host:
            continue

        target_page = inv.get("page_analysis", {})
        target_dest = target_page.get("form_action_url") or ""

        # Match on identical external credential collector destination
        if form_dest and target_dest and form_dest == target_dest:
            shared.append(f"Identical credential submission endpoint ({form_dest})")
            related.append(target_host)
            break

        # Match on structural attack pattern: external form action + password
        if has_ext_action and target_page.get("external_form_action") and has_pwd and target_page.get("password_inputs", 0) > 0:
            shared.append("Matching credential harvesting form architecture")
            related.append(target_host)
            break

        # Match on IP-based host with similar token pattern
        if features.get("ip_based_url") and inv.get("features", {}).get("ip_based_url"):
            shared.append("Shared IP-hosted infrastructure pattern")
            related.append(target_host)
            break

    if shared and related:
        note = (
            f"Shared technical characteristics detected with previously investigated target(s): {', '.join(related[:2])}. "
            "This indicates a potential architectural relationship or common template usage, though distinct ownership cannot be ruled out."
        )
        return CampaignSimilarity(
            has_related_campaign=True,
            confidence=0.72,
            shared_characteristics=list(set(shared)),
            potential_relationship_note=note,
            related_targets=related[:3],
        )

    return CampaignSimilarity(
        has_related_campaign=False,
        confidence=0.0,
        shared_characteristics=[],
        potential_relationship_note="No observable campaign or template overlaps identified across stored investigations.",
        related_targets=[],
    )

