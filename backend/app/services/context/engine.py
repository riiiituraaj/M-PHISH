def build_relationships(hostname: str, page_analysis: dict, context: dict | None = None) -> dict:
    """Build a small auditable graph from one navigation, never infer user identity."""
    nodes = [{"id": "url", "type": "url", "label": hostname}, {"id": "domain", "type": "domain", "label": hostname}, {"id": "page", "type": "webpage", "label": page_analysis.get("title", "Website") or "Website"}]
    edges = [["url", "domain"], ["domain", "page"]]
    if page_analysis.get("login_like"):
        nodes.append({"id": "form", "type": "form", "label": "Login form"})
        edges.append(["page", "form"])
    return {"nodes": nodes, "edges": edges, "context": context or {}}
