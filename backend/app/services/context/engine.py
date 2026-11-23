from ..observations import page_available, redacted_endpoint


def build_relationships(hostname: str, page_analysis: dict, context: dict | None = None) -> dict:
    source = page_analysis.get("source", "server_observed")
    observed_at = page_analysis.get("observed_at")
    nodes = [
        {
            "id": "domain",
            "type": "domain",
            "label": hostname,
            "source": "input",
            "observed_at": observed_at,
        }
    ]
    edges = []
    if page_available(page_analysis):
        nodes.append(
            {
                "id": "page",
                "type": "webpage",
                "label": str(page_analysis.get("title") or "Inspected page")[:200],
                "source": source,
                "observed_at": observed_at,
            }
        )
        edges.append(["domain", "page"])
        actions = page_analysis.get("form_actions") or (
            [page_analysis["form_action_url"]] if page_analysis.get("form_action_url") else []
        )
        for index, action in enumerate(actions[:20]):
            target = redacted_endpoint(
                action if isinstance(action, str) else action.get("url", ""),
                "https://" + hostname,
            )
            if target:
                ident = "destination-" + str(index)
                nodes.append(
                    {
                        "id": ident,
                        "type": "form_destination",
                        "label": target,
                        "source": source,
                        "observed_at": observed_at,
                    }
                )
                edges.append(["page", ident])
    return {
        "nodes": nodes,
        "edges": edges,
        "availability": "available" if page_available(page_analysis) else "partial",
        "limitations": [
            "Relationships reflect observed destinations; they do not establish ownership."
        ],
    }
