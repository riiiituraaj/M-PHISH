"""Stored research reads only. Training is an explicit offline command."""

import json
import os
from pathlib import Path


def run_multimodal_experiments(random_state: int = 42, force_rerun: bool = False) -> list[dict]:
    if force_rerun:
        raise ValueError(
            "Research execution is offline only: python -m backend.app.services.ml.offline"
        )
    configured = os.getenv("ML_RESEARCH_RESULTS")
    if not configured:
        return []
    try:
        path = Path(configured)
        if path.stat().st_size > 4_000_000:
            return []
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema_version") != "evaluation-v2" or not isinstance(
            data.get("experiments"), list
        ):
            return []
        return data["experiments"]
    except (OSError, ValueError, TypeError):
        return []
