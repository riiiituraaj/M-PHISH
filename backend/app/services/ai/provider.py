from typing import Protocol


class AIProvider(Protocol):
    async def explain(self, evidence: list[dict], risk_assessment: dict, user_level: str) -> dict:
        """Return evidence-grounded explanation fields without changing the assessment."""


class FallbackAI:
    async def explain(self, evidence: list[dict], risk_assessment: dict, user_level: str = "standard") -> dict:
        titles = ", ".join(item["title"] for item in evidence[:3]) or "no strong warning signs"
        return {"summary": f"The investigation found {titles}.", "why": "These observations are considered together rather than as proof from one signal.", "recommended_action": "Avoid entering sensitive information until you can verify the service directly.", "uncertainty": "This is an evidence-based risk assessment, not a guarantee of intent."}
