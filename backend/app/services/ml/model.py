from dataclasses import dataclass


@dataclass(frozen=True)
class Prediction:
    risk: float
    model_name: str = "url-baseline"
    model_version: str = "0.1.0"
    feature_version: str = "url-v1"


class ThreatModel:
    """Stable interface for a future calibrated Random Forest artifact."""
    def predict(self, features: dict) -> Prediction:
        signal = 0.0
        signal += .35 if features.get("ip_based_url") else 0
        signal += .2 if features.get("unusual_port") else 0
        signal += min(.3, len(features.get("suspicious_keywords", [])) * .1)
        signal += .15 if not features.get("https") else 0
        return Prediction(round(min(1.0, signal), 3))
