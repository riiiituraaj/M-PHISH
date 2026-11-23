"""Inference only; deploy a checksum-pinned, JSON-only artifact from the offline pipeline."""

import hashlib
import json
import math
import os
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from ..observations import page_available
from .dataset import FEATURE_NAMES

FEATURE_VERSION = "observations-v2"


@dataclass(frozen=True)
class Prediction:
    risk: float | None = None
    model_name: str = "unavailable"
    model_version: str = "none"
    feature_version: str = FEATURE_VERSION
    calibrated_probability: float | None = None
    raw_probability: float | None = None
    calibration_method: str | None = None
    feature_contributions: dict[str, float] = field(default_factory=dict)
    is_phishing: bool | None = None
    availability: str = "unavailable"
    reason: str | None = "No validated model artifact configured."
    attribution_scale: str | None = None
    base_value: float | None = None
    missing_features: list[str] = field(default_factory=list)
    threshold: float | None = None


def extract_features_vector(
    url_features: dict,
    domain_analysis: dict | None = None,
    page_analysis: dict | None = None,
    context: dict | None = None,
) -> np.ndarray:
    """One extraction path for training/inference. NaN represents an unobserved feature."""
    vector = np.full(len(FEATURE_NAMES), np.nan, dtype=np.float64)
    domain, page, ctx = domain_analysis or {}, page_analysis or {}, context or {}
    url_mapping = [
        "url_length",
        "hostname_length",
        "subdomain_count",
        "dot_count",
        "hyphen_count",
        "special_character_count",
        "ip_based_url",
        "https",
        "unusual_port",
        "suspicious_keywords",
        "percent_encoded",
    ]
    for index, key in enumerate(url_mapping):
        if key in url_features and url_features[key] is not None:
            value = len(url_features[key]) if key == "suspicious_keywords" else url_features[key]
            vector[index] = float(value)
    if (
        domain.get("dns", {}).get("available")
        or domain.get("dns_available")
        or domain.get("a_records")
        or domain.get("aaaa_records")
    ):
        vector[11:13] = [
            bool(domain.get("a_records")),
            bool(domain.get("aaaa_records")),
        ]
    tls = domain.get("tls") or {}
    if tls.get("available") is True:
        vector[13] = 1
    if domain.get("age_days") is not None:
        vector[14] = float(domain["age_days"])
    if domain.get("tls_mismatch") is not None and tls.get("available"):
        vector[15] = float(domain["tls_mismatch"])
    page_mapping = [
        "forms",
        "password_inputs",
        "text_inputs",
        "hidden_inputs",
        "login_like",
        "urgency_text",
        "external_form_action",
        "redirect_count",
        "external_domain_count",
        "initiates_download",
        "script_heavy",
    ]
    if page_available(page):
        for offset, key in enumerate(page_mapping, 16):
            if key in page and page[key] is not None:
                vector[offset] = float(page[key])
        if all(np.isfinite(vector[i]) for i in [6, 7, 9, 17]):
            vector[27] = float(
                vector[17] > 0 and (vector[7] == 0 or vector[6] > 0 or vector[9] > 1)
            )
        if np.isfinite(vector[17]) and page.get("destination_relationship"):
            vector[28] = float(vector[17] > 0 and page["destination_relationship"] == "unrelated")
    for index, key in [(29, "brand_name_mismatch"), (30, "claimed_org_unverified")]:
        if ctx.get(key) is not None:
            vector[index] = float(ctx[key])
    finite = vector[np.isfinite(vector)]
    if np.any(finite < 0) or np.any(finite > 1_000_000):
        raise ValueError("Feature outside supported nonnegative bounds")
    count_indices = list(range(6)) + [9, 14, 16, 17, 18, 19, 23, 24]
    if any(np.isfinite(vector[i]) and vector[i] != int(vector[i]) for i in count_indices):
        raise ValueError("Count features must be integer-valued")
    binary_indices = set(range(len(FEATURE_NAMES))) - set(count_indices)
    if any(np.isfinite(vector[i]) and vector[i] not in (0, 1) for i in binary_indices):
        raise ValueError("Boolean features must be zero or one")
    return vector


def sigmoid(value: float) -> float:
    return 1 / (1 + math.exp(-max(-700, min(700, value))))


class ThreatModel:
    def __init__(
        self,
        random_state: int = 42,
        artifact_path: str | None = None,
        expected_checksum: str | None = None,
    ):
        self.artifact = None
        self.reason = "No validated model artifact configured."
        path = artifact_path or os.getenv("ML_ARTIFACT_PATH")
        checksum = expected_checksum or os.getenv("ML_ARTIFACT_SHA256")
        if not path:
            return
        try:
            if not checksum or len(checksum) != 64:
                raise ValueError("An explicit artifact SHA-256 is required")
            file = Path(path)
            if file.stat().st_size > 1_000_000:
                raise ValueError("Artifact exceeds size limit")
            raw = file.read_bytes()
            if hashlib.sha256(raw).hexdigest() != checksum.lower():
                raise ValueError("Artifact checksum mismatch")
            data = json.loads(raw)
            if (
                data.get("feature_version") != FEATURE_VERSION
                or data.get("feature_names") != FEATURE_NAMES
            ):
                raise ValueError("Incompatible feature schema")
            if data.get("format") != "m-phish-linear-v1" or data.get("release_gate") != "passed":
                raise ValueError("Artifact has not passed its scoped detection gates")
            n = len(FEATURE_NAMES)
            for key, length in [
                ("median", n),
                ("mean", 2 * n),
                ("scale", 2 * n),
                ("coefficients", 2 * n),
            ]:
                if len(data[key]) != length or not all(math.isfinite(float(v)) for v in data[key]):
                    raise ValueError("Invalid numeric artifact shape")
            if any(v <= 0 for v in data["scale"]) or not 0 <= data["threshold"] <= 1:
                raise ValueError("Invalid preprocessing/threshold")
            for key in ["intercept", "calibration_slope", "calibration_intercept"]:
                if not math.isfinite(float(data[key])):
                    raise ValueError("Nonfinite model parameter")
            self.artifact, self.reason = data, None
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self.reason = f"Model unavailable: {type(exc).__name__}: {exc}"

    def predict_multimodal(
        self,
        url_features: dict,
        domain_analysis: dict | None = None,
        page_analysis: dict | None = None,
        context: dict | None = None,
    ) -> Prediction:
        vector = extract_features_vector(url_features, domain_analysis, page_analysis, context)
        missing = [
            name
            for name, value in zip(FEATURE_NAMES, vector, strict=True)
            if not np.isfinite(value)
        ]
        if self.artifact is None:
            return Prediction(reason=self.reason, missing_features=missing)
        artifact = self.artifact
        # A model is eligible only for the modality/missingness scope represented in its training manifest.
        pattern = "".join("1" if not np.isfinite(v) else "0" for v in vector)
        if pattern not in artifact.get("supported_missingness_patterns", []):
            return Prediction(
                reason="Observation coverage is outside the validated model scope.",
                missing_features=missing,
            )
        for i, (minimum, maximum) in enumerate(artifact["feature_ranges"]):
            if (
                np.isfinite(vector[i])
                and minimum is not None
                and not minimum <= vector[i] <= maximum
            ):
                return Prediction(
                    reason="Observation is outside validated feature ranges.",
                    missing_features=missing,
                )
        filled = np.where(np.isfinite(vector), vector, artifact["median"])
        expanded = np.concatenate([filled, (~np.isfinite(vector)).astype(float)])
        standard = (expanded - artifact["mean"]) / artifact["scale"]
        contributions = standard * artifact["coefficients"]
        margin = float(np.sum(contributions) + artifact["intercept"])
        raw = sigmoid(margin)
        calibrated = sigmoid(
            margin * artifact["calibration_slope"] + artifact["calibration_intercept"]
        )
        names = FEATURE_NAMES + [name + "__missing" for name in FEATURE_NAMES]
        return Prediction(
            calibrated,
            "logistic-regression-calibrated",
            artifact["model_version"],
            FEATURE_VERSION,
            calibrated,
            raw,
            "held-out-sigmoid",
            dict(zip(names, map(float, contributions), strict=True)),
            calibrated >= artifact["threshold"],
            "available",
            None,
            "raw_log_odds",
            float(artifact["intercept"]),
            missing,
            artifact["threshold"],
        )

    def predict(self, features: dict) -> Prediction:
        return self.predict_multimodal(features)


_global_model: ThreatModel | None = None


def get_threat_model() -> ThreatModel:
    global _global_model
    if _global_model is None:
        _global_model = ThreatModel()
    return _global_model
