from dataclasses import dataclass, field
from pathlib import Path
import json
import os
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import brier_score_loss, roc_auc_score
import xgboost as xgb

from .dataset import FEATURE_NAMES, FEATURE_GROUPS, generate_synthetic_dataset, load_external_dataset


MODEL_VERSION = "2.0.0"
FEATURE_VERSION = "multimodal-v2"


@dataclass(frozen=True)
class Prediction:
    risk: float
    model_name: str = "xgboost-platt-calibrated"
    model_version: str = MODEL_VERSION
    feature_version: str = FEATURE_VERSION
    calibrated_probability: float = 0.0
    raw_probability: float = 0.0
    calibration_method: str = "platt-scaling"
    feature_contributions: dict[str, float] = field(default_factory=dict)
    local_attribution: dict[str, float] = field(default_factory=dict)
    attribution_method: str = "leave-one-feature-out probability delta"
    is_phishing: bool = False
    training_data: str = "synthetic-development-benchmark"
    production_ready: bool = False
    validation: dict[str, float] = field(default_factory=dict)


def extract_features_vector(
    url_features: dict,
    domain_analysis: dict | None = None,
    page_analysis: dict | None = None,
    context: dict | None = None,
) -> np.ndarray:
    """Extract a deterministic 31-dimensional feature vector from multimodal observations."""
    vector = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    domain = domain_analysis or {}
    page = page_analysis or {}
    ctx = context or {}

    vector[0] = float(url_features.get("url_length", 30))
    vector[1] = float(url_features.get("hostname_length", 15))
    vector[2] = float(url_features.get("subdomain_count", 0))
    vector[3] = float(url_features.get("dot_count", 1))
    vector[4] = float(url_features.get("hyphen_count", 0))
    vector[5] = float(url_features.get("special_character_count", 0))
    vector[6] = 1.0 if url_features.get("ip_based_url") else 0.0
    vector[7] = 1.0 if url_features.get("https") else 0.0
    vector[8] = 1.0 if url_features.get("unusual_port") else 0.0
    vector[9] = float(len(url_features.get("suspicious_keywords", [])))
    vector[10] = 1.0 if url_features.get("percent_encoded") else 0.0

    a_records = domain.get("a_records", [])
    aaaa_records = domain.get("aaaa_records", [])
    tls = domain.get("tls", {}) or {}
    vector[11] = 1.0 if a_records else 0.0
    vector[12] = 1.0 if aaaa_records else 0.0
    vector[13] = 1.0 if tls.get("available") else 0.0
    vector[14] = float(domain.get("age_days", 365.0))
    vector[15] = 1.0 if domain.get("tls_mismatch") else 0.0

    vector[16] = float(page.get("forms", 0))
    vector[17] = float(page.get("password_inputs", 0))
    vector[18] = float(page.get("text_inputs", 1))
    vector[19] = float(page.get("hidden_inputs", 0))
    vector[20] = 1.0 if page.get("login_like") else 0.0
    vector[21] = 1.0 if page.get("urgency_text") else 0.0

    vector[22] = 1.0 if page.get("external_form_action") else 0.0
    vector[23] = float(page.get("redirect_count", 0))
    vector[24] = float(page.get("external_domain_count", 0))
    vector[25] = 1.0 if page.get("initiates_download") else 0.0
    vector[26] = 1.0 if page.get("script_heavy") else 0.0

    vector[27] = 1.0 if (vector[17] > 0 and (not vector[7] or vector[6] > 0 or vector[9] > 1)) else 0.0
    vector[28] = 1.0 if (vector[22] > 0 and vector[17] > 0) else 0.0
    vector[29] = 1.0 if ctx.get("brand_name_mismatch") else 0.0
    vector[30] = 1.0 if ctx.get("claimed_org_unverified") else 0.0
    return vector


class ThreatModel:
    """
    Reproducible ML engine for the repository's development benchmark.

    The important distinction is intentional: the bundled model is calibrated on a
    synthetic development benchmark and is NOT represented as a production detector.
    Real-world deployment requires an external, independently sourced phishing dataset.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self._is_trained = False
        self.primary_model = None
        self.rf_baseline = None
        self.lr_baseline = None
        self.validation_metrics: dict[str, float] = {}
        self.training_data = "synthetic-development-benchmark"
        self.model_approved = False
        self._train_models()

    def _train_models(self) -> None:
        dataset_path = os.getenv("MPHISH_DATASET_PATH", "").strip() or None
        X, y, self.training_data = load_external_dataset(dataset_path) if dataset_path else (*generate_synthetic_dataset(n_samples=2000, random_state=self.random_state), "synthetic-development-benchmark")
        X_train, X_holdout, y_train, y_holdout = train_test_split(
            X, y, test_size=0.2, random_state=self.random_state, stratify=y
        )

        base_xgb = xgb.XGBClassifier(
            n_estimators=80,
            max_depth=4,
            learning_rate=0.06,
            subsample=0.85,
            colsample_bytree=0.85,
            reg_lambda=1.0,
            eval_metric="logloss",
            random_state=self.random_state,
            n_jobs=1,
        )
        self.primary_model = CalibratedClassifierCV(
            estimator=base_xgb,
            method="sigmoid",
            cv=3,
        )
        self.primary_model.fit(X_train, y_train)

        self.rf_baseline = RandomForestClassifier(
            n_estimators=75,
            max_depth=6,
            random_state=self.random_state,
            n_jobs=1,
        )
        self.rf_baseline.fit(X_train, y_train)

        self.lr_baseline = LogisticRegression(max_iter=500, random_state=self.random_state)
        self.lr_baseline.fit(X_train, y_train)

        holdout_probs = self.primary_model.predict_proba(X_holdout)[:, 1]
        self.model_approved = os.getenv("MPHISH_MODEL_APPROVED", "false").lower() == "true" and self.training_data.startswith("external-csv:")
        self.validation_metrics = {
            "holdout_roc_auc": round(float(roc_auc_score(y_holdout, holdout_probs)), 4),
            "holdout_brier_score": round(float(brier_score_loss(y_holdout, holdout_probs)), 4),
            "holdout_samples": float(len(y_holdout)),
        }
        self._is_trained = True

    def _predict_probability(self, vector: np.ndarray) -> float:
        return float(np.clip(self.primary_model.predict_proba(vector.reshape(1, -1))[0, 1], 0.0, 1.0))

    def _local_attribution(self, vector: np.ndarray, baseline_probability: float) -> dict[str, float]:
        """Estimate local contribution using a batched leave-one-feature-out counterfactual."""
        counterfactuals = np.repeat(vector.reshape(1, -1), len(FEATURE_NAMES), axis=0)
        for idx in range(len(FEATURE_NAMES)):
            if idx == 7:
                neutral = 1.0
            elif idx == 14:
                neutral = 365.0
            elif idx in (0, 1, 2, 3, 4, 5, 9, 16, 18, 19, 23, 24):
                neutral = 0.0
            else:
                neutral = 0.0
            counterfactuals[idx, idx] = neutral
        probabilities = self.primary_model.predict_proba(counterfactuals)[:, 1]
        deltas = baseline_probability - np.clip(probabilities, 0.0, 1.0)
        attributions = {name: round(float(delta), 4) for name, delta in zip(FEATURE_NAMES, deltas)}
        return dict(sorted(attributions.items(), key=lambda item: abs(item[1]), reverse=True)[:10])

    def predict_multimodal(
        self,
        url_features: dict,
        domain_analysis: dict | None = None,
        page_analysis: dict | None = None,
        context: dict | None = None,
    ) -> Prediction:
        vector = extract_features_vector(url_features, domain_analysis, page_analysis, context)
        calibrated_prob = self._predict_probability(vector)

        # Group-level presence is intentionally retained as a descriptive signal,
        # not presented as model attribution.
        group_signals = {}
        for group, indices in FEATURE_GROUPS.items():
            sub_vec = vector[indices]
            group_signals[group] = round(float(np.mean(sub_vec > 0)), 2) if len(sub_vec) else 0.0

        local = self._local_attribution(vector, calibrated_prob)
        return Prediction(
            risk=round(calibrated_prob, 3),
            calibrated_probability=round(calibrated_prob, 3),
            raw_probability=round(calibrated_prob, 3),
            model_name="xgboost-platt-calibrated",
            model_version=MODEL_VERSION,
            feature_version=FEATURE_VERSION,
            calibration_method="platt-scaling",
            feature_contributions=group_signals,
            local_attribution=local,
            is_phishing=calibrated_prob >= 0.5,
            training_data=self.training_data,
            production_ready=self.model_approved,
            validation=self.validation_metrics,
        )

    def predict(self, features: dict) -> Prediction:
        return self.predict_multimodal(features)


_global_model: ThreatModel | None = None


def get_threat_model() -> ThreatModel:
    global _global_model
    if _global_model is None:
        _global_model = ThreatModel()
    return _global_model
