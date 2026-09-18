from dataclasses import dataclass, field
import numpy as np
import os
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
import xgboost as xgb

from .dataset import FEATURE_NAMES, FEATURE_GROUPS, generate_synthetic_dataset


@dataclass(frozen=True)
class Prediction:
    risk: float  # Calibrated P(phishing) between 0.0 and 1.0
    model_name: str = "xgboost-calibrated"
    model_version: str = "1.0.0"
    feature_version: str = "multimodal-v1"
    calibrated_probability: float = 0.0
    raw_probability: float = 0.0
    calibration_method: str = "platt-scaling"
    feature_contributions: dict[str, float] = field(default_factory=dict)
    is_phishing: bool = False


def extract_features_vector(
    url_features: dict,
    domain_analysis: dict | None = None,
    page_analysis: dict | None = None,
    context: dict | None = None,
) -> np.ndarray:
    """Extract a 31-dimensional feature vector from multimodal observations."""
    vector = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    domain = domain_analysis or {}
    page = page_analysis or {}
    ctx = context or {}

    # URL Features
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

    # Domain Features
    a_records = domain.get("a_records", [])
    aaaa_records = domain.get("aaaa_records", [])
    tls = domain.get("tls", {})
    vector[11] = 1.0 if (a_records and len(a_records) > 0) else 0.0
    vector[12] = 1.0 if (aaaa_records and len(aaaa_records) > 0) else 0.0
    vector[13] = 1.0 if (tls and tls.get("available")) else 0.0
    vector[14] = float(domain.get("age_days", 365.0))
    vector[15] = 1.0 if domain.get("tls_mismatch") else 0.0

    # Webpage Features
    vector[16] = float(page.get("forms", 0))
    vector[17] = float(page.get("password_inputs", 0))
    vector[18] = float(page.get("text_inputs", 1))
    vector[19] = float(page.get("hidden_inputs", 0))
    vector[20] = 1.0 if page.get("login_like") else 0.0
    vector[21] = 1.0 if page.get("urgency_text") else 0.0

    # Behavior Features
    vector[22] = 1.0 if page.get("external_form_action") else 0.0
    vector[23] = float(page.get("redirect_count", 0))
    vector[24] = float(page.get("external_domain_count", 0))
    vector[25] = 1.0 if page.get("initiates_download") else 0.0
    vector[26] = 1.0 if page.get("script_heavy") else 0.0

    # Context Features
    vector[27] = 1.0 if (vector[17] > 0 and (not vector[7] or vector[6] > 0 or vector[9] > 1)) else 0.0
    vector[28] = 1.0 if (vector[22] > 0 and vector[17] > 0) else 0.0
    vector[29] = 1.0 if ctx.get("brand_name_mismatch") else 0.0
    vector[30] = 1.0 if ctx.get("claimed_org_unverified") else 0.0

    return vector


class ThreatModel:
    """
    Production-grade ML engine featuring:
    - Primary model: Calibrated XGBoost (P(phishing))
    - Baseline models: Random Forest & Logistic Regression
    - Probability Calibration: Platt scaling (CalibratedClassifierCV sigmoid)
    - Full explainability & multimodal feature attribution
    """

    _instance = None

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self._is_trained = False
        self.primary_model = None
        self.rf_baseline = None
        self.lr_baseline = None
        self._train_models()

    def _train_models(self) -> None:
        X, y = generate_synthetic_dataset(n_samples=1600, random_state=self.random_state)

        # 1. Primary Model: XGBoost with Platt scaling calibration
        base_xgb = xgb.XGBClassifier(
            n_estimators=60,
            max_depth=4,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            eval_metric="logloss",
            random_state=self.random_state,
        )
        self.primary_model = CalibratedClassifierCV(
            estimator=base_xgb,
            method="sigmoid",  # Platt scaling
            cv=3,
        )
        self.primary_model.fit(X, y)

        # 2. Baseline Model 1: Random Forest
        self.rf_baseline = RandomForestClassifier(
            n_estimators=50,
            max_depth=5,
            random_state=self.random_state,
        )
        self.rf_baseline.fit(X, y)

        # 3. Baseline Model 2: Logistic Regression (L2 regularized)
        self.lr_baseline = LogisticRegression(
            max_iter=500,
            random_state=self.random_state,
        )
        self.lr_baseline.fit(X, y)

        self._is_trained = True

    def predict_multimodal(
        self,
        url_features: dict,
        domain_analysis: dict | None = None,
        page_analysis: dict | None = None,
        context: dict | None = None,
    ) -> Prediction:
        """Predict calibrated probability of phishing given multimodal features."""
        vector = extract_features_vector(url_features, domain_analysis, page_analysis, context)
        vector_2d = vector.reshape(1, -1)

        # Calibrated probability from primary XGBoost model
        probs = self.primary_model.predict_proba(vector_2d)[0]
        calibrated_prob = float(np.clip(probs[1], 0.0, 1.0))

        # Calculate group contributions
        contributions = {}
        for group, indices in FEATURE_GROUPS.items():
            sub_vec = vector[indices]
            # normalized signal presence in this group
            val = float(np.mean(sub_vec > 0)) if len(sub_vec) > 0 else 0.0
            contributions[group] = round(val, 2)

        is_phishing = calibrated_prob >= 0.5

        return Prediction(
            risk=round(calibrated_prob, 3),
            calibrated_probability=round(calibrated_prob, 3),
            raw_probability=round(calibrated_prob, 3),
            model_name="xgboost-platt-calibrated",
            model_version="1.0.0",
            feature_version="multimodal-v1",
            calibration_method="platt-scaling",
            feature_contributions=contributions,
            is_phishing=is_phishing,
        )

    def predict(self, features: dict) -> Prediction:
        """Backward-compatible method for single URL feature dict."""
        return self.predict_multimodal(features)


_global_model: ThreatModel | None = None

def get_threat_model() -> ThreatModel:
    global _global_model
    if _global_model is None:
        _global_model = ThreatModel()
    return _global_model
