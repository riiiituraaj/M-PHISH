from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.ml.model import get_threat_model
from backend.app.services.ml.experiments import run_multimodal_experiments

client = TestClient(app)


def test_safe_website_scenario():
    """Scenario 1: Normal harmless website yields TRUSTED state and high authenticity."""
    resp = client.post("/api/investigations", json={"url": "http://m-phish.local/simple-site.html"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed"
    assert data["digital_trust_profile"]["trust_state"] in ("TRUSTED", "CAUTION")
    assert data["digital_trust_profile"]["overall_trust"] >= 50
    assert data["website_authenticity"]["overall_score"] >= 60


def test_fake_login_external_destination():
    """Scenario 2: Password submitted to cross-origin collector triggers STOP state."""
    resp = client.post("/api/investigations", json={"url": "http://m-phish.local/suspicious-login.html"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["digital_trust_profile"]["trust_state"] == "STOP"
    assert data["trust_before_you_act"]["requires_intervention"] is True
    assert any(e["category"] == "BEHAVIOR" for e in data["evidence"])


def test_identity_mismatch_and_safe_route():
    """Scenario 3: Page claiming to be Google Account on an unverified domain triggers Safe Route."""
    resp = client.post("/api/investigations", json={"url": "http://m-phish.local/identity-mismatch.html"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["identity_analysis"]["is_impersonation_suspected"] is True
    assert data["identity_analysis"]["identity_consistency"] == "LOW"
    assert data["safe_route"] == "https://accounts.google.com"
    assert data["digital_trust_profile"]["trust_state"] == "STOP"


def test_synthetic_content_detection_is_contextual():
    """Scenario 4: AI-assisted text is flagged contextually without claiming it is inherently malicious."""
    resp = client.post("/api/investigations", json={"url": "http://m-phish.local/synthetic-content.html"})
    assert resp.status_code == 200
    data = resp.json()
    synthetic = data["synthetic_web_analysis"]
    assert synthetic["is_synthetic_likely"] is True
    assert len(synthetic["indicators"]) > 0
    # Must explicitly state that AI-assisted creation does not by itself imply malice
    assert "not" in synthetic["context_note"].lower()


def test_privacy_heavy_form_assessment():
    """Scenario 5: Form harvesting phone, address, government ID, PIN, and OTP is flagged."""
    resp = client.post("/api/investigations", json={"url": "http://m-phish.local/privacy-heavy.html"})
    assert resp.status_code == 200
    data = resp.json()
    privacy = data["privacy_assessment"]
    assert privacy["sensitive_count"] >= 2
    assert privacy["risk_level"] in ("ELEVATED", "HIGH")
    assert any(f["name"] == "otp" and f["detected"] for f in privacy["requested_fields"])


def test_download_risk_assessment():
    """Scenario 6: Executable file (.exe) on untrusted page triggers download alert."""
    resp = client.post("/api/investigations", json={"url": "http://m-phish.local/download-risk.html"})
    assert resp.status_code == 200
    data = resp.json()
    download = data["download_safety"]
    assert download["has_download"] is True
    assert download["is_executable_or_script"] is True
    assert download["risk_level"] in ("ATTENTION", "HIGH_RISK")


def test_dynamic_trust_evaluation_endpoint():
    """Dynamic trust endpoint responds to user interaction steps and flags sensitive field focus."""
    resp = client.post(
        "/api/v1/dynamic-trust/evaluate",
        json={
            "url": "http://m-phish.local/identity-mismatch.html",
            "action_type": "password_focused",
            "action_details": {"field": "password"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["requires_intervention"] is True
    assert data["transition"]["current_state"] == "STOP"
    assert data["safe_route"] == "https://accounts.google.com"


def test_calibrated_ml_model_bounds():
    """Calibrated XGBoost model returns valid probability between 0.0 and 1.0."""
    model = get_threat_model()
    # High risk sample
    pred_high = model.predict({
        "url_length": 120,
        "hostname_length": 45,
        "subdomain_count": 3,
        "ip_based_url": True,
        "https": False,
        "unusual_port": True,
        "suspicious_keywords": ["login", "verify", "secure"],
    })
    assert 0.0 <= pred_high.calibrated_probability <= 1.0
    assert pred_high.model_name == "xgboost-platt-calibrated"
    assert pred_high.calibration_method == "platt-scaling"

    # Low risk sample
    pred_low = model.predict({
        "url_length": 22,
        "hostname_length": 12,
        "subdomain_count": 0,
        "ip_based_url": False,
        "https": True,
        "unusual_port": False,
        "suspicious_keywords": [],
    })
    assert 0.0 <= pred_low.calibrated_probability <= 1.0
    assert pred_low.calibrated_probability < pred_high.calibrated_probability


def test_research_multimodal_experiments():
    """Multimodal ablation study endpoint computes Experiments A to E with standard metrics."""
    resp = client.get("/api/v1/research/experiments")
    assert resp.status_code == 200
    data = resp.json()["data"]
    experiments = data["experiments"]
    assert len(experiments) == 5
    exp_ids = [e["experiment_id"] for e in experiments]
    assert exp_ids == ["EXP-A", "EXP-B", "EXP-C", "EXP-D", "EXP-E"]
    for exp in experiments:
        assert 0.0 <= exp["accuracy"] <= 1.0
        assert 0.0 <= exp["roc_auc"] <= 1.0
        assert 0.0 <= exp["brier_score"] <= 1.0
        assert exp["inference_latency_ms"] >= 0.0


def test_demo_scenarios_endpoint():
    """Demo scenarios endpoint returns safe local walkthrough fixtures."""
    resp = client.get("/api/v1/demo/scenarios")
    assert resp.status_code == 200
    scenarios = resp.json()["data"]
    assert len(scenarios) >= 6

