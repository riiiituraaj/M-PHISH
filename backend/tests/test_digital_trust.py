import numpy as np

from backend.app.analysis import build_report
from backend.app.services.ml.experiments import run_multimodal_experiments
from backend.app.services.ml.model import extract_features_vector, get_threat_model


def test_missing_dom_dns_tls_is_unknown():
    report = build_report("https://example.com", remote=False)
    assert report["classification"] == "UNKNOWN"
    assert report["digital_trust_profile"]["trust_state"] == "UNKNOWN"
    assert report["website_authenticity"]["overall_score"] is None
    assert report["ml_prediction"]["raw_probability"] is None
    assert report["ml_prediction"]["calibrated_probability"] is None


def test_tutorial_brand_mention_is_not_impersonation():
    report = build_report(
        "https://tutorial.example",
        fixture_html="<title>Google Drive tutorial</title><p>Use Google Drive to share files.</p>",
        remote=False,
    )
    assert not report["identity_analysis"]["is_impersonation_suspected"]
    assert report["safe_route"] is None


def test_warning_survives_missing_domain_information():
    report = build_report(
        "https://deceptive.example",
        fixture_html='<title>Google Account Login</title><form action="https://collector.example/submit"><input type="password"></form>',
        remote=False,
    )
    assert report["classification"] in ("HIGH", "CRITICAL")
    assert report["digital_trust_profile"]["trust_state"] in ("HIGH_RISK", "STOP")
    assert report["domain_analysis"]["availability"] == "unavailable"
    assert report["decision_evidence_ids"]


def test_same_site_and_known_sso_are_contextual():
    for target in (
        "/login",
        "https://accounts.google.com/login",
        "https://checkout.stripe.com/pay",
    ):
        report = build_report(
            "https://shop.example.com",
            fixture_html=f'<title>Sign in</title><form action="{target}"><input type="password"></form>',
            remote=False,
        )
        assert report["classification"] not in ("HIGH", "CRITICAL")
        assert not report["identity_analysis"]["is_impersonation_suspected"]


def test_consented_extension_observation_changes_decision(signed):
    response = signed.post(
        "/api/v1/dynamic-trust/evaluate",
        json={
            "url": "https://normal.example",
            "action_type": "form_submit",
            "action_details": {
                "form_action": "https://unrelated.example",
                "field_categories": ["password"],
            },
            "context": {
                "observations": {
                    "consent": True,
                    "fields": ["password"],
                    "password_inputs": 1,
                    "forms": 1,
                    "form_actions": ["https://unrelated.example"],
                }
            },
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["requires_intervention"]
    assert response.json()["data"]["evidence"]


def test_field_values_never_enter_report():
    report = build_report(
        "https://example.com",
        fixture_html='<form><input type="password" value="secret-sentinel"></form>',
        remote=False,
    )
    assert "secret-sentinel" not in str(report)
    assert report["privacy_assessment"]["sensitive_count"] == 1


def test_missing_features_and_research_no_runtime_training():
    vector = extract_features_vector({"url_length": 20})
    assert np.isnan(vector[14])  # no invented domain age
    assert get_threat_model().predict_multimodal({"url_length": 20}).calibrated_probability is None
    assert run_multimodal_experiments() == []


def test_demo_is_isolated(signed):
    report = signed.post("/api/v1/demo/scenarios/benign-login")
    assert report.status_code == 200, report.text
    assert report.json()["data"]["demo"] is True
    assert signed.get("/api/v1/investigations").json()["data"] == []
