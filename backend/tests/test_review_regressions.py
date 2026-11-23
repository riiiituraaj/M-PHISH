import subprocess

from backend.app.analysis import build_report
from backend.app.collector import Target, inspect
from backend.app.services.webpage.analyzer import parse_html
from backend.app.visual import inspect_visual


def test_negative_client_observation_cannot_erase_collected_danger(monkeypatch):
    html = '<form action="https://collector.example/submit"><input type="password"></form>'
    monkeypatch.setattr(
        "backend.app.analysis.analyze_sync",
        lambda *a, **kw: parse_html("https://site.example", html) | {"raw_html": html},
    )
    report = build_report(
        "https://site.example",
        context={
            "observations": {
                "consent": True,
                "password_inputs": 0,
                "forms": 0,
                "form_actions": [],
                "fields": [],
            }
        },
    )
    assert report["classification"] in ("HIGH", "CRITICAL")
    assert report["page_analysis"]["password_inputs"] == 1
    assert report["page_analysis"]["client_observations"]["password_inputs"] == 0


def test_collector_deadline_becomes_unavailable(monkeypatch):
    def timeout(*a, **kw):
        raise subprocess.TimeoutExpired("collector", 24)

    monkeypatch.setattr("backend.app.collector.bounded_run", timeout)
    result = inspect(Target(url="https://example.com"))
    assert result["availability"] == "unavailable"
    assert result["reason"] == "collector_timeout_or_failure"


def test_visual_consent_sensitive_and_disabled_states(monkeypatch):
    monkeypatch.delenv("ENABLE_VISUAL", raising=False)
    assert inspect_visual("<p>test</p>")["reason"] == "consent_absent"
    assert inspect_visual("<p>test</p>", True)["reason"] == "disabled_provider"
    assert (
        inspect_visual('<input type="password">', True, True)["reason"]
        == "sensitive_form_capture_not_supported"
    )


def test_campaign_requires_specific_owned_endpoint():
    html = '<form action="https://collector.example/submit"><input type="password"></form>'
    first = build_report("https://one.example", fixture_html=html, remote=False, owner_id="alice")
    second = build_report(
        "https://two.example",
        fixture_html=html,
        remote=False,
        owner_id="alice",
        recent_reports=[first | {"owner_id": "alice"}],
    )
    assert second["campaign_similarity"]["has_related_campaign"]
    isolated = build_report(
        "https://two.example",
        fixture_html=html,
        remote=False,
        owner_id="bob",
        recent_reports=[first | {"owner_id": "alice"}],
    )
    assert not isolated["campaign_similarity"]["has_related_campaign"]
