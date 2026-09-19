from backend.app.services.webpage.analyzer import _safe_host
from backend.app.services.risk.engine import assess


def test_crawler_rejects_local_targets():
    assert _safe_host("http://127.0.0.1/") is False
    assert _safe_host("http://localhost/") is False


def test_risk_engine_is_bounded_and_transparent():
    result = assess([{"category": "CONTENT", "title": "Password field", "confidence": .9, "weight": 21}])
    assert 0 <= result.score <= 100
    assert result.top_factors == ["Password field"]
