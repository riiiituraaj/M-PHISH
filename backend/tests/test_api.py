from fastapi.testclient import TestClient

from backend.app.jobs import run_job
from backend.app.main import app


def test_health_safe_and_correlated(client):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["request_id"] == response.headers["X-Request-ID"]
    assert set(response.json()["data"]) == {"status", "service", "version"}


def test_all_route_families_require_session(client):
    for prefix in ("/api", "/api/v1"):
        for suffix in (
            "/investigations",
            "/investigations/x",
            "/investigations/x/report",
            "/investigations/x/export",
            "/investigations/x/evidence",
            "/investigations/x/graph",
            "/investigations/x/timeline",
        ):
            assert client.get(prefix + suffix).status_code == 401
        assert (
            client.post(prefix + "/quick-check", json={"url": "https://example.com"}).status_code
            == 401
        )
        assert (
            client.post(prefix + "/investigations", json={"url": "https://example.com"}).status_code
            == 401
        )
    for route in (
        "/settings",
        "/research/experiments",
        "/admin/status",
        "/demo/scenarios",
    ):
        assert client.get("/api/v1" + route).status_code == 401


def test_durable_job_and_evidence(signed):
    response = signed.post(
        "/api/v1/investigations",
        json={"url": "https://example.com/private/token?password=sentinel"},
    )
    assert response.status_code == 200
    job = response.json()["data"]
    assert job["status"] == "QUEUED"
    assert job["url"] == "https://example.com/"
    assert signed.get("/api/v1/investigations/" + job["id"]).json()["data"]["status"] == "QUEUED"
    run_job(job["id"])
    report = signed.get("/api/v1/investigations/" + job["id"] + "/report").json()["data"]
    assert report["status"] == "COMPLETED"
    assert report["classification"] == "UNKNOWN"
    assert report["digital_trust_profile"]["overall_trust"] is None
    assert "sentinel" not in str(report)
    assert report["request_id"] == response.headers["X-Request-ID"]
    run_job(job["id"])  # duplicate delivery must be a no-op
    assert signed.get("/api/v1/investigations/" + job["id"]).status_code == 200


def test_horizontal_authorization_all_operations(signed):
    iid = signed.post("/api/v1/investigations", json={"url": "https://example.com"}).json()["data"][
        "id"
    ]
    run_job(iid)
    other = TestClient(app, headers={"Origin": "http://localhost:3000"})
    assert (
        other.post(
            "/api/v1/auth/register",
            json={"email": "other@example.test", "password": "different-test-password"},
        ).status_code
        == 200
    )
    for prefix in ("/api", "/api/v1"):
        assert (
            other.get(prefix + "/investigations").json().get("data", []) == []
            if prefix.endswith("v1")
            else other.get(prefix + "/investigations").json() == []
        )
        for section in (
            "",
            "/report",
            "/evidence",
            "/graph",
            "/timeline",
            "/export?format=json",
            "/export?format=pdf",
        ):
            assert other.get(prefix + "/investigations/" + iid + section).status_code == 404
        assert other.delete(prefix + "/investigations/" + iid).status_code == 404
        assert other.post(prefix + "/investigations/" + iid + "/cancel").status_code == 404
        assert other.post(prefix + "/investigations/" + iid + "/retry").status_code == 404


def test_cancel_retry_and_no_history(signed):
    assert signed.patch("/api/v1/settings", json={"history_enabled": False}).status_code == 200
    iid = signed.post("/api/v1/investigations", json={"url": "https://example.com"}).json()["data"][
        "id"
    ]
    assert signed.get("/api/v1/investigations").json()["data"] == []
    assert (
        signed.post("/api/v1/investigations/" + iid + "/cancel").json()["data"]["status"]
        == "CANCELLED"
    )
    run_job(iid)
    assert signed.get("/api/v1/investigations/" + iid).json()["data"]["status"] == "CANCELLED"
    assert signed.post("/api/v1/investigations/" + iid + "/retry").status_code == 200
    run_job(iid)
    assert signed.get("/api/v1/investigations/" + iid + "/report").status_code == 200


def test_session_logout_csrf_and_research(signed):
    assert (
        signed.patch(
            "/api/v1/settings",
            headers={"Origin": "https://attacker.example"},
            json={"ai_enabled": True},
        ).status_code
        == 403
    )
    assert signed.get("/api/v1/research/experiments?force_rerun=true").status_code == 403
    assert signed.get("/api/v1/research/experiments").json()["data"]["experiments"] == []
    assert signed.get("/api/v1/admin/status").status_code == 403
    assert signed.post("/api/v1/auth/logout").status_code == 200
    assert signed.get("/api/v1/settings").status_code == 401


def test_pairing_single_use_origin_and_revocation(signed):
    extension_id = "a" * 32
    pair = signed.post("/api/v1/auth/pair", json={"extension_id": extension_id})
    assert pair.status_code == 200
    code = pair.json()["data"]["code"]
    ext = TestClient(app, headers={"Origin": "chrome-extension://" + extension_id})
    payload = {"code": code, "extension_id": extension_id}
    response = ext.post("/api/v1/auth/pair/exchange", json=payload)
    assert response.status_code == 200
    ext.headers["Authorization"] = "Bearer " + response.json()["data"]["access_token"]
    assert ext.post("/api/v1/auth/pair/exchange", json=payload).status_code == 401
    assert ext.get("/api/v1/auth/session").status_code == 200
    assert (
        ext.get(
            "/api/v1/auth/session", headers={"Origin": "chrome-extension://" + "b" * 32}
        ).status_code
        == 403
    )
    assert ext.post("/api/v1/auth/logout").status_code == 200
    assert ext.get("/api/v1/auth/session").status_code == 401


def test_sensitive_payload_rejected_without_echo(signed):
    response = signed.post(
        "/api/v1/dynamic-trust/evaluate",
        json={
            "url": "https://example.com",
            "action_type": "password_focused",
            "action_details": {"password": "secret-sentinel"},
        },
    )
    assert response.status_code == 422
    assert "secret-sentinel" not in response.text
    assert response.json()["request_id"] == response.headers["X-Request-ID"]


def test_queue_capacity_and_delete_account(signed):
    for _ in range(3):
        assert (
            signed.post("/api/v1/investigations", json={"url": "https://example.com"}).status_code
            == 200
        )
    assert (
        signed.post("/api/v1/investigations", json={"url": "https://example.com"}).status_code
        == 429
    )
    assert signed.delete("/api/v1/auth/account").status_code == 200
    assert signed.get("/api/v1/investigations").status_code == 401
