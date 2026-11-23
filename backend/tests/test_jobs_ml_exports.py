import json
import time

import numpy as np
from sqlalchemy import select, update

from backend.app.core import storage as db
from backend.app.jobs import run_job
from backend.app.services.ml.dataset import FEATURE_NAMES, single_feature_shortcuts
from backend.app.services.ml.model import ThreatModel
from backend.app.services.ml.offline import metrics, release_gate, split_indices


def test_expired_lease_recovery_and_failure_retry(signed, monkeypatch):
    iid = signed.post("/api/v1/investigations", json={"url": "https://example.com"}).json()["data"][
        "id"
    ]
    with db.transaction() as conn:
        conn.execute(
            update(db.jobs)
            .where(db.jobs.c.id == iid)
            .values(status="ANALYZING", lease_until=time.time() - 10, attempts=1)
        )
    run_job(iid)
    assert signed.get("/api/v1/investigations/" + iid).json()["data"]["status"] == "COMPLETED"
    other = signed.post("/api/v1/investigations", json={"url": "https://example.com"}).json()[
        "data"
    ]["id"]

    def crash(*args, **kw):
        raise TimeoutError("private URL must not enter logs")

    monkeypatch.setattr("backend.app.main.build_report", crash)
    import pytest

    for _ in range(3):
        with pytest.raises(TimeoutError):
            run_job(other)
    assert signed.get("/api/v1/investigations/" + other).json()["data"]["status"] == "FAILED"


def test_retention_deletes_jobs_and_reports(signed):
    iid = signed.post("/api/v1/investigations", json={"url": "https://example.com"}).json()["data"][
        "id"
    ]
    run_job(iid)
    with db.transaction() as conn:
        conn.execute(update(db.jobs).where(db.jobs.c.id == iid).values(expires_at=time.time() - 1))
    assert signed.get("/api/v1/investigations/" + iid).status_code == 404
    assert db.purge_expired() == 1
    with db.transaction() as conn:
        assert conn.execute(select(db.reports).where(db.reports.c.id == iid)).first() is None


def test_pdf_json_export_authorized_and_escaped(signed):
    iid = signed.post("/api/v1/investigations", json={"url": "https://example.com"}).json()["data"][
        "id"
    ]
    run_job(iid)
    response = signed.get("/api/v1/investigations/" + iid + "/export?format=pdf")
    assert response.status_code == 200 and response.content.startswith(b"%PDF")
    assert signed.get("/api/v1/investigations/" + iid + "/export?format=json").json()["id"] == iid


def test_synthetic_shortcut_and_uncertainty_gate():
    X = np.zeros((200, len(FEATURE_NAMES)))
    labels = np.array([0] * 100 + [1] * 100)
    X[:, 3] = np.where(labels, 6, 2)
    assert single_feature_shortcuts(X, labels)
    perfect = metrics(labels, labels)
    assert perfect["accuracy"] == 1
    assert not release_gate(perfect)  # 100 negatives cannot support <=1% FPR upper bound


def test_group_splits_are_disjoint():
    labels = np.array([0, 1] * 200)
    groups = np.repeat(np.arange(100), 4)
    splits = split_indices(labels, groups)
    names = list(splits)
    for i, name in enumerate(names):
        for other in names[i + 1 :]:
            assert set(groups[splits[name]]).isdisjoint(groups[splits[other]])


def test_untrusted_model_never_deserialized(tmp_path):
    target = tmp_path / "payload.pkl"
    target.write_bytes(b"not a model")
    result = ThreatModel(artifact_path=str(target), expected_checksum="0" * 64).predict_multimodal(
        {"url_length": 20}
    )
    assert result.availability == "unavailable"


def test_provider_injection_cannot_override_policy(monkeypatch):
    from backend.app.services.ai import grounded

    monkeypatch.setenv("AI_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "test-only")

    class Reply:
        content = b"{}"

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "evidence_ids": ["invented"],
                                    "safe_route": "https://attacker.example",
                                }
                            )
                        }
                    }
                ]
            }

    monkeypatch.setattr(grounded.httpx.Client, "post", lambda *a, **kw: Reply())
    fallback = {
        "provider": "fallback",
        "summary": "Observed warning",
        "recommended_action": "Pause",
    }
    result = grounded.explain(
        [{"id": "real", "category": "URL", "title": "Observed", "severity": "HIGH"}],
        fallback,
        True,
    )
    assert result["provider"] == "fallback" and result["recommended_action"] == "Pause"
    assert "safe_route" not in result
