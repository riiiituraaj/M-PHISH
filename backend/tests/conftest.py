import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from backend.app.core import storage


@pytest.fixture(autouse=True)
def database(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(tmp_path / "test.db"))
    monkeypatch.setenv("ALLOW_REGISTRATION", "true")
    monkeypatch.delenv("CRAWLER_URL", raising=False)
    monkeypatch.delenv("ML_ARTIFACT_PATH", raising=False)
    monkeypatch.setenv("EXTENSION_IDS", "a" * 32)
    if storage._engine is not None:
        storage._engine.dispose()
    storage._engine = None
    command.upgrade(Config("backend/alembic.ini"), "head")
    yield
    if storage._engine is not None:
        storage._engine.dispose()
    storage._engine = None


@pytest.fixture
def client():
    from backend.app.main import app

    with TestClient(app) as value:
        value.headers["Origin"] = "http://localhost:3000"
        yield value


@pytest.fixture
def signed(client):
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "owner@example.test", "password": "test-password-only-123"},
    )
    assert response.status_code == 200, response.text
    return client
