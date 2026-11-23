import socket
import time

import pytest

from backend.app.collector import Target, collect, fetch
from backend.app.core.network import TargetRejected, parse_target, resolve_public


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://m-phish.local",
        "http://169.254.169.254",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://224.0.0.1",
        "http://0.0.0.0",
        "https://user:pass@example.com",
        "https://example.com:8443",
        "file:///etc/passwd",
        "http://example.com\\@127.0.0.1",
    ],
)
def test_private_and_ambiguous_targets(url):
    with pytest.raises(TargetRejected):
        parse_target(url)


def test_mixed_dns_answers_blocked(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **kw: [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.2", 443)),
        ],
    )
    with pytest.raises(TargetRejected):
        resolve_public("https://example.com")


def test_redirect_to_private_is_blocked_before_second_fetch(monkeypatch):
    from backend.app import collector

    calls = []

    def redirect(url, deadline):
        calls.append(url)
        return None, "http://127.0.0.1/secret", {}

    monkeypatch.setattr(collector, "fetch", redirect)
    result = collect(Target(url="https://example.com"))
    assert result["availability"] == "unavailable"
    assert len(calls) == 1


def test_connection_peer_mismatch_and_numeric_pin(monkeypatch):
    from backend.app import collector

    monkeypatch.setattr(
        collector,
        "resolve_public",
        lambda _: (
            parse_target("https://example.com")[0],
            "example.com",
            ["93.184.216.34"],
        ),
    )

    class Socket:
        def getpeername(self):
            return ("127.0.0.1", 443)

        def close(self):
            pass

    destinations = []

    def connect(destination, **kw):
        destinations.append(destination)
        return Socket()

    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(TargetRejected):
        fetch("https://example.com", time.monotonic() + 10)
    assert destinations == [("93.184.216.34", 443)]


def test_oversized_request(signed):
    response = signed.post(
        "/api/v1/investigations",
        content=b"x" * 40000,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
