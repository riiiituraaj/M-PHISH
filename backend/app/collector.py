"""Isolated passive fetcher. Approved numeric-IP connections, TLS SNI validation.

No browser execution, cookies, form submission or automatic binary downloads.
Production requires the deployment network policy as a second boundary.
"""

import http.client
import json
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urljoin

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

from .core.network import TargetRejected, parse_target, redact_url, resolve_public
from .core.process import bounded_run
from .services.webpage.analyzer import parse_html, unavailable

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
slots = threading.BoundedSemaphore(2)


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=4096)
    visual_consent: bool = False


def fetch(url, deadline):
    parsed, host, addresses = resolve_public(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = socket.create_connection(
        (addresses[0], port), timeout=max(0.1, min(3, deadline - time.monotonic()))
    )
    conn = http.client.HTTPConnection(host, port, timeout=3)
    tls = {"available": False, "reason": "http_transport"}
    try:
        if sock.getpeername()[0] not in addresses:
            raise TargetRejected("Connection destination mismatch.")
        if parsed.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            certificate = sock.getpeercert()
            tls = {
                "available": True,
                "not_after": certificate.get("notAfter"),
                "issuer": certificate.get("issuer"),
            }
        conn.sock = sock
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        conn.request(
            "GET",
            path,
            headers={
                "Host": parsed.netloc,
                "Accept": "text/html",
                "Accept-Encoding": "identity",
                "User-Agent": "M-PHISH/0.2 passive-inspector",
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        if response.status in (301, 302, 303, 307, 308):
            return (
                None,
                response.getheader("Location"),
                {"tls": tls, "addresses": addresses},
            )
        if response.getheader("Content-Encoding", "identity") not in ("identity", ""):
            raise ValueError("Compressed responses are unsupported.")
        if "text/html" not in response.getheader("Content-Type", "").lower():
            raise ValueError("Only HTML is inspected.")
        if int(response.getheader("Content-Length", "0")) > 1_000_000:
            raise ValueError("Response size limit.")
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Collection timeout.")
            sock.settimeout(min(3, remaining))
            chunk = response.read(min(16384, 1_000_001 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > 1_000_000:
                raise ValueError("Response size limit.")
        return (
            body.decode("utf-8", errors="replace"),
            None,
            {"tls": tls, "addresses": addresses},
        )
    finally:
        conn.close()
        sock.close()


@app.get("/health")
def health():
    return {"status": "ok"}


def collect(payload: Target):
    target, chain, deadline = payload.url, [], time.monotonic() + 15
    try:
        for _ in range(6):
            parse_target(target)
            html, location, observations = fetch(target, deadline)
            if html is not None:
                result = parse_html(target, html)
                from .visual import inspect_visual

                result["visual_analysis"] = inspect_visual(
                    html,
                    payload.visual_consent,
                    sensitive=bool(
                        result.get("password_inputs") or "card" in result.get("fields", [])
                    ),
                )
                result.update(
                    raw_html=html,
                    final_url=redact_url(target),
                    redirect_chain=chain,
                    redirect_count=len(chain),
                    domain_analysis={
                        "availability": "available",
                        "hostname": parse_target(target)[1],
                        "a_records": [a for a in observations["addresses"] if ":" not in a],
                        "aaaa_records": [a for a in observations["addresses"] if ":" in a],
                        "tls": observations["tls"],
                        "age_days": None,
                        "registration": {
                            "availability": "unavailable",
                            "reason": "provider_not_configured",
                        },
                    },
                )
                return result
            if not location:
                raise ValueError("Redirect destination missing.")
            target = urljoin(target, location)
            parse_target(target)
            chain.append(redact_url(target))
        return unavailable("redirect_limit")
    except (ValueError, OSError, TimeoutError, http.client.HTTPException) as error:
        return unavailable(type(error).__name__)


@app.post("/inspect")
def inspect(payload: Target):
    if not slots.acquire(blocking=False):
        return unavailable("collector_capacity")
    try:
        # DNS and slow/trickling HTTP servers are bounded by process termination.
        result = bounded_run(
            [sys.executable, "-m", "backend.app.collector"],
            data=payload.model_dump_json().encode(),
            timeout=24,
        )
        if len(result) > 2_000_000:
            return unavailable("collector_output_limit")
        return json.loads(result)
    except (OSError, subprocess.SubprocessError, ValueError):
        return unavailable("collector_timeout_or_failure")
    finally:
        slots.release()


if __name__ == "__main__":
    print(
        json.dumps(
            collect(Target.model_validate_json(sys.stdin.buffer.read(32768))),
            ensure_ascii=False,
        )
    )
