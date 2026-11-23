"""Passive HTML observations from an isolated collector, never an API browser."""

import hashlib
import os
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from ...core.network import redact_url, resolve_public
from ..observations import destination_relationship


def _safe_host(value):
    try:
        resolve_public(value)
        return True
    except (ValueError, OSError):
        return False


class PageParser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.forms, self.passwords = url, 0, 0
        self.actions, self.fields, self.title = [], [], ""
        self.endpoint_fingerprints = {}
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "form":
            self.forms += 1
            if len(self.actions) < 12:
                try:
                    full = urljoin(self.url, attr.get("action") or self.url)
                    if urlsplit(full).path not in ("", "/"):
                        self.endpoint_fingerprints[redact_url(full)] = hashlib.sha256(
                            (redact_url(full) + urlsplit(full).path).encode()
                        ).hexdigest()
                    self.actions.append(
                        redact_url(urljoin(self.url, attr.get("action") or self.url))
                    )
                except ValueError:
                    pass
        if tag == "input":
            kind = str(attr.get("type", "")).lower()
            self.passwords += int(kind == "password")
            category = {"password": "password", "email": "email", "tel": "phone"}.get(kind)
            hint = str(attr.get("autocomplete", "")).lower()
            if hint.startswith("cc-"):
                category = "card"
            if hint == "one-time-code":
                category = "otp"
            if category and category not in self.fields:
                self.fields.append(category)

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:200]


def parse_html(url, html, source="isolated_collector"):
    parser = PageParser(url)
    parser.feed(html[:1_000_000])
    relations = [destination_relationship(url, action) for action in parser.actions]
    relation = (
        "unrelated" if "unrelated" in relations else (relations[0] if relations else "unknown")
    )
    return {
        "available": True,
        "availability": "available",
        "source": source,
        "html_available": True,
        "title": parser.title or "Untitled",
        "forms": parser.forms,
        "password_inputs": parser.passwords,
        "fields": parser.fields,
        "endpoint_fingerprints": parser.endpoint_fingerprints,
        "form_actions": parser.actions,
        "form_action_url": next(
            (a for a in parser.actions if destination_relationship(url, a) == "unrelated"),
            parser.actions[0] if parser.actions else None,
        ),
        "destination_relationship": relation,
        "external_form_action": relation == "unrelated",
        "login_like": parser.passwords > 0,
        "redirect_count": 0,
        "screenshot": None,
        "limitations": [
            "Passive HTML only; JavaScript behavior and authenticated pages are not inspected."
        ],
    }


def unavailable(reason="disabled_provider"):
    return {
        "available": False,
        "availability": "unavailable",
        "reason": reason,
        "title": "Unavailable",
        "forms": None,
        "password_inputs": None,
        "screenshot": None,
        "html_available": False,
    }


def analyze_sync(url, timeout_seconds=20, max_redirects=5, max_requests=100, visual_consent=False):
    endpoint = os.getenv("CRAWLER_URL")
    if not endpoint:
        return unavailable()
    try:
        with httpx.Client(timeout=min(timeout_seconds, 20), trust_env=False) as client:  # noqa: SIM117 -- close response before JSON parsing
            with client.stream(
                "POST",
                endpoint.rstrip("/") + "/inspect",
                json={"url": url, "visual_consent": visual_consent},
            ) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 2_000_000:
                        return unavailable("response_size_limit")
        import json

        return json.loads(body)
    except (ValueError, httpx.HTTPError):
        return unavailable("collector_unavailable")
