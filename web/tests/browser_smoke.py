"""Real Chromium UI journeys with a labelled, deterministic API substitute.

Requires a running dashboard at WEB_TEST_URL (default http://localhost:3000).
Does not claim real backend, Redis, deployment or detection validation.
"""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


def main():
    base = os.getenv("WEB_TEST_URL", "http://localhost:3000")
    output = Path(__file__).resolve().parents[1] / "artifacts" / "browser"
    output.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC)
    report = {
        "id": "controlled-job", "url": "https://example.com/", "hostname": "example.com",
        "status": "COMPLETED", "risk_score": 0, "classification": "UNKNOWN", "confidence": None,
        "summary": "Insufficient evidence to assess this page fully.",
        "recommendation": "Check the intended recipient before sharing sensitive information.",
        "coverage": {"fraction": 0.25, "url": "available", "domain": "unavailable", "page": "unavailable"},
        "digital_trust_profile": {"trust_state": "UNKNOWN", "overall_trust": None, "state_reason": "Collection unavailable."},
        "ml_prediction": {"availability": "unavailable", "raw_probability": None, "calibrated_probability": None},
        "evidence": [], "events": [], "limitations": ["Controlled UI test fixture; not a live assessment."],
        "created_at": stamp.isoformat(), "expires_at": (stamp + timedelta(minutes=5)).isoformat(),
        "contract_version": "2.0", "visual_analysis": {"availability": "unavailable", "reason": "consent_absent"},
    }
    state = {"signed_in": False, "polls": 0, "job": False, "outage": False,
             "settings": {"knowledge_level": "standard", "history_enabled": True, "ai_enabled": False,
                          "notifications_enabled": True, "retention_days": 7}}
    checks = []
    browser_errors = []

    def api(route):
        request = route.request
        path = request.url.split("/api/v1/")[-1].split("?")[0]
        headers = {"Access-Control-Allow-Origin": base, "Access-Control-Allow-Credentials": "true",
                   "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "GET,POST,PATCH,DELETE,OPTIONS"}
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=headers)
            return
        status = 200
        data = {}
        if state["outage"]:
            route.fulfill(status=503, content_type="application/json", headers=headers,
                          body=json.dumps({"success": False, "error": {"message": "Controlled service outage."}}))
            return
        if path == "auth/login":
            state["signed_in"] = True
            data = {"user": {"id": "test-user", "email": "test@example.com", "role": "user"}}
        elif not state["signed_in"]:
            status = 401
        elif path == "auth/session":
            data = {"user": {"id": "test-user", "email": "test@example.com", "role": "user"}}
        elif path == "auth/logout":
            state["signed_in"] = False
        elif path == "settings":
            if request.method == "PATCH":
                state["settings"].update(request.post_data_json)
            data = state["settings"]
        elif path == "investigations" and request.method == "POST":
            state["job"] = True
            state["polls"] = 0
            data = {"id": report["id"], "status": "QUEUED"}
        elif path == "investigations":
            data = [report] if state["job"] else []
        elif path.endswith("/export"):
            route.fulfill(status=200, headers=headers, content_type="application/json", body=json.dumps(report))
            return
        elif path == "investigations/controlled-job":
            state["polls"] += 1
            data = report if state["polls"] > 1 else {"id": report["id"], "url": report["url"], "status": "QUEUED"}
        elif path == "research/experiments":
            data = {"availability": "unavailable", "experiments": [], "limitations": ["No independent evaluation."]}
        elif path == "demo/scenarios":
            data = [{"id": "simple-site", "title": "Simple site", "description": "Controlled synthetic fixture."}]
        elif path == "demo/scenarios/simple-site":
            data = report | {"demo": True}
        else:
            status = 404
        payload = {"success": status == 200, "data": data, "request_id": "controlled-request"}
        if status != 200:
            payload["error"] = {"message": "Sign in required." if status == 401 else "Controlled route unavailable."}
        route.fulfill(status=status, content_type="application/json", headers=headers, body=json.dumps(payload))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel="chromium")
        context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
        context.route("**/api/v1/**", api)
        page = context.new_page()
        page.on("pageerror", lambda error: browser_errors.append(str(error)))
        page.goto(base)
        expect(page.get_by_role("heading", name="Understand the evidence before you act.")).to_be_visible()
        page.get_by_role("link", name="Sign in", exact=True).click()
        page.get_by_label("Email", exact=True).fill("test@example.com")
        page.get_by_label("Password", exact=True).fill("controlled-test-password")
        page.get_by_role("button", name="Sign in", exact=True).click()
        expect(page.get_by_role("button", name="Sign out")).to_be_visible()
        checks.append("desktop sign-in and session navigation")
        page.get_by_label("Website URL", exact=True).fill("https://example.com")
        page.get_by_role("button", name="Start investigation").click()
        expect(page.get_by_role("heading", name="Waiting for a worker")).to_be_visible()
        expect(page.get_by_role("heading", name=report["summary"])).to_be_visible(timeout=10000)
        expect(page.get_by_text("25.0%; availability is separate from severity")).to_be_visible()
        assert "TRUSTED" not in page.locator("main").inner_text()
        assert "NaN" not in page.locator("main").inner_text()
        checks.append("queued-to-completed flow; unavailable/null results never become trusted or NaN")
        with page.expect_download() as downloaded:
            page.get_by_role("button", name="Export JSON").click()
        assert downloaded.value.suggested_filename.endswith(".json")
        checks.append("JSON export download")
        page.screenshot(path=str(output / "report-desktop.png"), full_page=True)
        page.get_by_role("link", name="Settings", exact=True).click()
        page.get_by_label("Explanation detail").select_option("technical")
        page.get_by_label("Save investigations to history").uncheck()
        page.get_by_role("button", name="Save preferences").click()
        expect(page.get_by_text("Preferences saved to your account.")).to_be_visible()
        page.reload()
        expect(page.get_by_label("Explanation detail")).to_have_value("technical")
        expect(page.get_by_label("Save investigations to history")).not_to_be_checked()
        checks.append("settings persist across reload via API")
        page.get_by_role("link", name="Research", exact=True).click()
        expect(page.get_by_role("heading", name="No stored evaluation is available")).to_be_visible()
        assert "Optimal" not in page.locator("main").inner_text()
        checks.append("unavailable research has no invented winner")
        page.get_by_role("link", name="Demo", exact=True).click()
        page.get_by_role("button", name="Run fixture").click()
        expect(page.get_by_text("Isolated demonstration.", exact=True)).to_be_visible()
        checks.append("demo is explicitly labelled")
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(base + "/investigations/controlled-job")
        expect(page.get_by_role("heading", name=report["summary"])).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1")
        page.screenshot(path=str(output / "report-mobile.png"), full_page=True)
        checks.append("mobile 390px report has no horizontal overflow")
        page.goto(base + "/admin")
        expect(page.get_by_text("Administrator access is required.")).to_be_visible()
        checks.append("ordinary user sees permission-denied state")
        state["outage"] = True
        page.goto(base + "/investigations")
        expect(page.get_by_text("Service unavailable", exact=True)).to_be_visible()
        checks.append("service failure presents unavailable, no sample fallback")
        assert not browser_errors, browser_errors
        context.close()
        browser.close()
    result = {"scope": "Real Chromium UI with controlled API substitute; not backend/queue E2E", "at": datetime.now(UTC).isoformat(), "checks": checks, "browser_errors": browser_errors}
    (output / "results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
