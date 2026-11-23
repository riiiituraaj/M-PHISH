"""Optional bounded offline rendering. Images and OCR text are never persisted."""

import hashlib
import io
import json
import os
import subprocess
import sys

from .core.process import bounded_run


def inspect_visual(html, consent=False, sensitive=False):
    if not consent:
        return {"availability": "unavailable", "reason": "consent_absent"}
    if sensitive:
        return {
            "availability": "unavailable",
            "reason": "sensitive_form_capture_not_supported",
        }
    if os.getenv("ENABLE_VISUAL") != "true":
        return {"availability": "unavailable", "reason": "disabled_provider"}
    if os.name != "posix":
        return {"availability": "unavailable", "reason": "isolated_linux_renderer_required"}
    try:
        completed = bounded_run(
            [sys.executable, "-m", "backend.app.visual", "--render"],
            data=html[:500000].encode(),
            timeout=8,
        )
        if len(completed) > 500000:
            return {"availability": "unavailable", "reason": "screenshot_size_limit"}
        result = json.loads(completed)
        return result
    except (OSError, subprocess.SubprocessError, ValueError):
        return {
            "availability": "unavailable",
            "reason": "renderer_unavailable_or_timeout",
        }


def render(html):
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, chromium_sandbox=True)
        try:
            context = browser.new_context(
                java_script_enabled=False,
                accept_downloads=False,
                service_workers="block",
                viewport={"width": 1280, "height": 720},
            )
            context.set_offline(True)
            context.route("**/*", lambda route: route.abort())
            page = context.new_page()
            page.set_content(html, wait_until="domcontentloaded", timeout=3000)
            screenshot = page.screenshot(type="png", full_page=False, timeout=3000)
            if len(screenshot) > 400000:
                raise ValueError("Capture too large")
            result = {
                "availability": "available",
                "capture_sha256": hashlib.sha256(screenshot).hexdigest(),
                "width": 1280,
                "height": 720,
                "retention": "image discarded after analysis",
                "method": "offline static HTML rendering",
                "limitations": [
                    "Remote images, styles and scripts are blocked. This is not a faithful live-page screenshot or validated visual phishing detection."
                ],
                "ocr": {
                    "availability": "unavailable",
                    "reason": "optional_tesseract_not_installed",
                },
            }
            try:
                import pytesseract
                from PIL import Image

                text = pytesseract.image_to_string(Image.open(io.BytesIO(screenshot)), timeout=2)[
                    :10000
                ].lower()
                # Store only catalog term matches, never complete OCR text.
                result["ocr"] = {
                    "availability": "available",
                    "engine": "tesseract",
                    "observed_brand_terms": [
                        v for v in ("google", "microsoft", "paypal", "apple", "amazon") if v in text
                    ],
                    "limitations": ["Text mentions do not establish identity or impersonation."],
                }
            except (ImportError, OSError, RuntimeError):
                pass
            return result
        finally:
            browser.close()


if __name__ == "__main__":
    print(json.dumps(render(sys.stdin.buffer.read(500001).decode("utf-8", errors="replace"))))
