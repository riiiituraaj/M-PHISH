import asyncio
import ipaddress
import socket
from urllib.parse import urlparse


def _safe_host(value: str) -> bool:
    host = urlparse(value).hostname
    if not host or urlparse(value).scheme not in {"http", "https"}:
        return False
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(host)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved)
    except ValueError:
        try:
            addresses = socket.getaddrinfo(host, None)
            return all(not ipaddress.ip_address(item[4][0]).is_private and not ipaddress.ip_address(item[4][0]).is_loopback and not ipaddress.ip_address(item[4][0]).is_link_local for item in addresses)
        except socket.gaierror:
            return False


async def analyze(url: str, timeout_seconds: int = 15, max_redirects: int = 5, max_html_bytes: int = 1_000_000, max_requests: int = 100) -> dict:
    """Analyze a page without interaction. Intended for the restricted crawler image."""
    result = {"available": False, "title": "Unavailable", "forms": 0, "password_inputs": 0, "login_like": False, "external_form_action": False, "redirect_count": 0, "external_domain_count": 0, "screenshot": None, "error": None, "blocked_requests": 0, "request_count": 0}
    if not _safe_host(url):
        result["error"] = "Target rejected by crawler network policy"
        return result
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        result["error"] = "Playwright is not installed"
        return result
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, downloads_path=None)
            context = await browser.new_context(java_script_enabled=True, accept_downloads=False)
            page = await context.new_page()
            redirects = []
            external_domains = set()
            initial_host = urlparse(url).hostname
            blocked = 0
            requests = 0

            async def guard(route):
                nonlocal blocked, requests
                requests += 1
                target = route.request.url
                if requests > max_requests or not _safe_host(target):
                    blocked += 1
                    await route.abort("blockedbyclient")
                    return
                await route.continue_()

            await context.route("**/*", guard)
            page.on("request", lambda request: redirects.append(request.url) if request.is_navigation_request() and request.url != url else None)
            page.on("request", lambda request: external_domains.add(urlparse(request.url).hostname) if urlparse(request.url).hostname and urlparse(request.url).hostname != initial_host else None)
            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            if len(redirects) > max_redirects:
                await browser.close()
                result["error"] = "Redirect limit exceeded"
                return result
            html = (await page.content())[:max_html_bytes]
            result.update({"available": True, "title": await page.title() or "Unavailable", "forms": await page.locator("form").count(), "password_inputs": await page.locator('input[type="password"]').count(), "login_like": bool(await page.locator('input[type="password"]').count()) or any(term in html.lower() for term in ("sign in", "log in", "verify your account")), "external_form_action": any((urlparse(value).hostname or "") != initial_host for value in await page.locator("form").evaluate_all("forms => forms.map(form => form.action)")), "redirect_count": len(redirects), "external_domain_count": len(external_domains), "status_code": response.status if response else None, "blocked_requests": blocked, "request_count": requests})
            await browser.close()
    except Exception as error:
        result["error"] = type(error).__name__
    return result


def analyze_sync(url: str, timeout_seconds: int = 15, max_redirects: int = 5, max_requests: int = 100) -> dict:
    return asyncio.run(analyze(url, timeout_seconds, max_redirects, max_requests=max_requests))
