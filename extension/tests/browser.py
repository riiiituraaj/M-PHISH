"""Loaded MV3 tests against a controlled local fixture, never third-party websites.
Run: .venv/Scripts/python.exe extension/tests/browser.py
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import time
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "test-results"
OUT.mkdir(exist_ok=True)
requests = []
fixture = b'''<!doctype html><html><head><title>Controlled extension fixture</title></head><body><h1>Controlled test fixture</h1><p>Local fixture. No real credentials or downloads.</p><form action="/submitted" method="post"><label>Password <input type="password" name="password" value="TEST_VALUE_NEVER_COLLECT"></label><button type="submit">Sign in</button></form><a id="download" href="/sample.exe?token=TEST_PRIVATE_QUERY">Download fixture</a><script>window.submitted=0;window.downloaded=0;document.addEventListener('submit',e=>{e.preventDefault();window.submitted++});document.addEventListener('click',e=>{if(e.target.id==='download'){e.preventDefault();window.downloaded++}});</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path.startswith('/api/'):
            self.response({'success': True, 'data': {}})
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(fixture)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'content-type,authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        self.end_headers()

    def response(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))) or b'{}')
        requests.append({'path': self.path, 'body': body})
        if self.path.endswith('/pair/exchange'):
            self.response({'success': True, 'data': {'access_token': 'controlled-test-token', 'expires_in': 1800}})
        elif self.path.endswith('/quick-check'):
            self.response({'success': True, 'data': {'tier': 'UNKNOWN', 'deep_required': False, 'top_reasons': []}})
        elif self.path.endswith('/dynamic-trust/evaluate'):
            self.response({'success': True, 'data': {'requires_intervention': True, 'intervention_modal': {'message': 'Controlled observation: review the destination.'}}})
        else:
            self.response({'success': True, 'data': {}})


server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
base = f'http://127.0.0.1:{server.server_port}'
checks = []
try:
    with tempfile.TemporaryDirectory(prefix='m-phish-extension-') as profile, sync_playwright() as p:
        context = p.chromium.launch_persistent_context(profile, channel='chromium', headless=True, args=[f'--disable-extensions-except={ROOT}', f'--load-extension={ROOT}'])
        context.set_default_timeout(10000)
        worker = context.service_workers[0] if context.service_workers else context.wait_for_event('serviceworker')
        extension_id = worker.url.split('/')[2]
        options = context.new_page()
        options.goto(f'chrome-extension://{extension_id}/options.html')
        expect(options.get_by_role('heading', name='M-PHISH X settings')).to_be_visible()
        checks.append('real MV3 load and options rendering')
        page = context.new_page()
        page.goto(f'{base}/fixture?token=TEST_PRIVATE_QUERY')
        page.wait_for_timeout(250)
        page.get_by_role('button', name='Sign in', exact=True).click()
        expect(page.get_by_role('button', name='Continue once')).to_be_visible()
        assert page.evaluate('window.submitted') == 0
        page.get_by_role('button', name='Continue once').evaluate('(button) => button.click()')
        assert page.evaluate('window.submitted') == 0
        checks.append('page-script clicks cannot authorize the continue override')
        page.screenshot(path=str(OUT/'form-paused.png'), full_page=True)
        page.get_by_role('button', name='Continue once').click()
        assert page.evaluate('window.submitted') == 1
        assert page.locator('#m-phish-shield-root').count() == 0
        checks.append('native form paused synchronously and override resumes once')
        page.locator('#download').click()
        expect(page.get_by_role('button', name='Continue once')).to_be_visible()
        assert page.evaluate('window.downloaded') == 0
        page.get_by_role('button', name='Continue once').click()
        assert page.evaluate('window.downloaded') == 1
        checks.append('direct executable link paused and override resumes once')
        assert len(requests) == 0
        checks.append('local mode produces zero service traffic')
        await_settings = "async settings => {await chrome.storage.local.set(settings);return true}"
        worker.evaluate(await_settings, {'backendUrl': base, 'cloudConsent': True, 'protectionMode': 'standard'})
        options.reload()
        options.locator('#code').fill('controlled-pair-code')
        options.get_by_role('button', name='Pair', exact=True).click()
        expect(options.get_by_role('status')).to_contain_text('Paired for up to 30 minutes')
        checks.append('options pairing exchanges one-time code with controlled API')
        page.bring_to_front()
        page.wait_for_timeout(300)
        page.get_by_role('button', name='Sign in', exact=True).click()
        try:
            expect(page.get_by_text('Controlled observation: review the destination.').first).to_be_visible()
        except AssertionError:
            print('DIAGNOSTIC', page.locator('#m-phish-shield-root').evaluate('(r)=>r.shadowRoot.textContent') if page.locator('#m-phish-shield-root').count() else 'No warning', requests)
            raise
        page.get_by_role('button', name='Cancel action').click()
        assert any(x['path'].endswith('/dynamic-trust/evaluate') for x in requests)
        payloads = json.dumps(requests)
        assert 'TEST_VALUE_NEVER_COLLECT' not in payloads and 'TEST_PRIVATE_QUERY' not in payloads
        checks.append('real content-to-worker dynamic flow sends no input values or private queries')
        page.get_by_role('button', name='Sign in', exact=True).click()
        expect(page.get_by_role('button', name='Continue once')).to_be_visible()
        worker.evaluate(await_settings, {'protectionEnabled': False})
        expect(page.locator('#m-phish-shield-root')).to_have_count(0)
        before = len(requests)
        page.get_by_role('button', name='Sign in', exact=True).click()
        page.locator('#download').click()
        page.goto(f'{base}/fixture2')
        page.wait_for_timeout(2250)
        assert len(requests) == before
        checks.append('off switch removes pending warning and stops interaction/navigation traffic')
        options.reload()
        options.screenshot(path=str(OUT/'settings.png'), full_page=True)
        context.close()
finally:
    server.shutdown()
    (OUT/'browser-results.json').write_text(json.dumps({'checks':checks,'count':len(checks),'api':'controlled local substitute','loaded_extension':True,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2))
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
