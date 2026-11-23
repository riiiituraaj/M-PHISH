import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";
const source = await readFile(new URL("../lib/api.ts", import.meta.url), "utf8");
const javascript = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText;
const api = await import("data:text/javascript;base64," + Buffer.from(javascript).toString("base64"));

test("missing model outputs remain unavailable rather than 0%", () => {
  assert.equal(api.percent(null), "Unavailable");
  assert.equal(api.percent(undefined), "Unavailable");
  assert.equal(api.percent(NaN), "Unavailable");
  assert.equal(api.percent(0), "0.0%");
  assert.equal(api.percent(0.89), "89.0%");
});
test("URL normalization rejects credential URLs and non-public input", () => {
  assert.equal(api.normalizeUrl("example.com"), "https://example.com/");
  assert.equal(api.normalizeUrl("https://example.com/private?token=secret#fragment"), "https://example.com/");
  assert.throws(() => api.normalizeUrl("https://user:password@example.com/"));
  assert.throws(() => api.normalizeUrl("localhost"));
});
test("authenticated reads include cookies and prevent caching", async () => {
  let captured;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => { captured = { url, options }; return new Response(JSON.stringify({ success: true, data: { user: { id: "a", email: "a@example.com", role: "user" } } })); };
  try { const result = await api.getSession(); assert.equal(result.user.id, "a"); assert.equal(captured.options.credentials, "include"); assert.equal(captured.options.cache, "no-store"); assert.ok(captured.options.signal); } finally { globalThis.fetch = original; }
});
test("expired sessions preserve HTTP status and request correlation", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ success: false, error: { message: "Session expired." }, request_id: "req-test" }), { status: 401 });
  try { await assert.rejects(api.getReport("private"), error => error instanceof api.ApiError && error.status === 401 && error.requestId === "req-test"); } finally { globalThis.fetch = original; }
});
test("provider outage rejects instead of returning a reassuring report", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => { throw new TypeError("offline"); };
  try { await assert.rejects(api.getReport("private"), error => error instanceof api.ApiError && error.status === 0 && /unavailable/.test(error.message)); } finally { globalThis.fetch = original; }
});
test("explicit visual consent and pagination filters reach intended API routes", async () => {
  const captured = []; const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => { captured.push({ url, options }); return new Response(JSON.stringify({ success: true, data: [] })); };
  try { await api.createInvestigation("https://example.com", true); assert.equal(JSON.parse(captured[0].options.body).context.visual_consent, true); await api.listInvestigations({ limit: 20, offset: 40, q: "test & space", classification: "ALL" }); assert.match(captured[1].url, /offset=40/); assert.doesNotMatch(captured[1].url, /classification/); assert.equal(new URL(captured[1].url).searchParams.get("q"), "test & space"); } finally { globalThis.fetch = original; }
});
