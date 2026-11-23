export type User = { id: string; email: string; role: string };
export type Settings = { knowledge_level: string; history_enabled: boolean; ai_enabled: boolean; notifications_enabled: boolean; retention_days: number };
export type Evidence = { id: string; category: string; title: string; description: string; confidence?: number | null; severity: string; weight?: number; source?: string; observed_at?: string; created_at?: string; availability?: string; rule_version?: string };
export type Graph = { nodes: { id: string; type: string; label: string; source?: string; observed_at?: string }[]; edges: (string[] | { source: string; target: string; label?: string })[] };
export type Report = {
  id: string; url: string; hostname: string; status?: string; risk_score: number | null; classification: string; confidence: number | null;
  summary: string; recommendation: string; evidence: Evidence[]; events: { event_type: string; message: string; timestamp: string }[];
  created_at?: string; completed_at?: string; expires_at?: string; contract_version?: string; policy_version?: string; demo?: boolean; limitations?: string[];
  coverage?: { fraction?: number; url?: unknown; domain?: unknown; page?: unknown }; page_analysis?: Record<string, unknown>; domain_analysis?: Record<string, unknown>;
  digital_trust_profile?: { trust_state: string; overall_trust: number | null; state_reason: string; policy_version?: string; decision_evidence_ids?: string[] };
  identity_analysis?: Record<string, unknown>; privacy_assessment?: Record<string, unknown>; synthetic_web_analysis?: Record<string, unknown>; deceptive_claim_analysis?: Record<string, unknown>;
  download_safety?: Record<string, unknown>; campaign_similarity?: Record<string, unknown>; visual_analysis?: Record<string, unknown>; website_authenticity?: Record<string, unknown>;
  ml_prediction?: { availability?: string; reason?: string; model_name?: string; model_version?: string; raw_probability: number | null; calibrated_probability: number | null; calibration_method?: string; feature_contributions?: Record<string, number>; attribution_scale?: string };
  context_graph?: Graph; features?: Record<string, unknown>; ai_report?: Record<string, unknown>; safe_route?: string | null;
};
export type ResearchExperiment = { experiment_id: string; name?: string; model_name?: string; feature_groups?: string[]; accuracy?: number; precision?: number; recall?: number; f1?: number; roc_auc?: number; pr_auc?: number; false_positive_rate?: number; false_negative_rate?: number; brier_score?: number; inference_latency_ms?: number; release_gate?: string; split_support?: Record<string, number>; confidence_intervals?: Record<string, unknown>; precision_interval_95?: number[]; recall_interval_95?: number[]; fpr_interval_95?: number[]; support?: Record<string, number>; confusion_matrix?: Record<string, number> };
export type ResearchSuite = { experiments: ResearchExperiment[]; availability: string; benchmark_dataset_samples?: number | null; evaluated_at?: string | null; primary_model?: string | null; limitations?: string[] };
export type DemoScenario = { id: string; title: string; description: string };
export class ApiError extends Error { constructor(message: string, public status: number, public requestId?: string) { super(message); this.name = "ApiError"; } }
export const apiBase = () => process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
export const percent = (value: unknown) => typeof value === "number" && Number.isFinite(value) ? (value * 100).toFixed(1) + "%" : "Unavailable";
export function normalizeUrl(value: string) { const raw = value.trim(); const url = new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw); if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || !url.hostname.includes(".")) throw new Error("Enter a public HTTP(S) URL without embedded credentials."); return url.origin + "/"; }
export async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response;
  try { response = await fetch(apiBase() + path, { ...options, credentials: "include", cache: "no-store", signal: options.signal || AbortSignal.timeout(15000), headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } }); }
  catch (error) { if (options.signal?.aborted) throw error; throw new ApiError("The analysis service is unavailable. No safety result is being inferred.", 0); }
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload?.success) { const message = typeof payload?.error === "string" ? payload.error : payload?.error?.message || payload?.detail || "Request failed (" + response.status + ")."; throw new ApiError(typeof message === "string" ? message : "The request was rejected.", response.status, payload?.request_id || response.headers.get("X-Request-ID") || undefined); }
  return payload.data as T;
}
export const getSession = () => request<{ user: User }>("/api/v1/auth/session");
export const signIn = (email: string, password: string, register = false) => request<{ user: User }>("/api/v1/auth/" + (register ? "register" : "login"), { method: "POST", body: JSON.stringify({ email, password }) });
export const signOut = () => request("/api/v1/auth/logout", { method: "POST" });
export const getSettings = () => request<Settings>("/api/v1/settings");
export const saveSettings = (values: Settings) => request<Settings>("/api/v1/settings", { method: "PATCH", body: JSON.stringify(values) });
export const pairExtension = (extension_id: string) => request<{ code: string; expires_in: number }>("/api/v1/auth/pair", { method: "POST", body: JSON.stringify({ extension_id }) });
export const createInvestigation = (value: string, visualConsent = false) => request<{ id: string; status: string }>("/api/v1/investigations", { method: "POST", body: JSON.stringify({ url: normalizeUrl(value), context: { visual_consent: visualConsent } }) });
export const listInvestigations = (params: { limit?: number; offset?: number; q?: string; classification?: string; sort?: string } = {}) => request<Report[]>("/api/v1/investigations?" + new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== "ALL").map(([k, v]) => [k, String(v)])));
export const getReport = (id: string) => request<Report>("/api/v1/investigations/" + encodeURIComponent(id));
export const jobAction = (id: string, action: "cancel" | "retry" | "delete") => request("/api/v1/investigations/" + encodeURIComponent(id) + (action === "delete" ? "" : "/" + action), { method: action === "delete" ? "DELETE" : "POST" });
export async function downloadExport(id: string, format: "json" | "pdf") { const response = await fetch(apiBase() + "/api/v1/investigations/" + encodeURIComponent(id) + "/export?format=" + format, { credentials: "include", cache: "no-store", signal: AbortSignal.timeout(15000) }); if (!response.ok) throw new ApiError("Export unavailable (" + response.status + ").", response.status); const url = URL.createObjectURL(await response.blob()); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "m-phish-" + id + "." + format; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
export const getResearchExperiments = () => request<ResearchSuite>("/api/v1/research/experiments");
export const getDemoScenarios = () => request<DemoScenario[]>("/api/v1/demo/scenarios");
export const runDemo = (id: string) => request<Report>("/api/v1/demo/scenarios/" + encodeURIComponent(id), { method: "POST" });
