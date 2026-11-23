export const VERSION = "evidence-v2";
export const defaults = {
  protectionEnabled: true, protectionMode: "local", cloudConsent: false,
  automaticNotifications: true, showLowRisk: false, explanationLevel: "standard",
  backendUrl: "", dashboardUrl: "", exclusions: [] as { origin: string; expires: number }[],
};
export type Settings = typeof defaults;
export type Observations = { consent: true; fields: string[]; form_actions: string[]; password_inputs: number; forms: number; frame_coverage: "top_frame_only"; page_fingerprint?: string };
export type Result = { availability: string; message: string; requires_intervention?: boolean; evidence?: { title?: string; description?: string; id?: string }[]; quick?: Record<string, unknown>; report?: Record<string, unknown>; [key: string]: unknown };
export function originOnly(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 4096) return null;
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password ? `${url.origin}/` : null; } catch { return null; }
}
export function backendOrigin(value: string): string | null {
  try { const u = new URL(value); return !u.username && !u.password && !u.search && !u.hash && u.pathname === "/" && (u.protocol === "https:" || (u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname))) ? u.origin : null; } catch { return null; }
}
export function excluded(url: string, settings: Settings): boolean {
  const origin = originOnly(url); return settings.exclusions.some(x => `${x.origin}/` === origin && x.expires > Date.now());
}
export function localCheck(value: string): Result {
  const url = originOnly(value); if (!url) return {availability: "unavailable", message: "Unsupported page."};
  const parsed = new URL(url); const reasons: string[] = [];
  if (parsed.protocol === "http:") reasons.push("This page uses unencrypted HTTP transport.");
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname)) reasons.push("The host is an IP address; this does not identify an organization.");
  if (parsed.hostname.includes("xn--")) reasons.push("The hostname uses internationalized encoding. Check its spelling carefully.");
  return {availability: "partial", message: reasons.length ? reasons.join(" ") : "No significant risk observed in the local URL checks completed. Page content and identity were not verified.", evidence: reasons.map((description,i)=>({id:`local-${i}`,title:"Local URL observation",description})), quick:{tier: reasons.length ? "MEDIUM" : "UNKNOWN", score: null, deep_required:true}};
}
export function cleanObservations(value: unknown): Observations | undefined {
  if (!value || typeof value !== "object") return;
  const v = value as Record<string, unknown>;
  if (v.consent !== true) return;
  const allowed = ["password","email","otp","card","phone","address","banking"];
  return {consent:true, fields: Array.isArray(v.fields) ? v.fields.filter(x=>typeof x === "string" && allowed.includes(x)).slice(0,7) : [], form_actions: Array.isArray(v.form_actions) ? [...new Set(v.form_actions.map(originOnly).filter((x):x is string=>!!x))].slice(0,12) : [], password_inputs: Math.max(0,Math.min(100,Math.floor(Number(v.password_inputs)||0))), forms:Math.max(0,Math.min(100,Math.floor(Number(v.forms)||0))), frame_coverage:"top_frame_only", page_fingerprint: typeof v.page_fingerprint === "string" ? v.page_fingerprint.slice(0,80) : undefined};
}
export function cleanAction(value: unknown): Record<string, unknown> {
  const v = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const result: Record<string, unknown> = {};
  for (const key of ["form_action","destination"]) { const url=originOnly(v[key]); if(url) result[key]=url; }
  if (v.is_executable === true) result.is_executable=true;
  if (Array.isArray(v.field_categories)) result.field_categories=v.field_categories.filter(x=>["password","email","otp","card","phone","address","banking"].includes(String(x))).slice(0,7);
  if(typeof v.page_fingerprint === "string") result.page_fingerprint=v.page_fingerprint.slice(0,80);
  return result;
}
export function escapeHtml(value: unknown): string { return String(value ?? "").replace(/[&<>"']/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]!)); }
