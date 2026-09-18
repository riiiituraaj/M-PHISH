/**
 * M-PHISH X popup.
 *
 * Renders one of four states: paused, analysing, quick URL check, full report.
 */

type Evidence = {
  title: string;
  description: string;
  category: string;
  confidence: number;
  weight?: number;
};

type DigitalTrustProfile = {
  identity_trust: number;
  security_trust: number;
  content_trust: number;
  interaction_trust: number;
  privacy_trust: number;
  behavioral_trust: number;
  authenticity: number;
  overall_trust: number;
  trust_state: "TRUSTED" | "CAUTION" | "HIGH_RISK" | "STOP";
  state_reason: string;
};

type IdentityAnalysis = {
  claimed_service: string;
  current_website: string;
  credential_destination: string;
  identity_consistency: string;
  explanation: string;
  safe_route: string | null;
  is_impersonation_suspected: boolean;
};

type Report = {
  id: string;
  hostname: string;
  url: string;
  risk_score: number;
  classification: string;
  summary: string;
  recommendation: string;
  what_happened?: string;
  why_it_matters?: string;
  what_to_do?: string;
  evidence: Evidence[];
  digital_trust_profile?: DigitalTrustProfile;
  identity_analysis?: IdentityAnalysis;
  safe_route?: string | null;
};

type QuickCheck = {
  deep_required: boolean;
  tier: "LOW" | "MEDIUM" | "HIGH";
  score: number;
  top_reasons: string[];
  features?: Record<string, unknown>;
};

type Envelope<T> = { success: boolean; data: T; request_id: string };
type Job = { id: string; status: string };
type Tone = "trusted" | "caution" | "high-risk" | "stop";

const API_ENDPOINTS = ["https://m-phish.onrender.com", "http://localhost:8000"];
const DEFAULT_DASHBOARD = "https://m-phish.vercel.app";
const LOCAL_DASHBOARD = "http://localhost:3000";

const root = document.getElementById("app")!;

/** Backend base that answered last. */
let activeBase: string | null = null;
/** Optional dashboard override saved from the options page. */
let dashboardOverride: string | null = null;

const escape = (value: string) =>
  (value || "").replace(/[&<>"']/g, (c) => {
    const map: Record<string, string> = { "&": "&", "<": "<", ">": ">", '"': '"', "'": "'" };
    return map[c];
  });

const icon = (paths: string, size = 13) =>
  `<svg class="icon" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;

const ICON_EXTERNAL = icon(
  '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/>',
);
const ICON_CHEVRON = icon('<path d="m6 9 6 6 6-6"/>', 14);
const ICON_CHECK = icon('<path d="M20 6 9 17l-5-5"/>', 12);
const ICON_SHIELD = icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', 14);
const ICON_REFRESH = icon('<path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>', 13);
const ICON_SAFE = icon('<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="M22 4 12 14.01l-3-3"/>', 13);
const ICON_ALERT = icon('<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>', 14);

const TONE_TITLE: Record<Tone, string> = {
  trusted: "Looks trustworthy",
  caution: "Caution advised",
  "high-risk": "High risk detected",
  stop: "Stop before you continue",
};

const TONE_ICON: Record<Tone, string> = {
  trusted: ICON_CHECK,
  caution: ICON_ALERT,
  "high-risk": ICON_ALERT,
  stop: ICON_ALERT,
};

/** Dashboard base URL: saved override, else derived from the backend that answered. */
function dashboardBase() {
  if (dashboardOverride) return dashboardOverride.replace(/\/+$/, "");
  if (activeBase && activeBase.includes("localhost")) return LOCAL_DASHBOARD;
  return DEFAULT_DASHBOARD;
}

function openDashboard(path = "") {
  chrome.tabs.create({ url: `${dashboardBase()}${path}` });
}

function header() {
  return `
    <header class="header">
      <div class="brand">
        <span class="brand-mark">${ICON_SHIELD}</span>
        <span class="brand-name">M-PHISH <b>X</b></span>
      </div>
    </header>`;
}

function shell(body: string) {
  root.innerHTML = `<div class="popup">${header()}<div class="content">${body}</div></div>`;
}

function row(label: string, value: string, options?: { mono?: boolean }) {
  return `<div class="row"><span class="row-label">${escape(label)}</span><span class="row-value${
    options?.mono ? " mono" : ""
  }">${escape(value)}</span></div>`;
}

function scoreBlock(
  score: number,
  tone: Tone,
  pillLabel: string,
  caption: string,
) {
  const bounded = Math.max(0, Math.min(100, score));
  return `
    <section class="score">
      <div class="score-head">
        <span class="label">Digital trust score</span>
        <span class="pill ${tone}">${escape(pillLabel)}</span>
      </div>
      <div class="score-value"><strong>${bounded}</strong><span>/100</span></div>
      <div class="meter" role="img" aria-label="Trust score ${bounded} out of 100">
        <span class="meter-fill ${tone}" style="width:${Math.max(3, bounded)}%"></span>
      </div>
      <p class="score-caption">${escape(caption)}</p>
    </section>`;
}

function statusBanner(tone: Tone) {
  return `
    <div class="banner ${tone}">
      <span class="banner-dot" aria-hidden="true"></span>
      <b>${escape(TONE_TITLE[tone])}</b>
    </div>`;
}

function footer(protectionEnabled = true) {
  return `
    <footer class="footer">
      <button class="text-action" id="protection" type="button">
        ${protectionEnabled ? "Pause protection" : "Resume protection"}
      </button>
      <span class="footer-note">No passwords, cookies or keystrokes are read.</span>
    </footer>`;
}

function bindFooter(protectionEnabled = true) {
  const button = document.getElementById("protection");
  if (button) button.onclick = () => setProtection(!protectionEnabled);
}

function renderOff() {
  shell(`
    <section class="state">
      <span class="state-icon">${ICON_SHIELD}</span>
      <h1>Protection is paused</h1>
      <p class="lede">M-PHISH X is not reviewing the sites you visit. Nothing is being analysed or stored.</p>
    </section>
    <div class="actions">
      <button class="button primary" id="resume" type="button">Resume protection</button>
    </div>
    ${footer(false)}`);
  document.getElementById("resume")!.onclick = () => setProtection(true);
  bindFooter(false);
}

function setProtection(enabled: boolean) {
  chrome.storage.local.set({ protectionEnabled: enabled }).then(init);
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let lastError: Error | null = null;
  for (const base of API_ENDPOINTS) {
    try {
      const response = await fetch(`${base}${path}`, options);
      if (response.ok) {
        activeBase = base;
        return ((await response.json()) as Envelope<T>).data;
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
    }
  }
  throw lastError || new Error("The analysis service is unreachable.");
}

function hostOf(url: string) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function renderLoading(host: string) {
  shell(`
    <div class="loading">
      <span class="spinner" aria-hidden="true"></span>
      <div>
        <p class="loading-title">Analysing ${escape(host)}</p>
        <p class="loading-note">Checking identity, page signals and behaviour.</p>
      </div>
    </div>
    <div class="skeleton" aria-hidden="true">
      <span class="skeleton-line w80"></span>
      <span class="skeleton-line w60"></span>
      <span class="skeleton-line w40"></span>
    </div>`);
}

async function checkCurrent(tabId: number, url: string) {
  renderLoading(hostOf(url));
  try {
    const quick = await request<QuickCheck>("/api/v1/quick-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, context: { tab_id: tabId } }),
    });
    if (!quick.deep_required) {
      renderReady(url, quick);
      return;
    }
    const job = await request<Job>("/api/v1/investigations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, context: { tab_id: tabId } }),
    });
    for (let attempt = 0; attempt < 40; attempt++) {
      const status = await request<Report & { status: string }>(
        `/api/v1/investigations/${encodeURIComponent(job.id)}`,
      );
      if (status.status === "COMPLETED") {
        showReport(status);
        return;
      }
      if (status.status === "FAILED") throw new Error("The investigation did not complete.");
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error("The investigation timed out.");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Service unreachable.";
    renderError(message, () => checkCurrent(tabId, url));
  }
}

function renderError(message: string, retry: () => void) {
  shell(`
    <section class="state">
      <span class="state-icon">${ICON_ALERT}</span>
      <h1>No result yet</h1>
      <p class="lede">${escape(message)}</p>
      <p class="lede subtle">Confirm the M-PHISH X backend is running, then try again.</p>
    </section>
    <div class="actions">
      <button class="button primary" id="retry" type="button">
        ${ICON_REFRESH} Try again
      </button>
    </div>
    ${footer()}`);
  document.getElementById("retry")!.onclick = retry;
  bindFooter();
}

function renderReady(url: string, quick: QuickCheck) {
  const host = hostOf(url);
  const trustScore = Math.max(0, Math.min(100, 100 - quick.score));
  const tone: Tone =
    quick.tier === "LOW" ? "trusted" : quick.tier === "MEDIUM" ? "caution" : "high-risk";
  const signals = quick.top_reasons.length
    ? quick.top_reasons
        .map((reason) => `<div class="evidence"><b>${escape(reason)}</b><span>URL signal</span></div>`)
        .join("")
    : `<div class="evidence"><b>No suspicious URL signals</b><span>URL analysis</span></div>`;

  shell(`
    ${statusBanner(tone)}
    <div class="target">
      <p class="target-host">${escape(host)}</p>
      <p class="target-url">${escape(url)}</p>
    </div>

    ${scoreBlock(
      trustScore,
      tone,
      quick.tier,
      "URL signals only. Run a full investigation to weigh page, identity and behaviour evidence.",
    )}

    <div class="rows">
      ${row("URL risk", `${quick.score} / 100`)}
      ${row("Signals raised", String(quick.top_reasons.length))}
      ${row("Analysis", "Quick URL check")}
    </div>

    <div class="actions">
      <button class="button primary" id="check" type="button">Run full investigation</button>
      <button class="button ghost" id="view-signals" type="button">View details</button>
    </div>

    ${disclosure("quick-signals", "URL signals", `<div class="evidence-list">${signals}</div>`)}

    ${footer()}`);

  document.getElementById("check")!.onclick = async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const current = tabs[0];
    if (current?.id && current.url && /^https?:/i.test(current.url))
      await checkCurrent(current.id, current.url);
  };
  document.getElementById("view-signals")!.onclick = () => {
    const toggle = document.getElementById("quick-signals");
    const panel = document.getElementById("quick-signals-panel");
    if (toggle && panel) {
      const open = panel.hasAttribute("hidden");
      if (open) {
        panel.removeAttribute("hidden");
        toggle.setAttribute("aria-expanded", "true");
        toggle.classList.add("open");
      }
    }
  };
  bindDisclosure("quick-signals");
  bindFooter();
}

function toneOf(state: string): Tone {
  if (state === "STOP") return "stop";
  if (state === "HIGH_RISK") return "high-risk";
  if (state === "CAUTION") return "caution";
  return "trusted";
}

function showReport(report: Report) {
  const profile = report.digital_trust_profile;
  const identity = report.identity_analysis;
  const trustState = profile?.trust_state || (report.risk_score >= 50 ? "STOP" : "CAUTION");
  const overallTrust = profile ? profile.overall_trust : Math.max(10, 100 - report.risk_score);
  const tone = toneOf(trustState);

  const identityRows = identity
    ? `<section class="card">
         <div class="card-head">
           <span class="label">Who am I giving this to?</span>
           <span class="pill ${identity.identity_consistency === "HIGH" ? "trusted" : tone}">${escape(
             identity.identity_consistency,
           )}</span>
         </div>
         <div class="rows">
           ${row("Claimed service", identity.claimed_service || "Not stated")}
           ${row("Current host", identity.current_website || report.hostname, { mono: true })}
           ${row("Data destination", identity.credential_destination || "Not detected", { mono: true })}
         </div>
         ${identity.explanation ? `<p class="card-note">${escape(identity.explanation)}</p>` : ""}
       </section>`
    : "";

  const safeRoute = report.safe_route || identity?.safe_route || null;
  const safeRouteButton = safeRoute
    ? `<a class="button safe" href="${escape(safeRoute)}" target="_blank" rel="noopener noreferrer">
         ${ICON_SAFE} Open official site
       </a>`
    : "";

  const evidence = report.evidence.length
    ? report.evidence
        .slice(0, 6)
        .map(
          (item) => `
          <div class="evidence">
            <b>${escape(item.title)}</b>
            <span>${escape(item.category)} · ${Math.round(item.confidence * 100)}% confidence</span>
            <p>${escape(item.description)}</p>
          </div>`,
        )
        .join("")
    : `<div class="evidence"><b>No anomalous evidence recorded</b><span>Engine output</span></div>`;

  shell(`
    ${statusBanner(tone)}
    <div class="target">
      <p class="target-host">${escape(report.hostname)}</p>
      <p class="target-url">${escape(report.url)}</p>
    </div>

    ${scoreBlock(
      overallTrust,
      tone,
      trustState.replace("_", " "),
      profile?.state_reason || report.recommendation,
    )}

    ${identityRows}

    <section class="card">
      <span class="label">What happened</span>
      <p class="card-note">${escape(report.what_happened || report.summary)}</p>
    </section>

    <div class="actions">
      ${safeRouteButton}
      <button class="button primary" id="full-report" type="button">
        ${ICON_EXTERNAL} View full report on dashboard
      </button>
      <button class="button ghost" id="refresh" type="button">
        ${ICON_REFRESH} Re-check this page
      </button>
    </div>

    ${disclosure(
      "report-details",
      `Evidence and next steps (${report.evidence.length})`,
      `<div class="recommendation">${escape(report.what_to_do || report.recommendation)}</div>
       <div class="evidence-list">${evidence}</div>
       <p class="target-url mono">${escape(report.id)}</p>`,
    )}

    ${footer()}`);

  document.getElementById("full-report")!.onclick = () =>
    openDashboard(`/investigations/${encodeURIComponent(report.id)}`);
  document.getElementById("refresh")!.onclick = async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const current = tabs[0];
    if (current?.id && current.url && /^https?:/i.test(current.url))
      await checkCurrent(current.id, current.url);
  };
  bindDisclosure("report-details");
  bindFooter();
}

async function init() {
  const settings = await chrome.storage.local.get(["protectionEnabled", "dashboardUrl"]);

  dashboardOverride =
    typeof settings.dashboardUrl === "string" && settings.dashboardUrl.trim()
      ? settings.dashboardUrl.trim()
      : null;

  if (settings.protectionEnabled === false) {
    renderOff();
    return;
  }

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
    shell(`
      <section class="state">
        <span class="state-icon">${ICON_CHECK}</span>
        <h1>Open a website to inspect it</h1>
        <p class="lede">This tab is not a regular web page, so there is nothing to analyse yet.</p>
      </section>
      <div class="actions">
        <button class="button primary" id="refresh" type="button">
          ${ICON_REFRESH} Re-check
        </button>
      </div>
      ${footer()}`);
    document.getElementById("refresh")!.onclick = init;
    bindFooter();
    return;
  }

  const saved = await chrome.storage.local.get(`report:${tab.id}`);
  if (saved[`report:${tab.id}`]) {
    showReport(saved[`report:${tab.id}`] as Report);
  } else {
    await checkCurrent(tab.id, tab.url);
  }
}

init();

function disclosure(id: string, label: string, content: string) {
  return `
    <button class="disclosure-toggle" id="${id}" type="button" aria-expanded="false" aria-controls="${id}-panel">
      <span>${escape(label)}</span>${ICON_CHEVRON}
    </button>
    <section class="disclosure" id="${id}-panel" hidden>${content}</section>`;
}

function bindDisclosure(id: string) {
  const toggle = document.getElementById(id);
  const panel = document.getElementById(`${id}-panel`);
  if (!toggle || !panel) return;
  toggle.onclick = () => {
    const open = panel.hasAttribute("hidden");
    if (open) panel.removeAttribute("hidden");
    else panel.setAttribute("hidden", "");
    toggle.setAttribute("aria-expanded", String(open));
    toggle.classList.toggle("open", open);
  };
}