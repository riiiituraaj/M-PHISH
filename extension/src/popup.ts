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

const API_ENDPOINTS = ["https://m-phish.onrender.com", "http://localhost:8000"];
const DASHBOARD_URL = "https://m-phish.vercel.app";
const root = document.getElementById("app")!;

const escape = (value: string) =>
  (value || "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );

function shell(body: string) {
  root.innerHTML = `<div class="card"><div class="topbar"><div class="brand"><img src="icon.svg" alt=""><span>M-PHISH <b>X</b></span></div><button class="dashboard-link" id="dashboard" type="button">Dashboard <span aria-hidden="true">↗</span></button></div>${body}</div>`;
  document.getElementById("dashboard")!.onclick = () => {
    chrome.tabs.create({ url: DASHBOARD_URL });
  };
}

function renderOff() {
  shell(
    '<div class="eyebrow">Protection is off</div><p class="summary">M-PHISH X is not monitoring browser navigation.</p><button class="button" id="toggle">Turn On</button>',
  );
  document.getElementById("toggle")!.onclick = () => setProtection(true);
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
        return ((await response.json()) as Envelope<T>).data;
      }
    } catch (e) {
      lastError = e instanceof Error ? e : new Error(String(e));
    }
  }
  throw lastError || new Error("Backend connection failed.");
}

async function checkCurrent(tabId: number, url: string) {
  shell(
    '<div class="progress"><b>●</b> Digital Identity<br><b>●</b> Website Authenticity<br><b>●</b> Behavior & Privacy<br><span>○</span> Digital Trust Profile</div>',
  );
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
      if (status.status === "FAILED") throw new Error("Investigation failed");
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error("Investigation timed out");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Service unreachable";
    shell(
      `<p class="summary">${escape(message)}. Confirm the M-PHISH X backend is running.</p><button class="button secondary" id="retry">Try again</button>`,
    );
    document.getElementById("retry")!.onclick = () => checkCurrent(tabId, url);
  }
}

function renderReady(url: string, quick: QuickCheck) {
  const host = new URL(url).hostname;
  const trustScore = Math.max(0, Math.min(100, 100 - quick.score));
  const state = quick.tier === "LOW" ? "trusted" : quick.tier === "MEDIUM" ? "caution" : "high-risk";
  const stateTitle = quick.tier === "LOW" ? "Website appears trustworthy" : quick.tier === "MEDIUM" ? "CAUTION ADVISED" : "HIGH RISK DETECTED";
  const dot = quick.tier === "LOW" ? "green" : quick.tier === "MEDIUM" ? "amber" : "orange";
  const reasons = quick.top_reasons.length
    ? quick.top_reasons.map((reason) => `<div class="detail"><b>${escape(reason)}</b><span>URL signal</span></div>`).join("")
    : `<div class="detail"><b>No suspicious URL signals detected</b><span>URL analysis</span></div>`;
  shell(
    `<div class="state-banner ${state}"><span class="dot ${dot}"></span> ${escape(stateTitle)}</div>` +
    `<div class="host">${escape(host)}</div>` +
    `<div class="trust-score-row"><div><span class="trust-label">Digital Trust</span><div class="trust-val">${trustScore}<small> / 100</small></div></div><span class="trust-pill ${state}">${escape(quick.tier)}</span></div>` +
    `<div class="trust-grid">` +
    `<div class="trust-dim"><span>URL risk</span><b>${quick.score}/100</b></div>` +
    `<div class="trust-dim"><span>Signals</span><b>${quick.top_reasons.length}</b></div>` +
    `<div class="trust-dim"><span>Analysis</span><b>Quick</b></div>` +
    `<div class="trust-dim"><span>Deep scan</span><b>Available</b></div>` +
    `</div>` +
    `<div class="btn-group"><button class="button" id="check">Run Full Investigation</button><button class="button secondary" id="quick-details" aria-expanded="false">View Details</button></div>` +
    `<section class="details" id="quick-report-details" hidden><h2>URL Analysis</h2>${reasons}<div class="detail-url">${escape(url)}</div></section>` +
    `<button class="button secondary" id="toggle">Turn Off Protection</button>`,
  );
  document.getElementById("check")!.onclick = async () => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const current = tabs[0];
    if (current?.id && current.url && /^https?:/i.test(current.url))
      await checkCurrent(current.id, current.url);
  };
  document.getElementById("quick-details")!.onclick = () => {
    const details = document.getElementById("quick-report-details")!;
    const button = document.getElementById("quick-details")!;
    const hidden = details.hasAttribute("hidden");
    if (hidden) details.removeAttribute("hidden");
    else details.setAttribute("hidden", "");
    button.setAttribute("aria-expanded", String(hidden));
    button.textContent = hidden ? "Hide Details" : "View Details";
  };
  document.getElementById("toggle")!.onclick = () => setProtection(false);
}

function showReport(report: Report) {
  const profile = report.digital_trust_profile;
  const identity = report.identity_analysis;
  const trustState = profile?.trust_state || (report.risk_score >= 50 ? "STOP" : "CAUTION");
  const overallTrust = profile ? profile.overall_trust : Math.max(10, 100 - report.risk_score);

  let stateBannerClass = "trusted";
  let stateTitle = "Website appears trustworthy";
  let stateDot = "green";

  if (trustState === "STOP") {
    stateBannerClass = "stop";
    stateTitle = "STOP BEFORE YOU ENTER";
    stateDot = "red";
  } else if (trustState === "HIGH_RISK") {
    stateBannerClass = "high-risk";
    stateTitle = "HIGH RISK DETECTED";
    stateDot = "orange";
  } else if (trustState === "CAUTION") {
    stateBannerClass = "caution";
    stateTitle = "CAUTION ADVISED";
    stateDot = "amber";
  }

  const identityHtml = identity
    ? `
      <div class="identity-box">
        <div class="identity-header">WHO AM I GIVING THIS TO?</div>
        <div class="identity-row"><span>Claimed Service</span><b>${escape(identity.claimed_service)}</b></div>
        <div class="identity-row"><span>Current Host</span><code>${escape(identity.current_website)}</code></div>
        <div class="identity-row"><span>Data Destination</span><code>${escape(identity.credential_destination)}</code></div>
        <div class="identity-row"><span>Consistency</span><b class="consist-${identity.identity_consistency.toLowerCase()}">${escape(identity.identity_consistency)}</b></div>
      </div>
    `
    : "";

  const safeRouteHtml = report.safe_route
    ? `<a class="button action-safe" href="${escape(report.safe_route)}" target="_blank">Open Verified Official Site</a>`
    : "";

  shell(`
    <div class="state-banner ${stateBannerClass}">
      <span class="dot ${stateDot}"></span>
      <b>${escape(stateTitle)}</b>
    </div>
    <div class="host">${escape(report.hostname)}</div>

    <div class="trust-score-row">
      <div>
        <span class="trust-label">Digital Trust Score</span>
        <div class="trust-val">${overallTrust}<small> / 100</small></div>
      </div>
      <span class="trust-pill ${stateBannerClass}">${escape(trustState.replace("_", " "))}</span>
    </div>

    ${identityHtml}

    <p class="summary">${escape(report.what_happened || report.summary)}</p>

    ${safeRouteHtml}

    <div class="btn-group">
      <button class="button secondary" id="why" aria-expanded="false">View Details</button>
      <button class="button secondary" id="full">Full Report in Dashboard</button>
    </div>

    <section class="details" id="details" hidden>
      <h2>What Should I Do?</h2>
      <div class="recommendation">
        <p>${escape(report.what_to_do || report.recommendation)}</p>
      </div>

      <h2>Evidence Attribution</h2>
      ${report.evidence
        .slice(0, 5)
        .map(
          (e) =>
            `<div class="detail"><b>${escape(e.title)}</b><span>${escape(e.category)} · ${Math.round(e.confidence * 100)}% confidence</span><p>${escape(e.description)}</p></div>`,
        )
        .join("")}
      <div class="detail-url">${escape(report.url)}</div>
    </section>
  `);

  document.getElementById("full")!.onclick = () => {
    chrome.tabs.create({
      url: `${DASHBOARD_URL}/investigations/${encodeURIComponent(report.id)}`,
    });
  };

  document.getElementById("why")!.onclick = () => {
    const details = document.getElementById("details")!;
    const button = document.getElementById("why")!;
    const hidden = details.hasAttribute("hidden");
    if (hidden) details.removeAttribute("hidden");
    else details.setAttribute("hidden", "");
    button.setAttribute("aria-expanded", String(hidden));
    button.textContent = hidden ? "Hide Details" : "View Details";
  };
}

async function init() {
  const settings = await chrome.storage.local.get(["protectionEnabled"]);
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (settings.protectionEnabled === false) {
    renderOff();
    return;
  }
  if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
    shell('<p class="summary">Open a regular website to inspect with M-PHISH X.</p>');
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
