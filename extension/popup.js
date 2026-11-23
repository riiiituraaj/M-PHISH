"use strict";
(() => {
  // src/policy.ts
  var defaults = {
    protectionEnabled: true,
    protectionMode: "local",
    cloudConsent: false,
    automaticNotifications: true,
    showLowRisk: false,
    explanationLevel: "standard",
    backendUrl: "",
    dashboardUrl: "",
    exclusions: []
  };
  function originOnly(value) {
    if (typeof value !== "string" || value.length > 4096) return null;
    try {
      const url = new URL(value);
      return ["http:", "https:"].includes(url.protocol) && !url.username && !url.password ? `${url.origin}/` : null;
    } catch {
      return null;
    }
  }
  function backendOrigin(value) {
    try {
      const u = new URL(value);
      return !u.username && !u.password && !u.search && !u.hash && u.pathname === "/" && (u.protocol === "https:" || u.protocol === "http:" && ["localhost", "127.0.0.1"].includes(u.hostname)) ? u.origin : null;
    } catch {
      return null;
    }
  }
  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  }

  // src/popup.ts
  var root = document.getElementById("app");
  var tabId;
  var prefs = { ...defaults };
  var current = { availability: "unknown", message: "No current assessment." };
  var run = 0;
  function render() {
    const report = current.report;
    const evidence = Array.isArray(report?.evidence) ? report.evidence : current.evidence || [];
    const title = !prefs.protectionEnabled ? "Protection paused" : current.availability === "unavailable" ? "Protection unavailable" : current.availability === "pending" ? "Checking\u2026" : current.availability === "unknown" ? "No current assessment" : "Partial check";
    root.innerHTML = `<div class="popup"><header class="header"><div class="brand"><span class="brand-name">M-PHISH <b>X</b></span></div><button id="settings" class="text-action" type="button">Settings</button></header><div class="content"><section class="state"><h1>${escapeHtml(title)}</h1><p class="lede">${escapeHtml(!prefs.protectionEnabled ? "Navigation and interaction checks are paused." : current.message)}</p></section>${report ? `<div class="rows"><div class="row"><span class="row-label">Observed risk</span><span class="row-value">${escapeHtml(report.classification || "UNKNOWN")}</span></div><div class="row"><span class="row-label">Scanned</span><span class="row-value">${escapeHtml(report.created_at || report.scanned_at || "See report")}</span></div></div>` : ""}${prefs.protectionEnabled ? `<div class="actions"><button id="quick" class="button primary" type="button" ${tabId === void 0 ? "disabled" : ""}>Check current page</button><button id="deep" class="button ghost" type="button" ${tabId === void 0 || prefs.protectionMode === "local" || !prefs.cloudConsent ? "disabled" : ""}>Request deep investigation</button>${report?.id ? '<button id="report" class="button ghost" type="button">View full report</button>' : ""}</div>` : ""}${prefs.explanationLevel !== "simple" ? `<details><summary>Evidence and limitations (${evidence.length})</summary>${evidence.slice(0, prefs.explanationLevel === "technical" ? 20 : 6).map((e) => `<div class="evidence"><b>${escapeHtml(e.title)}</b><p>${escapeHtml(e.description)}</p>${prefs.explanationLevel === "technical" ? `<small>${escapeHtml(e.id)}</small>` : ""}</div>`).join("")}<p>Origins only; paths and queries are redacted. Unobserved content, frames and destinations remain unknown. This check does not certify safety or scan files for malware.</p></details>` : ""}<footer class="footer"><button id="toggle" class="text-action" type="button">${prefs.protectionEnabled ? "Pause" : "Resume"} protection</button><span class="footer-note">Mode: ${escapeHtml(prefs.protectionMode)}. No field values collected.</span></footer></div></div>`;
    document.getElementById("settings").onclick = () => chrome.runtime.openOptionsPage();
    document.getElementById("toggle").onclick = async () => {
      run++;
      await chrome.storage.local.set({ protectionEnabled: !prefs.protectionEnabled });
      await init();
    };
    document.getElementById("quick")?.addEventListener("click", () => void inspect(false));
    document.getElementById("deep")?.addEventListener("click", () => void inspect(true));
    document.getElementById("report")?.addEventListener("click", () => {
      const base = backendOrigin(prefs.dashboardUrl);
      if (base && report?.id) chrome.tabs.create({ url: `${base}/investigations/${encodeURIComponent(String(report.id))}` });
      else {
        current = { ...current, message: "Configure your owned dashboard origin in Settings." };
        render();
      }
    });
  }
  async function inspect(deep) {
    const sequence = ++run;
    current = { availability: "pending", message: "Waiting for the configured checks. Missing results are not a safety assurance." };
    render();
    try {
      const result = await chrome.runtime.sendMessage({ type: "inspect", tabId, deep });
      if (sequence === run) {
        current = result;
        render();
      }
    } catch {
      if (sequence === run) {
        current = { availability: "unavailable", message: "Protection unavailable. The extension could not complete this check." };
        render();
      }
    }
  }
  async function init() {
    prefs = { ...defaults, ...await chrome.storage.local.get(defaults) };
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    tabId = tab?.url && originOnly(tab.url) ? tab.id : void 0;
    current = tabId === void 0 ? { availability: "unknown", message: "Open an HTTP(S) page to inspect it." } : await chrome.runtime.sendMessage({ type: "status", tabId });
    render();
  }
  chrome.storage.onChanged.addListener((_changes, area) => {
    if (area === "local") void init();
  });
  void init();
})();
