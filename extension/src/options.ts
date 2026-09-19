/// <reference path="./chrome.d.ts" />
/**
 * M-PHISH X options page.
 *
 * Full-tab settings surface: protection toggles, explanation depth,
 * and dashboard address used by the popup's "View full report" button.
 */

type Preferences = {
  protectionEnabled: boolean;
  automaticNotifications: boolean;
  showLowRisk: boolean;
  explanationLevel: string;
  dashboardUrl: string;
  apiEndpoint: string;
  apiKey: string;
};

const defaults: Preferences = {
  protectionEnabled: true,
  automaticNotifications: true,
  showLowRisk: false,
  explanationLevel: "standard",
  dashboardUrl: "",
  apiEndpoint: "https://m-phish.onrender.com",
  apiKey: "",
};

const root = document.getElementById("options")!;

const htmlEscape = (value: string) =>
  (value || "").replace(/[&<>"']/g, (c) => {
    const map: Record<string, string> = { "&": "&", "<": "<", ">": ">", '"': '"', "'": "'" };
    return map[c];
  });

const icon = (paths: string, size = 13) =>
  `<svg class="icon" viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;

const ICON_SHIELD = icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', 16);

const toggle = (
  id: string,
  checked: boolean,
  title: string,
  hint: string,
) => `
  <label class="toggle-row">
    <span class="toggle-copy"><b>${htmlEscape(title)}</b><small>${htmlEscape(hint)}</small></span>
    <span class="switch">
      <input id="${id}" type="checkbox" ${checked ? "checked" : ""} />
      <span class="switch-track"></span>
    </span>
  </label>`;

function render(value: Partial<Preferences>) {
  const prefs: Preferences = { ...defaults, ...value };

  root.innerHTML = `
    <div class="options-page">
      <header class="options-header">
        <div>
          <h1 class="options-title">M-PHISH <b style="color:var(--accent)">X</b> settings</h1>
          <p class="options-sub">Control how the extension watches the pages you open.</p>
        </div>
        <span class="brand-mark" style="width:36px;height:36px;border-radius:10px;">${ICON_SHIELD}</span>
      </header>

      <section class="section">
        <div class="section-head">
          <span class="label">Protection</span>
          <h2>Monitoring</h2>
          <p>Choose what the extension reviews while you browse.</p>
        </div>
        ${toggle(
          "protection",
          prefs.protectionEnabled,
          "Enable protection",
          "Check top-level HTTP and HTTPS navigation as pages load.",
        )}
        ${toggle(
          "notifications",
          prefs.automaticNotifications,
          "Desktop notifications",
          "Show a system notification when a page needs review.",
        )}
        ${toggle(
          "lowrisk",
          prefs.showLowRisk,
          "Show low-risk status",
          "Display a badge on ordinary pages instead of staying silent.",
        )}
      </section>

      <section class="section">
        <div class="section-head">
          <span class="label">Explanation</span>
          <h2>Level of detail</h2>
          <p>How much reasoning the extension surfaces alongside a verdict.</p>
        </div>
        <div class="field">
          <label for="level">Explanation level</label>
          <select id="level">
            <option value="simple" ${prefs.explanationLevel === "simple" ? "selected" : ""}>Simple — one clear recommendation</option>
            <option value="standard" ${prefs.explanationLevel === "standard" ? "selected" : ""}>Standard — evidence with confidence</option>
            <option value="technical" ${prefs.explanationLevel === "technical" ? "selected" : ""}>Technical — full forensic detail</option>
          </select>
          <span class="field-hint">Verdicts and scores stay identical at every level.</span>
        </div>
      </section>

      <section class="section">
        <div class="section-head">
          <span class="label">Analysis service</span>
          <h2>Backend connection</h2>
          <p>Use the hosted API by default, or point the extension at a local/private deployment.</p>
        </div>
        <div class="field">
          <label for="apiEndpoint">API address</label>
          <input id="apiEndpoint" type="url" inputmode="url" spellcheck="false" value="${htmlEscape(prefs.apiEndpoint)}" />
          <span class="field-hint">The extension sends analysis requests only to this configured origin.</span>
        </div>
        <div class="field">
          <label for="apiKey">API key <span style="opacity:.65">(optional)</span></label>
          <input id="apiKey" type="password" autocomplete="off" spellcheck="false" value="${htmlEscape(prefs.apiKey)}" />
          <span class="field-hint">Only use a key intended for browser clients. Do not store privileged server credentials here.</span>
        </div>
      </section>

      <section class="section">
        <div class="section-head">
          <span class="label">Dashboard</span>
          <h2>Report destination</h2>
          <p>The "View full report" button opens investigations in this dashboard.</p>
        </div>
        <div class="field">
          <label for="dashboard">Dashboard address</label>
          <input
            id="dashboard"
            type="url"
            inputmode="url"
            spellcheck="false"
            placeholder="https://m-phish.vercel.app"
            value="${htmlEscape(prefs.dashboardUrl)}"
          />
          <span class="field-hint">Leave empty to detect automatically: a local backend links to localhost:3000, otherwise the hosted dashboard is used.</span>
        </div>
      </section>

      <div class="options-actions">
        <button class="button primary" id="save" type="button">Save settings</button>
        <button class="button ghost" id="reset" type="button">Reset to defaults</button>
      </div>
      <div id="saved" class="save-state" role="status" aria-live="polite"></div>
      <p class="privacy-note">
        M-PHISH X never reads passwords, cookies, keystrokes or clipboard data.
      </p>
    </div>`;

  const read = (id: string) =>
    (document.getElementById(id) as HTMLInputElement).checked;
  const readValue = (id: string) =>
    (document.getElementById(id) as HTMLInputElement | HTMLSelectElement).value;
  const status = document.getElementById("saved")!;

  const collect = (): Preferences => ({
    protectionEnabled: read("protection"),
    automaticNotifications: read("notifications"),
    showLowRisk: read("lowrisk"),
    explanationLevel: readValue("level"),
    dashboardUrl: readValue("dashboard").trim(),
    apiEndpoint: readValue("apiEndpoint").trim(),
    apiKey: readValue("apiKey"),
  });

  document.getElementById("save")!.onclick = async () => {
    await chrome.storage.local.set(collect());
    status.textContent = "Settings saved";
    window.setTimeout(() => (status.textContent = ""), 2400);
  };
  document.getElementById("reset")!.onclick = async () => {
    await chrome.storage.local.set(defaults);
    render(defaults);
    document.getElementById("saved")!.textContent = "Defaults restored";
  };
}

chrome.storage.local.get(Object.keys(defaults)).then(render);