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

  // src/options.ts
  var root = document.getElementById("options");
  async function render() {
    const p = { ...defaults, ...await chrome.storage.local.get(defaults) };
    const { auth } = await chrome.storage.session.get("auth");
    root.innerHTML = `<div class="options-page"><header class="options-header"><h1>M-PHISH X settings</h1></header><section class="section"><h2>Privacy and protection</h2><p>Local checks are the default. Cloud modes send page origin, requested field categories and destination origins to the service you choose. Paths, queries, fragments, field values, cookies, clipboard and keystrokes are never sent. Origin-only checks have limited coverage.</p><label class="toggle-row">Enable protection <input id="enabled" type="checkbox" ${p.protectionEnabled ? "checked" : ""}></label><div class="field"><label for="mode">Mode</label><select id="mode"><option value="local">Local URL checks \u2014 no cloud traffic</option><option value="standard">Standard \u2014 cloud URL and interaction checks</option><option value="deep">Deep \u2014 automatically queue deeper checks</option></select></div><label class="toggle-row">I consent to sending these minimized observations to my configured service <input id="consent" type="checkbox" ${p.cloudConsent ? "checked" : ""}></label><label class="toggle-row">Desktop warnings <input id="notifications" type="checkbox" ${p.automaticNotifications ? "checked" : ""}></label><label class="toggle-row">Show partial-check badge <input id="badge" type="checkbox" ${p.showLowRisk ? "checked" : ""}></label><div class="field"><label for="level">Explanation detail</label><select id="level"><option value="simple">Simple</option><option value="standard">Standard</option><option value="technical">Technical</option></select></div></section><section class="section"><h2>Connect your service</h2><p>Only configure a service you trust. Its operator receives the observations described above. HTTPS is required except for localhost development. Changing the service clears pairing.</p><div class="field"><label for="backend">API origin</label><input type="url" id="backend" value="${escapeHtml(p.backendUrl)}" placeholder="https://your-owned-api.example"></div><div class="field"><label for="dashboard">Dashboard origin</label><input type="url" id="dashboard" value="${escapeHtml(p.dashboardUrl)}" placeholder="https://your-owned-dashboard.example"></div><button id="save" class="button primary" type="button">Save settings</button><p>Extension ID: <code>${escapeHtml(chrome.runtime.id)}</code></p><p>Ask your service administrator to allow this exact extension ID, then generate a five-minute pairing code in your signed-in dashboard settings.</p><div class="field"><label for="code">One-time pairing code</label><input id="code" autocomplete="off" spellcheck="false"></div><button id="pair" class="button" type="button">Pair</button><button id="logout" class="button ghost" type="button">Revoke pairing</button><p>${auth?.expires > Date.now() ? "Session paired; expires within 30 minutes." : "Not paired. Local checks remain available."}</p></section><section class="section"><h2>Temporary exclusions</h2><p>Exclude an exact origin for one hour. This stops checks and warnings for that origin. Dismissing a warning never creates an exclusion.</p><div class="field"><label for="exclude">Origin to exclude</label><input id="exclude" type="url" placeholder="https://example.com"></div><button id="add" class="button" type="button">Exclude for one hour</button><ul>${p.exclusions.filter((x) => x.expires > Date.now()).map((x) => `<li>${escapeHtml(x.origin)} \u2014 expires ${escapeHtml(new Date(x.expires).toLocaleTimeString())}</li>`).join("")}</ul><button id="clear" class="button ghost" type="button">Clear exclusions</button></section><p id="status" role="status" aria-live="polite"></p><p>Supported interventions: top-frame native sensitive form submissions and direct executable links. JavaScript data transfers, all frames, and all downloads cannot be blocked universally. Disable with the switch above, or uninstall from chrome://extensions.</p></div>`;
    document.getElementById("mode").value = p.protectionMode;
    document.getElementById("level").value = p.explanationLevel;
    const value = (id) => document.getElementById(id).value.trim();
    const checked = (id) => document.getElementById(id).checked;
    const status = (text) => {
      document.getElementById("status").textContent = text;
    };
    document.getElementById("save").onclick = async () => {
      const base = value("backend") ? backendOrigin(value("backend")) : "";
      const dashboard = value("dashboard") ? backendOrigin(value("dashboard")) : "";
      if (base === null || dashboard === null) {
        status("Use an HTTPS origin with no path or credentials, or localhost HTTP for development.");
        return;
      }
      if (value("mode") !== "local" && (!checked("consent") || !base)) {
        status("Cloud modes need an explicit consent check and a service origin.");
        return;
      }
      if (base && !await chrome.permissions.request({ origins: [`${base}/*`] })) {
        status("Service permission was declined.");
        return;
      }
      await chrome.storage.local.set({ protectionEnabled: checked("enabled"), protectionMode: value("mode"), cloudConsent: checked("consent"), backendUrl: base, dashboardUrl: dashboard, automaticNotifications: checked("notifications"), showLowRisk: checked("badge"), explanationLevel: value("level") });
      status("Settings saved.");
    };
    document.getElementById("pair").onclick = async () => {
      const code = value("code");
      document.getElementById("code").value = "";
      try {
        const result = await chrome.runtime.sendMessage({ type: "pair", code });
        status(result.message);
      } catch {
        status("Pairing failed. Check the saved service and allowed extension ID.");
      }
    };
    document.getElementById("logout").onclick = async () => {
      const result = await chrome.runtime.sendMessage({ type: "logout" });
      status(result.message);
    };
    document.getElementById("add").onclick = async () => {
      const origin = backendOrigin(value("exclude"));
      if (!origin) {
        status("Enter an exact HTTPS origin.");
        return;
      }
      await chrome.storage.local.set({ exclusions: [...p.exclusions.filter((x) => x.expires > Date.now() && x.origin !== origin), { origin, expires: Date.now() + 36e5 }].slice(-30) });
      void render();
    };
    document.getElementById("clear").onclick = async () => {
      await chrome.storage.local.set({ exclusions: [] });
      void render();
    };
  }
  void render();
})();
