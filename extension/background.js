"use strict";
(() => {
  // src/policy.ts
  var VERSION = "evidence-v2";
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
  function excluded(url, settings2) {
    const origin = originOnly(url);
    return settings2.exclusions.some((x) => `${x.origin}/` === origin && x.expires > Date.now());
  }
  function localCheck(value) {
    const url = originOnly(value);
    if (!url) return { availability: "unavailable", message: "Unsupported page." };
    const parsed = new URL(url);
    const reasons = [];
    if (parsed.protocol === "http:") reasons.push("This page uses unencrypted HTTP transport.");
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname)) reasons.push("The host is an IP address; this does not identify an organization.");
    if (parsed.hostname.includes("xn--")) reasons.push("The hostname uses internationalized encoding. Check its spelling carefully.");
    return { availability: "partial", message: reasons.length ? reasons.join(" ") : "No significant risk observed in the local URL checks completed. Page content and identity were not verified.", evidence: reasons.map((description, i) => ({ id: `local-${i}`, title: "Local URL observation", description })), quick: { tier: reasons.length ? "MEDIUM" : "UNKNOWN", score: null, deep_required: true } };
  }
  function cleanObservations(value) {
    if (!value || typeof value !== "object") return;
    const v = value;
    if (v.consent !== true) return;
    const allowed = ["password", "email", "otp", "card", "phone", "address", "banking"];
    return { consent: true, fields: Array.isArray(v.fields) ? v.fields.filter((x) => typeof x === "string" && allowed.includes(x)).slice(0, 7) : [], form_actions: Array.isArray(v.form_actions) ? [...new Set(v.form_actions.map(originOnly).filter((x) => !!x))].slice(0, 12) : [], password_inputs: Math.max(0, Math.min(100, Math.floor(Number(v.password_inputs) || 0))), forms: Math.max(0, Math.min(100, Math.floor(Number(v.forms) || 0))), frame_coverage: "top_frame_only", page_fingerprint: typeof v.page_fingerprint === "string" ? v.page_fingerprint.slice(0, 80) : void 0 };
  }
  function cleanAction(value) {
    const v = value && typeof value === "object" ? value : {};
    const result = {};
    for (const key of ["form_action", "destination"]) {
      const url = originOnly(v[key]);
      if (url) result[key] = url;
    }
    if (v.is_executable === true) result.is_executable = true;
    if (Array.isArray(v.field_categories)) result.field_categories = v.field_categories.filter((x) => ["password", "email", "otp", "card", "phone", "address", "banking"].includes(String(x))).slice(0, 7);
    if (typeof v.page_fingerprint === "string") result.page_fingerprint = v.page_fingerprint.slice(0, 80);
    return result;
  }

  // src/background.ts
  var pending = /* @__PURE__ */ new Set();
  var generation = 0;
  var actions = /* @__PURE__ */ new Set(["password_focused", "card_focused", "otp_focused", "banking_focused", "form_focused", "form_submit", "download_attempt"]);
  var settings = async () => ({ ...defaults, ...await chrome.storage.local.get(defaults) });
  var unavailable = (message = "Protection unavailable. No safety conclusion can be made.") => ({ availability: "unavailable", message, requires_intervention: false });
  var reportKey = (tabId) => `report:${tabId}`;
  async function badge(tabId, result) {
    const s = await settings();
    if (!s.protectionEnabled) return;
    const risk = String(result.report?.digital_trust_profile?.trust_state || result.quick?.tier || "UNKNOWN");
    await chrome.action.setBadgeText({ tabId, text: result.availability === "unavailable" ? "?" : ["HIGH", "HIGH_RISK", "STOP"].includes(risk) ? "!" : s.showLowRisk ? "\u2026" : "" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: ["HIGH", "HIGH_RISK", "STOP"].includes(risk) ? "#b91c1c" : "#8a5c12" });
  }
  async function api(path, body, pairing = false) {
    const start = generation;
    const s = await settings();
    const base = backendOrigin(s.backendUrl);
    if (!pairing && (!s.protectionEnabled || !s.cloudConsent || s.protectionMode === "local")) throw new Error("Cloud protection is paused or not consented.");
    if (!base) throw new Error("Configure and pair an analysis service in Settings.");
    const { auth } = await chrome.storage.session.get("auth");
    if (!pairing && (!auth?.token || auth.base !== base || auth.expires <= Date.now())) throw new Error("Pairing expired. Pair again in Settings.");
    const controller = new AbortController();
    pending.add(controller);
    const timer = setTimeout(() => controller.abort(), 8e3);
    try {
      if (start !== generation) throw new Error("Protection settings changed.");
      const response = await fetch(`${base}${path}`, { method: body === void 0 ? "GET" : "POST", headers: { "Content-Type": "application/json", ...!pairing ? { Authorization: `Bearer ${auth.token}` } : {} }, body: body === void 0 ? void 0 : JSON.stringify(body), credentials: "omit", redirect: "error", signal: controller.signal });
      if (response.status === 401) await chrome.storage.session.remove("auth");
      if (!response.ok) throw new Error(response.status === 401 ? "Pairing expired or revoked." : `Analysis service returned ${response.status}.`);
      const payload = await response.json();
      if (payload?.success === false || !payload?.data) throw new Error("Invalid analysis response.");
      if (start !== generation) throw new Error("Protection settings changed.");
      return payload.data;
    } finally {
      clearTimeout(timer);
      pending.delete(controller);
    }
  }
  async function validTab(tabId, url, documentId) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab.url !== url) return false;
      if (documentId) {
        const frame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
        if (frame?.documentId !== documentId) return false;
      }
      return true;
    } catch {
      return false;
    }
  }
  async function inspect(tabId, exactUrl, deep = false, observations, documentId) {
    const start = generation;
    const s = await settings();
    const url = originOnly(exactUrl);
    if (!s.protectionEnabled) return { availability: "paused", message: "Protection paused." };
    if (!url || excluded(url, s)) return { availability: "excluded", message: "This page is unsupported or temporarily excluded." };
    let result = localCheck(url);
    if (s.protectionMode !== "local" && s.cloudConsent) {
      try {
        const obs = cleanObservations(observations);
        const quick = await api("/api/v1/quick-check", { url, context: obs ? { observations: obs } : {} });
        result = { availability: "partial", message: "URL check completed. Redacted paths and queries and unobserved content limit coverage.", quick };
        if (deep || s.protectionMode === "deep" && quick.deep_required) {
          const job = await api("/api/v1/investigations", { url, context: obs ? { observations: obs } : {} });
          const deadline = Date.now() + 3e4;
          while (Date.now() < deadline) {
            if (start !== generation || !await validTab(tabId, exactUrl, documentId)) throw new Error("Page or settings changed.");
            const report = await api(`/api/v1/investigations/${encodeURIComponent(String(job.id))}`);
            if (report.status === "COMPLETED") {
              result = { availability: "partial", message: String(report.recommendation || "Review the completed checks and their limitations."), report };
              break;
            }
            if (["FAILED", "CANCELLED"].includes(String(report.status))) throw new Error(`Investigation ${String(report.status).toLowerCase()}.`);
            await new Promise((resolve) => setTimeout(resolve, 750));
          }
          if (!result.report) throw new Error("Investigation still pending; open history in the dashboard.");
        }
      } catch (error) {
        result = unavailable(error instanceof Error ? error.message : void 0);
      }
    }
    if (start === generation && await validTab(tabId, exactUrl, documentId)) {
      await chrome.storage.session.set({ [reportKey(tabId)]: { value: result, url: exactUrl, documentId, expires: Date.now() + 6e4, version: VERSION } });
      await badge(tabId, result);
      await chrome.tabs.sendMessage(tabId, { type: "assessment", url: exactUrl, result }, { frameId: 0 }).catch(() => {
      });
      if (s.automaticNotifications && result.report && ["HIGH", "CRITICAL"].includes(String(result.report.classification))) chrome.notifications.create(`m-phish-${tabId}`, { type: "basic", iconUrl: "icons/icon128.png", title: "M-PHISH: review this page", message: String(result.report.recommendation || "Review the observed evidence.").slice(0, 300) });
    }
    return result;
  }
  function trustedPage(sender) {
    return sender.id === chrome.runtime.id && (sender.frameId === void 0 || sender.frameId === 0) && !!sender.url && ["popup.html", "options.html"].some((page) => sender.url === chrome.runtime.getURL(page));
  }
  async function handle(message, sender) {
    if (sender.id !== chrome.runtime.id) return unavailable("Invalid sender.");
    if (trustedPage(sender)) {
      if (message.type === "pair") {
        if (typeof message.code !== "string" || message.code.length > 256) return unavailable("Invalid pairing code.");
        const data = await api("/api/v1/auth/pair/exchange", { code: message.code, extension_id: chrome.runtime.id }, true);
        const s2 = await settings();
        if (typeof data.access_token !== "string" || typeof data.expires_in !== "number") throw new Error("Invalid pairing response.");
        await chrome.storage.session.set({ auth: { token: data.access_token, base: backendOrigin(s2.backendUrl), expires: Date.now() + Math.min(data.expires_in, 1800) * 1e3 } });
        return { availability: "paired", message: "Paired for up to 30 minutes. Browser restart clears this pairing." };
      }
      if (message.type === "logout") {
        try {
          await api("/api/v1/auth/logout", {});
        } catch {
        }
        await invalidate(true);
        return { availability: "unpaired", message: "Pairing removed locally. If the service was unavailable, revoke sessions in the dashboard." };
      }
      if (message.type === "inspect" && Number.isInteger(message.tabId)) {
        const tab = await chrome.tabs.get(Number(message.tabId));
        if (!tab.url) return unavailable();
        return inspect(Number(message.tabId), tab.url, message.deep === true);
      }
      if (message.type === "status" && Number.isInteger(message.tabId)) {
        const tab = await chrome.tabs.get(Number(message.tabId));
        const saved = (await chrome.storage.session.get(reportKey(Number(message.tabId))))[reportKey(Number(message.tabId))];
        if (saved?.url === tab.url && saved.expires > Date.now() && saved.version === VERSION) return saved.value;
        return { availability: "unknown", message: "No current assessment. Run a check to begin." };
      }
      return unavailable("Unsupported extension command.");
    }
    const s = await settings();
    if (!s.protectionEnabled) return { availability: "paused", message: "Protection paused." };
    if (sender.frameId !== 0 || sender.tab?.id === void 0 || typeof sender.url !== "string" || message.url !== sender.url || !originOnly(sender.url) || !await validTab(sender.tab.id, sender.url, sender.documentId)) return unavailable("Page context changed or is unsupported.");
    if (excluded(sender.url, s)) return { availability: "excluded", message: "Origin temporarily excluded." };
    if (message.type === "observations") return inspect(sender.tab.id, sender.url, false, message.observations, sender.documentId);
    if (message.type !== "interaction-event" || !actions.has(String(message.action_type))) return unavailable("Unsupported interaction.");
    if (s.protectionMode === "local" || !s.cloudConsent) return { ...localCheck(sender.url), requires_intervention: true, message: "Local check only. Review the destination before continuing; cloud analysis is disabled." };
    const start = generation;
    try {
      const data = await api("/api/v1/dynamic-trust/evaluate", { url: originOnly(sender.url), action_type: message.action_type, action_details: cleanAction(message.action_details), context: { observations: cleanObservations(message.observations) } });
      if (start !== generation || !await validTab(sender.tab.id, sender.url, sender.documentId)) return { availability: "stale", message: "Page changed; assessment discarded." };
      return { availability: "partial", message: String(data.intervention_modal?.message || "Review the observed interaction."), ...data };
    } catch (error) {
      return unavailable(error instanceof Error ? error.message : void 0);
    }
  }
  chrome.runtime.onMessage.addListener((message, sender, reply) => {
    if (!message || typeof message !== "object") return;
    handle(message, sender).then(reply).catch((error) => reply(unavailable(error instanceof Error ? error.message : void 0)));
    return true;
  });
  async function invalidate(auth = false) {
    generation++;
    for (const controller of pending) controller.abort();
    pending.clear();
    const all = await chrome.storage.session.get(null);
    await chrome.storage.session.remove(Object.keys(all).filter((x) => auth || x.startsWith("report:")));
    for (const tab of await chrome.tabs.query({})) {
      if (tab.id === void 0) continue;
      await chrome.action.setBadgeText({ tabId: tab.id, text: "" }).catch(() => {
      });
      chrome.tabs.sendMessage(tab.id, { type: "settings-changed" }).catch(() => {
      });
      chrome.notifications.clear(`m-phish-${tab.id}`);
    }
  }
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (Object.keys(changes).some((key) => key in defaults)) void invalidate(!!changes.backendUrl);
  });
  async function navigation(details) {
    if (details.frameId !== 0) return;
    await chrome.storage.session.remove(reportKey(details.tabId));
    await chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
    if (originOnly(details.url)) void inspect(details.tabId, details.url, false, void 0, details.documentId);
  }
  chrome.webNavigation.onCommitted.addListener(navigation);
  chrome.webNavigation.onHistoryStateUpdated.addListener(navigation);
  chrome.webNavigation.onReferenceFragmentUpdated.addListener(navigation);
  chrome.tabs.onRemoved.addListener((tabId) => {
    void chrome.storage.session.remove(reportKey(tabId));
  });
  chrome.runtime.onInstalled.addListener(async (details) => {
    const current = await chrome.storage.local.get(defaults);
    await chrome.storage.local.set({ ...defaults, ...current });
    await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
    if (details.reason === "install") chrome.runtime.openOptionsPage();
  });
})();
