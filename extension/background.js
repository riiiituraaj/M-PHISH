(() => {
  // src/background.ts
  var API_ENDPOINTS = ["https://m-phish.onrender.com", "http://localhost:8000"];
  var TTL = 5 * 60 * 1e3;
  var supported = (url) => !!url && /^https?:\/\//i.test(url);
  var key = (url) => `result:${url}`;
  var contextKey = (tabId) => `context:${tabId}`;
  function badge(tabId, text, color) {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  }
  async function cached(url) {
    const data = await chrome.storage.local.get(key(url));
    const item = data[key(url)];
    return item && Date.now() - item.savedAt < TTL ? item.value : void 0;
  }
  async function request(path, options) {
    let lastError = null;
    for (const base of API_ENDPOINTS) {
      try {
        const response = await fetch(`${base}${path}`, options);
        if (response.ok) {
          return (await response.json()).data;
        }
      } catch (e) {
        lastError = e instanceof Error ? e : new Error(String(e));
      }
    }
    throw lastError || new Error(`API request failed for ${path}`);
  }
  async function investigate(tabId, url) {
    const job = await request("/api/v1/investigations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, context: { tab_id: tabId } })
    });
    for (let attempt = 0; attempt < 40; attempt++) {
      const status = await request(
        `/api/v1/investigations/${encodeURIComponent(job.id)}`
      );
      if (status.status === "COMPLETED") return status;
      if (status.status === "FAILED") throw new Error("Investigation failed");
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error("Investigation timed out");
  }
  async function inspect(tabId, url) {
    if (!supported(url)) return;
    const existing = await cached(url);
    if (existing) {
      apply(tabId, url, existing);
      return;
    }
    try {
      const quick = await request("/api/v1/quick-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, context: { tab_id: tabId } })
      });
      await chrome.storage.local.set({
        [key(url)]: { value: quick, savedAt: Date.now() }
      });
      apply(tabId, url, quick);
      if (quick.deep_required) {
        const report = await investigate(tabId, url);
        await chrome.storage.local.set({ [`report:${tabId}`]: report });
        const trustProfile = report.digital_trust_profile;
        if (trustProfile) {
          applyTrustBadge(tabId, trustProfile.trust_state);
          chrome.tabs.sendMessage(tabId, {
            type: "trust-update",
            trust_state: trustProfile.trust_state,
            report
          }).catch(() => {
          });
        }
        const settings = await chrome.storage.local.get("automaticNotifications");
        if (quick.tier !== "LOW" && settings.automaticNotifications !== false) {
          chrome.notifications.create(`m-phish-${tabId}`, {
            type: "basic",
            iconUrl: "icon.svg",
            title: `M-PHISH X \xB7 ${report.summary || quick.tier + " RISK"}`,
            message: report.recommendation || quick.top_reasons.join(" \xB7 ") || "Review website authenticity before sharing credentials."
          });
        }
      }
    } catch {
      badge(tabId, "!", "#b47a27");
    }
  }
  function apply(tabId, url, quick) {
    chrome.storage.local.get("showLowRisk").then((settings) => {
      if (quick.tier === "LOW" && !settings.showLowRisk) {
        chrome.action.setBadgeText({ tabId, text: "" });
      } else {
        badge(
          tabId,
          quick.tier === "LOW" ? "\u2713" : quick.tier === "MEDIUM" ? "!" : "\u26A0",
          quick.tier === "LOW" ? "#22c55e" : quick.tier === "MEDIUM" ? "#eab308" : "#ef4444"
        );
      }
    });
    chrome.tabs.sendMessage(tabId, { type: "quick-result", url, quick }).catch(() => {
    });
  }
  function applyTrustBadge(tabId, state) {
    if (state === "STOP") {
      badge(tabId, "STOP", "#ef4444");
    } else if (state === "HIGH_RISK") {
      badge(tabId, "\u26A0", "#f97316");
    } else if (state === "CAUTION") {
      badge(tabId, "!", "#eab308");
    } else if (state === "TRUSTED") {
      chrome.storage.local.get("showLowRisk").then((s) => {
        if (s.showLowRisk) badge(tabId, "\u2713", "#22c55e");
        else chrome.action.setBadgeText({ tabId, text: "" });
      });
    }
  }
  async function handleInteractionEvent(tabId, url, actionType, actionDetails) {
    try {
      const result = await request("/api/v1/dynamic-trust/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          action_type: actionType,
          action_details: actionDetails
        })
      });
      if (tabId && result?.transition) {
        applyTrustBadge(tabId, result.transition.current_state);
      }
      return result;
    } catch (error) {
      return { requires_intervention: false };
    }
  }
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "interaction-event") {
      handleInteractionEvent(
        sender.tab?.id,
        message.url,
        message.action_type,
        message.action_details
      ).then((res) => sendResponse(res));
      return true;
    }
  });
  chrome.runtime.onInstalled.addListener(
    () => chrome.storage.local.set({
      installedAt: Date.now(),
      protectionEnabled: true,
      automaticNotifications: true,
      showLowRisk: false,
      protectionMode: "standard"
    })
  );
  chrome.runtime.onStartup.addListener(
    () => chrome.storage.local.get("protectionEnabled").then((value) => {
      if (value.protectionEnabled === void 0)
        chrome.storage.local.set({ protectionEnabled: true });
    })
  );
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    chrome.storage.local.get(["protectionEnabled", contextKey(details.tabId)]).then(async (settings) => {
      if (settings.protectionEnabled === false) return;
      const url = details.url;
      if (!supported(url)) return;
      const parsed = new URL(url);
      const prior = settings[contextKey(details.tabId)] || {};
      const next = {
        session_id: prior.session_id || crypto.randomUUID(),
        previous_url: prior.current_url,
        current_url: url,
        domains_seen: Array.from(
          /* @__PURE__ */ new Set([...prior.domains_seen || [], parsed.hostname])
        ),
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
      await chrome.storage.local.set({ [contextKey(details.tabId)]: next });
      inspect(details.tabId, url);
    });
  });
  chrome.tabs.onRemoved.addListener(
    (tabId) => chrome.storage.local.remove([contextKey(tabId), `report:${tabId}`])
  );
})();
