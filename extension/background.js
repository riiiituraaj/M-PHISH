(() => {
  // src/background.ts
  var API = "https://m-phish.onrender.com";
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
  async function inspect(tabId, url) {
    if (!supported(url)) return;
    const existing = await cached(url);
    if (existing) {
      apply(tabId, url, existing);
      return;
    }
    try {
      const response = await fetch(`${API}/api/quick-check`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, context: { tab_id: tabId } }) });
      if (!response.ok) return;
      const quick = await response.json();
      await chrome.storage.local.set({ [key(url)]: { value: quick, savedAt: Date.now() } });
      apply(tabId, url, quick);
      if (quick.deep_required) {
        const full = await fetch(`${API}/api/investigations`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, context: { tab_id: tabId } }) });
        if (full.ok) {
          const report = await full.json();
          await chrome.storage.local.set({ [`report:${tabId}`]: report });
          const settings = await chrome.storage.local.get("automaticNotifications");
          if (quick.tier !== "LOW" && settings.automaticNotifications !== false) chrome.notifications.create(`m-phish-${tabId}`, { type: "basic", iconUrl: "icon.svg", title: `M-PHISH X \xB7 ${quick.tier} RISK`, message: quick.top_reasons.join(" \xB7 ") || "Review this website before sharing sensitive information." });
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
        badge(tabId, quick.tier === "LOW" ? "\u2713" : quick.tier === "MEDIUM" ? "!" : "\u26A0", quick.tier === "LOW" ? "#347a55" : quick.tier === "MEDIUM" ? "#b47a27" : "#c44949");
      }
    });
    chrome.tabs.sendMessage(tabId, { type: "quick-result", url, quick }).catch(() => {
    });
  }
  chrome.runtime.onInstalled.addListener(() => chrome.storage.local.set({ installedAt: Date.now(), protectionEnabled: true, automaticNotifications: true, showLowRisk: false }));
  chrome.runtime.onStartup.addListener(() => chrome.storage.local.get("protectionEnabled").then((value) => {
    if (value.protectionEnabled === void 0) chrome.storage.local.set({ protectionEnabled: true });
  }));
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    chrome.storage.local.get(["protectionEnabled", contextKey(details.tabId)]).then(async (settings) => {
      if (settings.protectionEnabled === false) return;
      const url = details.url;
      if (!supported(url)) return;
      const parsed = new URL(url);
      const prior = settings[contextKey(details.tabId)] || {};
      const next = { session_id: prior.session_id || crypto.randomUUID(), previous_url: prior.current_url, current_url: url, domains_seen: Array.from(/* @__PURE__ */ new Set([...prior.domains_seen || [], parsed.hostname])), timestamp: (/* @__PURE__ */ new Date()).toISOString() };
      await chrome.storage.local.set({ [contextKey(details.tabId)]: next });
      inspect(details.tabId, url);
    });
  });
  chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.local.remove([contextKey(tabId), `report:${tabId}`]));
})();
