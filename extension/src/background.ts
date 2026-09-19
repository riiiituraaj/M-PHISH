/// <reference path="./chrome.d.ts" />
type QuickCheck = {
  tier: "LOW" | "MEDIUM" | "HIGH";
  deep_required: boolean;
  top_reasons: string[];
  score: number;
};
type Envelope<T> = { success: boolean; data: T; request_id: string };
type Job = { id: string; status: string };
type TabContext = {
  session_id: string;
  previous_url?: string;
  current_url: string;
  domains_seen: string[];
  timestamp: string;
};

const DEFAULT_API_ENDPOINT = "https://m-phish.onrender.com";
const TTL = 5 * 60 * 1000;
const supported = (url?: string) => !!url && /^https?:\/\//i.test(url);
const ignoredHost = (url: string) => {
  try {
    return ["m-phish.vercel.app", "m-phish.onrender.com", "localhost", "127.0.0.1"].includes(new URL(url).hostname);
  } catch {
    return true;
  }
};
const key = (url: string) => `result:${url}`;
const contextKey = (tabId: number) => `context:${tabId}`;

function badge(tabId: number, text: string, color: string) {
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

async function cached(url: string): Promise<QuickCheck | undefined> {
  const data = await chrome.storage.local.get(key(url));
  const item = data[key(url)];
  return item && Date.now() - item.savedAt < TTL ? item.value : undefined;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const settings = await chrome.storage.local.get(["apiEndpoint", "apiKey"]);
  const base = typeof settings.apiEndpoint === "string" && settings.apiEndpoint.trim()
    ? settings.apiEndpoint.trim().replace(/\/+$/, "")
    : DEFAULT_API_ENDPOINT;
  const headers = new Headers(options?.headers || {});
  if (typeof settings.apiKey === "string" && settings.apiKey.trim()) headers.set("X-API-Key", settings.apiKey.trim());
  const response = await fetch(`${base}${path}`, { ...options, headers });
  const envelope = (await response.json().catch(() => null)) as Envelope<T> | null;
  if (!response.ok || !envelope?.success) {
    throw new Error((envelope as any)?.error || `API request failed (${response.status})`);
  }
  return envelope.data;
}


async function investigate(
  tabId: number,
  url: string,
): Promise<Record<string, unknown>> {
  const job = await request<Job>("/api/v1/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, context: { tab_id: tabId } }),
  });
  for (let attempt = 0; attempt < 40; attempt++) {
    const status = await request<Record<string, unknown> & { status: string }>(
      `/api/v1/investigations/${encodeURIComponent(job.id)}`,
    );
    if (status.status === "COMPLETED") return status;
    if (status.status === "FAILED") throw new Error("Investigation failed");
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error("Investigation timed out");
}

async function inspect(tabId: number, url: string) {
  if (!supported(url)) return;
  const existing = await cached(url);
  if (existing) {
    apply(tabId, url, existing);
    return;
  }
  try {
    const quick = await request<QuickCheck>("/api/v1/quick-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, context: { tab_id: tabId } }),
    });
    await chrome.storage.local.set({
      [key(url)]: { value: quick, savedAt: Date.now() },
    });
    apply(tabId, url, quick);
    if (quick.deep_required) {
      const report = await investigate(tabId, url);
      await chrome.storage.local.set({ [`report:${tabId}`]: report });

      // Check dynamic trust state
      const trustProfile = (report as any).digital_trust_profile;
      if (trustProfile) {
        applyTrustBadge(tabId, trustProfile.trust_state);
        chrome.tabs.sendMessage(tabId, {
          type: "trust-update",
          trust_state: trustProfile.trust_state,
          report,
        }).catch(() => {});
      }

      const settings = await chrome.storage.local.get("automaticNotifications");
      if (quick.tier !== "LOW" && settings.automaticNotifications !== false) {
        chrome.notifications.create(`m-phish-${tabId}`, {
          type: "basic",
          iconUrl: "icon.svg",
          title: `M-PHISH X · ${(report as any).summary || quick.tier + " RISK"}`,
          message:
            (report as any).recommendation ||
            quick.top_reasons.join(" · ") ||
            "Review website authenticity before sharing credentials.",
        });
      }
    }
  } catch {
    badge(tabId, "!", "#b47a27");
  }
}

function apply(tabId: number, url: string, quick: QuickCheck) {
  chrome.storage.local.get("showLowRisk").then((settings) => {
    if (quick.tier === "LOW" && !settings.showLowRisk) {
      chrome.action.setBadgeText({ tabId, text: "" });
    } else {
      badge(
        tabId,
        quick.tier === "LOW" ? "✓" : quick.tier === "MEDIUM" ? "!" : "⚠",
        quick.tier === "LOW"
          ? "#22c55e"
          : quick.tier === "MEDIUM"
            ? "#eab308"
            : "#ef4444",
      );
    }
  });
  chrome.tabs
    .sendMessage(tabId, { type: "quick-result", url, quick })
    .catch(() => {});
}

function applyTrustBadge(tabId: number, state: string) {
  if (state === "STOP") {
    badge(tabId, "STOP", "#ef4444");
  } else if (state === "HIGH_RISK") {
    badge(tabId, "⚠", "#f97316");
  } else if (state === "CAUTION") {
    badge(tabId, "!", "#eab308");
  } else if (state === "TRUSTED") {
    chrome.storage.local.get("showLowRisk").then((s) => {
      if (s.showLowRisk) badge(tabId, "✓", "#22c55e");
      else chrome.action.setBadgeText({ tabId, text: "" });
    });
  }
}

// Handle real-time user interaction events from content sentinel
async function handleInteractionEvent(
  tabId: number | undefined,
  url: string,
  actionType: string,
  actionDetails: Record<string, unknown>,
) {
  try {
    const result = await request<any>("/api/v1/dynamic-trust/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        action_type: actionType,
        action_details: actionDetails,
      }),
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
      message.action_details,
    ).then((res) => sendResponse(res));
    return true; // Keep channel open for async response
  }
});

chrome.runtime.onInstalled.addListener(() =>
  chrome.storage.local.set({
    installedAt: Date.now(),
    protectionEnabled: true,
    automaticNotifications: true,
    showLowRisk: false,
    protectionMode: "standard",
  }),
);

chrome.runtime.onStartup.addListener(() =>
  chrome.storage.local.get("protectionEnabled").then((value) => {
    if (value.protectionEnabled === undefined)
      chrome.storage.local.set({ protectionEnabled: true });
  }),
);

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.storage.local
    .get(["protectionEnabled", contextKey(details.tabId)])
    .then(async (settings) => {
      if (settings.protectionEnabled === false) return;
      const url = details.url;
      if (!supported(url) || ignoredHost(url)) return;
      const parsed = new URL(url);
      const prior = (settings[contextKey(details.tabId)] || {}) as TabContext;
      const next = {
        session_id: prior.session_id || crypto.randomUUID(),
        previous_url: prior.current_url,
        current_url: url,
        domains_seen: Array.from(
          new Set([...(prior.domains_seen || []), parsed.hostname]),
        ),
        timestamp: new Date().toISOString(),
      };
      await chrome.storage.local.set({ [contextKey(details.tabId)]: next });
      inspect(details.tabId, url);
    });
});

chrome.tabs.onRemoved.addListener((tabId) =>
  chrome.storage.local.remove([contextKey(tabId), `report:${tabId}`]),
);
