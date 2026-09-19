/// <reference path="./chrome.d.ts" />
// M-PHISH X Content Script: "Trust Before You Act" & Dynamic Interaction Sentinel

let isDismissedForSession = false;
let currentTrustState: string = "TRUSTED";
let currentReport: any = null;
let extensionContextValid = true;

function sendRuntimeMessage(
  message: Record<string, unknown>,
  callback: (response?: any) => void,
) {
  if (!extensionContextValid) return;
  try {
    if (!chrome.runtime?.id) {
      extensionContextValid = false;
      return;
    }
    chrome.runtime.sendMessage(message, (response) => {
      try {
        if (chrome.runtime.lastError) {
          extensionContextValid = false;
          return;
        }
      } catch {
        extensionContextValid = false;
        return;
      }
      callback(response);
    });
  } catch {
    extensionContextValid = false;
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "quick-result") {
    document.documentElement.dataset.mPhishRisk = message.quick.tier;
  } else if (message.type === "trust-update") {
    currentTrustState = message.trust_state;
    currentReport = message.report;
    document.documentElement.dataset.mPhishTrust = message.trust_state;
  }
  sendResponse({ received: true });
});

// Detect sensitive interactions
function attachInteractionListeners() {
  document.addEventListener("focusin", (event) => {
    const target = event.target as HTMLElement;
    if (!target) return;

    const tagName = target.tagName.toLowerCase();
    if (tagName !== "input" && tagName !== "textarea" && tagName !== "select") return;

    const input = target as HTMLInputElement;
    const type = (input.getAttribute("type") || "").toLowerCase();
    const name = (input.getAttribute("name") || "").toLowerCase();
    const placeholder = (input.getAttribute("placeholder") || "").toLowerCase();

    let actionType: string | null = null;
    let fieldLabel = "personal information";

    if (type === "password" || name.includes("pass") || name.includes("pwd") || name.includes("pin")) {
      actionType = "password_focused";
      fieldLabel = "password";
    } else if (name.includes("card") || name.includes("cvv") || name.includes("cvc") || placeholder.includes("card")) {
      actionType = "card_focused";
      fieldLabel = "payment card details";
    } else if (name.includes("otp") || name.includes("one_time") || placeholder.includes("otp")) {
      actionType = "otp_focused";
      fieldLabel = "one-time verification code";
    } else if (name.includes("bank") || name.includes("upi") || name.includes("routing")) {
      actionType = "banking_focused";
      fieldLabel = "banking / payment details";
    } else if (tagName === "input" && type !== "hidden" && type !== "submit") {
      actionType = "form_focused";
      fieldLabel = "information";
    }

    if (!actionType) return;

    // Determine form destination
    const form = input.closest("form");
    const formAction = form ? form.action : "";

    sendRuntimeMessage(
      {
        type: "interaction-event",
        url: window.location.href,
        action_type: actionType,
        action_details: {
          field_type: type,
          field_label: fieldLabel,
          form_action: formAction,
        },
      },
      (response) => {
        if (!response) return;
        if (response.requires_intervention && !isDismissedForSession) {
          showTrustBeforeYouActBanner(response, { field_label: fieldLabel, form_action: formAction });
        }
      }
    );
  }, true);

  // Monitor executable downloads
  document.addEventListener("click", (event) => {
    const target = (event.target as HTMLElement).closest("a");
    if (!target || !target.href) return;
    const href = target.href.toLowerCase();
    if (href.match(/\.(exe|msi|bat|ps1|vbs|apk)$/)) {
      sendRuntimeMessage(
        {
          type: "interaction-event",
          url: window.location.href,
          action_type: "download_attempt",
          action_details: {
            download_url: target.href,
            is_executable: true,
          },
        },
        (response) => {
          if (response?.requires_intervention && !isDismissedForSession) {
            showTrustBeforeYouActBanner(response, { download_url: target.href });
          }
        }
      );
    }
  });
}

type InterventionContext = {
  field_label?: string;
  form_action?: string;
  download_url?: string;
};

function hostOf(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value;
  }
}

function showTrustBeforeYouActBanner(
  data: any,
  context: InterventionContext = {},
) {
  if (document.getElementById("m-phish-shield-root")) return;

  const container = document.createElement("div");
  container.id = "m-phish-shield-root";

  // Attach shadow root to prevent page style contamination
  const shadow = container.attachShadow({ mode: "open" });

  const modal = data.intervention_modal || {};
  const profile = data.digital_trust_profile || {};
  const identity = data.identity_analysis || {};
  const title = modal.title || "Before you continue";
  const message =
    modal.message ||
    profile.state_reason ||
    "This page has not established verifiable trust.";
  const recommendation =
    modal.recommended_action ||
    "Do not enter credentials or payment details on this page.";
  const safeRoute = modal.safe_route || data.safe_route || null;

  const facts = (
    [
      context.field_label ? ["Interaction", context.field_label] : null,
      context.form_action ? ["Data sent to", hostOf(context.form_action)] : null,
      context.download_url ? ["Download from", hostOf(context.download_url)] : null,
      identity.claimed_service ? ["Claims to be", identity.claimed_service] : null,
      profile.trust_state
        ? ["Trust state", String(profile.trust_state).replace("_", " ")]
        : null,
    ] as (string[] | null)[]
  ).filter(Boolean) as string[][];

  const factsHtml = facts
    .map(
      ([label, value]) =>
        `<div class="fact"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`,
    )
    .join("");

  const notes = [
    identity.is_impersonation_suspected
      ? "The page presents another organisation's identity."
      : null,
    identity.explanation || null,
    profile.state_reason || null,
  ].filter(Boolean) as string[];

  const notesHtml = notes.map((note) => `<p>${escapeHtml(note)}</p>`).join("");

  shadow.innerHTML = `
    <style>
      :host {
        all: initial;
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #e9f1fb;
      }
      .shield-card {
        width: 372px;
        padding: 16px;
        border: 1px solid rgba(248, 113, 113, 0.34);
        border-radius: 14px;
        background: rgba(12, 20, 33, 0.97);
        backdrop-filter: blur(18px);
        -webkit-backdrop-filter: blur(18px);
        box-shadow: 0 18px 44px rgba(0, 0, 0, 0.48);
        box-sizing: border-box;
        animation: mPhishSlideUp 0.24s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes mPhishSlideUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .head {
        display: flex;
        align-items: center;
        gap: 9px;
        margin-bottom: 10px;
      }
      .mark {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: #f87171;
      }
      .title {
        font-size: 13.5px;
        font-weight: 620;
        color: #ffffff;
        letter-spacing: -0.01em;
      }
      .brand-tag {
        margin-left: auto;
        font-size: 9.5px;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #6b809a;
      }
      .message {
        margin: 0 0 12px;
        font-size: 12px;
        line-height: 1.55;
        color: #98adc6;
      }
      .facts {
        display: flex;
        flex-direction: column;
        margin-bottom: 12px;
      }
      .fact {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 12px;
        padding: 7px 0;
        border-bottom: 1px solid rgba(140, 172, 204, 0.14);
        font-size: 11.5px;
      }
      .fact:last-child { border-bottom: 0; }
      .fact span { color: #6b809a; }
      .fact b {
        font-weight: 620;
        color: #e9f1fb;
        text-align: right;
        overflow-wrap: anywhere;
      }
      .recommendation {
        margin-bottom: 14px;
        padding: 10px 12px;
        border-left: 2px solid #f87171;
        border-radius: 0 8px 8px 0;
        background: rgba(248, 113, 113, 0.1);
        color: #fecaca;
        font-size: 11.5px;
        line-height: 1.5;
      }
      .actions {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .btn {
        appearance: none;
        border: 0;
        padding: 9px 12px;
        border-radius: 6px;
        font-size: 12.5px;
        font-weight: 550;
        cursor: pointer;
        text-align: center;
        text-decoration: none;
        box-sizing: border-box;
        transition: filter 0.15s ease, background 0.15s ease;
      }
      .btn-safe {
        background: #2563eb;
        color: #ffffff;
      }
      .btn-safe:hover { filter: brightness(1.1); }
      .btn-back {
        background: #26313a;
        color: #e6edf0;
      }
      .btn-back:hover { background: #34424d; }
      .btn-row {
        display: flex;
        gap: 8px;
      }
      .btn-row .btn { flex: 1; }
      .btn-subtle {
        background: transparent;
        color: #8b9aa3;
        font-size: 11px;
        padding: 4px 6px;
        border: 1px solid transparent;
      }
      .btn-subtle:hover { color: #cfd8dc; text-decoration: underline; }
      .details-content {
        margin-top: 10px;
        padding-top: 10px;
        border-top: 1px solid #26313a;
        font-size: 11.5px;
        color: #8b9aa3;
        line-height: 1.45;
        display: none;
      }
      .details-content.visible { display: block; }
    </style>
    <div class="shield-card">
      <div class="header">
        <span class="indicator"></span>
        <span class="title">${escapeHtml(title)}</span>
        <span class="brand-tag">M-PHISH X</span>
      </div>
      <p class="message">${escapeHtml(message)}</p>
      <div class="recommendation">${escapeHtml(recommendation)}</div>
      <div class="actions">
        ${
          safeRoute
            ? `<a class="btn btn-safe" href="${escapeHtml(safeRoute)}" target="_blank" id="btn-saferoute">Open Verified Official Site</a>`
            : ""
        }
        <div class="btn-row">
          <button class="btn btn-back" id="btn-back">Go Back</button>
          <button class="btn btn-back" id="btn-dismiss">Continue anyway</button>
        </div>
        <button class="btn btn-subtle" id="btn-why">Why am I seeing this?</button>
      </div>
      <div class="details-content" id="details-panel">
        <strong>Identified Signals:</strong><br>
        • Current web host does not match authentic institution credentials.<br>
        • Sensitive inputs were activated prior to verified trust establishment.<br>
        • Data entered here will not be submitted to the official entity.
      </div>
    </div>
  `;

  document.body.appendChild(container);

  const btnDismiss = shadow.getElementById("btn-dismiss");
  if (btnDismiss) {
    btnDismiss.onclick = () => {
      isDismissedForSession = true;
      container.remove();
    };
  }

  const btnBack = shadow.getElementById("btn-back");
  if (btnBack) {
    btnBack.onclick = () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.close();
      }
    };
  }

  const btnWhy = shadow.getElementById("btn-why");
  const detailsPanel = shadow.getElementById("details-panel");
  if (btnWhy && detailsPanel) {
    btnWhy.onclick = () => {
      const isVis = detailsPanel.classList.contains("visible");
      if (isVis) {
        detailsPanel.classList.remove("visible");
        btnWhy.textContent = "Why am I seeing this?";
      } else {
        detailsPanel.classList.add("visible");
        btnWhy.textContent = "Hide explanation";
      }
    };
  }
}

function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

attachInteractionListeners();
