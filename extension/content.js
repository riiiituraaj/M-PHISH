(() => {
  // src/content.ts
  var isDismissedForSession = false;
  var currentTrustState = "TRUSTED";
  var currentReport = null;
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
  function attachInteractionListeners() {
    document.addEventListener("focusin", (event) => {
      const target = event.target;
      if (!target) return;
      const tagName = target.tagName.toLowerCase();
      if (tagName !== "input" && tagName !== "textarea" && tagName !== "select") return;
      const input = target;
      const type = (input.type || "").toLowerCase();
      const name = (input.name || "").toLowerCase();
      const placeholder = (input.placeholder || "").toLowerCase();
      let actionType = null;
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
      const form = input.closest("form");
      const formAction = form ? form.action : "";
      chrome.runtime.sendMessage(
        {
          type: "interaction-event",
          url: window.location.href,
          action_type: actionType,
          action_details: {
            field_type: type,
            field_label: fieldLabel,
            form_action: formAction
          }
        },
        (response) => {
          if (chrome.runtime.lastError || !response) return;
          if (response.requires_intervention && !isDismissedForSession) {
            showTrustBeforeYouActBanner(response, input);
          }
        }
      );
    }, true);
    document.addEventListener("click", (event) => {
      const target = event.target.closest("a");
      if (!target || !target.href) return;
      const href = target.href.toLowerCase();
      if (href.match(/\.(exe|msi|bat|ps1|vbs|apk)$/)) {
        chrome.runtime.sendMessage(
          {
            type: "interaction-event",
            url: window.location.href,
            action_type: "download_attempt",
            action_details: {
              download_url: target.href,
              is_executable: true
            }
          },
          (response) => {
            if (response?.requires_intervention && !isDismissedForSession) {
              showTrustBeforeYouActBanner(response, target);
            }
          }
        );
      }
    });
  }
  function showTrustBeforeYouActBanner(data, focusedElement) {
    if (document.getElementById("m-phish-shield-root")) return;
    const container = document.createElement("div");
    container.id = "m-phish-shield-root";
    const shadow = container.attachShadow({ mode: "open" });
    const modal = data.intervention_modal || {};
    const title = modal.title || "Before you enter credentials";
    const message = modal.message || "This website has not established verifiable trust.";
    const recommendation = modal.recommended_action || "We recommend not entering sensitive information here.";
    const safeRoute = modal.safe_route || null;
    shadow.innerHTML = `
    <style>
      :host {
        all: initial;
        position: fixed;
        bottom: 24px;
        right: 24px;
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        color: #e6edf0;
      }
      .shield-card {
        width: 380px;
        background: rgba(17, 22, 28, 0.96);
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border: 1px solid rgba(196, 73, 73, 0.4);
        border-radius: 12px;
        box-shadow: 0 16px 40px rgba(0, 0, 0, 0.45);
        padding: 18px 20px;
        box-sizing: border-box;
        animation: mPhishSlideUp 0.28s cubic-bezier(0.16, 1, 0.3, 1);
      }
      @keyframes mPhishSlideUp {
        from { opacity: 0; transform: translateY(12px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .header {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 10px;
      }
      .indicator {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #e25555;
        box-shadow: 0 0 10px rgba(226, 85, 85, 0.6);
      }
      .title {
        font-size: 14px;
        font-weight: 600;
        color: #ffffff;
        letter-spacing: -0.01em;
      }
      .brand-tag {
        margin-left: auto;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #8b9aa3;
        font-weight: 600;
      }
      .message {
        font-size: 12.5px;
        line-height: 1.5;
        color: #b0bec5;
        margin: 0 0 12px 0;
      }
      .recommendation {
        font-size: 12px;
        line-height: 1.45;
        background: rgba(196, 73, 73, 0.12);
        border-left: 3px solid #e25555;
        padding: 8px 10px;
        border-radius: 4px;
        color: #ffcccc;
        margin-bottom: 14px;
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
        ${safeRoute ? `<a class="btn btn-safe" href="${escapeHtml(safeRoute)}" target="_blank" id="btn-saferoute">Open Verified Official Site</a>` : ""}
        <div class="btn-row">
          <button class="btn btn-back" id="btn-back">Go Back</button>
          <button class="btn btn-back" id="btn-dismiss">Continue anyway</button>
        </div>
        <button class="btn btn-subtle" id="btn-why">Why am I seeing this?</button>
      </div>
      <div class="details-content" id="details-panel">
        <strong>Identified Signals:</strong><br>
        \u2022 Current web host does not match authentic institution credentials.<br>
        \u2022 Sensitive inputs were activated prior to verified trust establishment.<br>
        \u2022 Data entered here will not be submitted to the official entity.
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
  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }
  attachInteractionListeners();
})();
