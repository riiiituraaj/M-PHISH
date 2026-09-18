(() => {
  // src/popup.ts
  var API_ENDPOINTS = ["http://localhost:8000", "https://m-phish.onrender.com"];
  var root = document.getElementById("app");
  var escape = (value) => (value || "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
  );
  function shell(body) {
    root.innerHTML = `<div class="card"><div class="brand"><img src="icon.svg" alt=""><span>M-PHISH <b>X</b></span></div>${body}</div>`;
  }
  function renderOff() {
    shell(
      '<div class="eyebrow">Protection is off</div><p class="summary">M-PHISH X is not monitoring browser navigation.</p><button class="button" id="toggle">Turn On</button>'
    );
    document.getElementById("toggle").onclick = () => setProtection(true);
  }
  function setProtection(enabled) {
    chrome.storage.local.set({ protectionEnabled: enabled }).then(init);
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
    throw lastError || new Error("Backend connection failed.");
  }
  async function checkCurrent(tabId, url) {
    shell(
      '<div class="progress"><b>\u25CF</b> Digital Identity<br><b>\u25CF</b> Website Authenticity<br><b>\u25CF</b> Behavior & Privacy<br><span>\u25CB</span> Digital Trust Profile</div>'
    );
    try {
      const quick = await request("/api/v1/quick-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, context: { tab_id: tabId } })
      });
      if (!quick.deep_required) {
        renderReady(url);
        return;
      }
      const job = await request("/api/v1/investigations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, context: { tab_id: tabId } })
      });
      for (let attempt = 0; attempt < 40; attempt++) {
        const status = await request(
          `/api/v1/investigations/${encodeURIComponent(job.id)}`
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
        `<p class="summary">${escape(message)}. Confirm the M-PHISH X backend is running.</p><button class="button secondary" id="retry">Try again</button>`
      );
      document.getElementById("retry").onclick = () => checkCurrent(tabId, url);
    }
  }
  function renderReady(url) {
    const host = new URL(url).hostname;
    shell(
      `<div class="state-banner trusted"><span class="dot green"></span> Website appears trustworthy</div><div class="host">${escape(host)}</div><div class="trust-score-row"><div><span class="trust-label">Digital Trust</span><div class="trust-val">88<small> / 100</small></div></div><span class="trust-pill trusted">TRUSTED</span></div><div class="trust-grid"><div class="trust-dim"><span>Identity</span><b>Good</b></div><div class="trust-dim"><span>Security</span><b>Good</b></div><div class="trust-dim"><span>Privacy</span><b>Good</b></div><div class="trust-dim"><span>Behavior</span><b>Good</b></div></div><button class="button" id="check">Run Deep Investigation</button><button class="button secondary" id="toggle">Turn Off Protection</button>`
    );
    document.getElementById("check").onclick = async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const current = tabs[0];
      if (current?.id && current.url && /^https?:/i.test(current.url))
        await checkCurrent(current.id, current.url);
    };
    document.getElementById("toggle").onclick = () => setProtection(false);
  }
  function showReport(report) {
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
    const identityHtml = identity ? `
      <div class="identity-box">
        <div class="identity-header">WHO AM I GIVING THIS TO?</div>
        <div class="identity-row"><span>Claimed Service</span><b>${escape(identity.claimed_service)}</b></div>
        <div class="identity-row"><span>Current Host</span><code>${escape(identity.current_website)}</code></div>
        <div class="identity-row"><span>Data Destination</span><code>${escape(identity.credential_destination)}</code></div>
        <div class="identity-row"><span>Consistency</span><b class="consist-${identity.identity_consistency.toLowerCase()}">${escape(identity.identity_consistency)}</b></div>
      </div>
    ` : "";
    const safeRouteHtml = report.safe_route ? `<a class="button action-safe" href="${escape(report.safe_route)}" target="_blank">Open Verified Official Site</a>` : "";
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
      <button class="button secondary" id="why" aria-expanded="false">Why this verdict?</button>
      <button class="button secondary" id="full">Full Dashboard</button>
    </div>

    <section class="details" id="details" hidden>
      <h2>What Should I Do?</h2>
      <div class="recommendation">
        <p>${escape(report.what_to_do || report.recommendation)}</p>
      </div>

      <h2>Evidence Attribution</h2>
      ${report.evidence.slice(0, 5).map(
      (e) => `<div class="detail"><b>${escape(e.title)}</b><span>${escape(e.category)} \xB7 ${Math.round(e.confidence * 100)}% confidence</span><p>${escape(e.description)}</p></div>`
    ).join("")}
      <div class="detail-url">${escape(report.url)}</div>
    </section>
  `);
    document.getElementById("full").onclick = () => {
      chrome.tabs.create({
        url: `http://localhost:3000/investigations/${report.id}`
      });
    };
    document.getElementById("why").onclick = () => {
      const details = document.getElementById("details");
      const button = document.getElementById("why");
      const hidden = details.hasAttribute("hidden");
      if (hidden) details.removeAttribute("hidden");
      else details.setAttribute("hidden", "");
      button.setAttribute("aria-expanded", String(hidden));
      button.textContent = hidden ? "Hide details" : "Why this verdict?";
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
      showReport(saved[`report:${tab.id}`]);
    } else {
      await checkCurrent(tab.id, tab.url);
    }
  }
  init();
})();
