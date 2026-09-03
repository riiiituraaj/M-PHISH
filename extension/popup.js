(() => {
  // src/popup.ts
  var API = "https://m-phish.onrender.com";
  var root = document.getElementById("app");
  var escape = (value) => value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  function shell(body) {
    root.innerHTML = `<div class="card"><div class="brand"><img src="icon.svg" alt=""><span>M-PHISH <b>X</b></span></div>${body}</div>`;
  }
  function renderOff() {
    shell('<div class="eyebrow">Protection is off</div><p class="summary">M-PHISH X is not monitoring browser navigation.</p><button class="button" id="toggle">Turn On</button>');
    document.getElementById("toggle").onclick = () => setProtection(true);
  }
  function setProtection(enabled) {
    chrome.storage.local.set({ protectionEnabled: enabled }).then(init);
  }
  async function checkCurrent(tabId, url) {
    let stage = "quick check";
    shell('<div class="progress"><b>\u25CF</b> Address<br><b>\u25CF</b> Domain<br><b>\u25CF</b> Page<br><span>\u25CB</span> Risk</div>');
    try {
      const quickResponse = await fetch(`${API}/api/quick-check`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, context: { tab_id: tabId } }) });
      if (!quickResponse.ok) throw new Error(`Quick check returned HTTP ${quickResponse.status}`);
      const quick = await quickResponse.json();
      if (!quick.deep_required) {
        renderReady(url);
        return;
      }
      stage = "deep analysis";
      const reportResponse = await fetch(`${API}/api/investigations`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, context: { tab_id: tabId } }) });
      if (!reportResponse.ok) throw new Error(`Deep analysis returned HTTP ${reportResponse.status}`);
      showReport(await reportResponse.json());
    } catch (error) {
      const message = error instanceof Error ? error.message : `${stage} failed`;
      shell(`<p class="summary">${escape(message)}. Confirm the M-PHISH X backend is running.</p><button class="button secondary" id="retry">Try again</button>`);
      document.getElementById("retry").onclick = () => checkCurrent(tabId, url);
    }
  }
  function renderReady(url) {
    const host = new URL(url).hostname;
    shell(`<div class="eyebrow">Protection ON</div><div class="host">${escape(host)}</div><p class="summary">Quietly checking new websites for warning signs. No detailed report is available for this page yet.</p><button class="button" id="check">Check this page</button><button class="button secondary" id="toggle">Turn Off</button>`);
    document.getElementById("check").onclick = async () => {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const current = tabs[0];
      if (current?.id && current.url && /^https?:/i.test(current.url)) await checkCurrent(current.id, current.url);
      else shell('<p class="summary">The active tab is no longer an HTTP(S) page.</p>');
    };
    document.getElementById("toggle").onclick = () => setProtection(false);
  }
  function showReport(report) {
    shell(`<div class="score">${report.risk_score}<small> / 100</small></div><div class="risk">${escape(report.classification)}</div><p class="summary">${escape(report.summary)}</p>${report.evidence.slice(0, 3).map((e) => `<div class="reason">${escape(e.title)}</div>`).join("")}<button class="button secondary" id="why" aria-expanded="false">Why this result</button><button class="button" id="full">Full Report</button><section class="details" id="details" hidden><h2>Why this result?</h2>${report.evidence.slice(0, 5).map((e) => `<div class="detail"><b>${escape(e.title)}</b><span>${escape(e.category)} \xB7 ${Math.round(e.confidence * 100)}% confidence${e.weight ? ` \xB7 +${e.weight}` : ""}</span><p>${escape(e.description)}</p></div>`).join("")}<div class="recommendation"><b>Safer next step</b><p>${escape(report.recommendation)}</p></div><div class="detail-url">${escape(report.url)}</div></section>`);
    document.getElementById("full").onclick = () => chrome.tabs.create({ url: `https://m-phish.vercel.app/investigations/${report.id}` });
    document.getElementById("why").onclick = () => {
      const details = document.getElementById("details");
      const button = document.getElementById("why");
      const hidden = details.hasAttribute("hidden");
      if (hidden) details.removeAttribute("hidden");
      else details.setAttribute("hidden", "");
      button.setAttribute("aria-expanded", String(hidden));
      button.textContent = hidden ? "Hide details" : "Why this result";
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
      shell('<p class="summary">Open a regular website to use M-PHISH X.</p>');
      return;
    }
    const saved = await chrome.storage.local.get(`report:${tab.id}`);
    if (saved[`report:${tab.id}`]) showReport(saved[`report:${tab.id}`]);
    else await checkCurrent(tab.id, tab.url);
  }
  init();
})();
