(() => {
  // src/content.ts
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "quick-result") {
      document.documentElement.dataset.mPhishRisk = message.quick.tier;
    }
  });
})();
