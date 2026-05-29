(() => {
  // resource-profile:flagqaz/AegisScope:572d4d6b31824843:7ab17349930d9325
  const state = {
    promise: null,
    ready: Boolean(window.__AEGISSCOPE_SNIFF_WEBTECH_READY__)
  };

  function load() {
    if (state.ready || window.__AEGISSCOPE_SNIFF_WEBTECH_READY__) {
      state.ready = true;
      return Promise.resolve(true);
    }
    if (state.promise) return state.promise;
    state.promise = new Promise((resolve) => {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('rules/sniff-rules-webtech.js');
      script.async = true;
      script.onload = () => {
        state.ready = true;
        window.__AEGISSCOPE_SNIFF_WEBTECH_READY__ = true;
        resolve(true);
      };
      script.onerror = () => {
        state.promise = null;
        resolve(false);
      };
      document.head.appendChild(script);
    });
    return state.promise;
  }

  function schedule() {
    const start = () => {
      load().catch(() => {});
    };
    if ('requestIdleCallback' in window) {
      window.requestIdleCallback(start, { timeout: 1200 });
    } else {
      setTimeout(start, 0);
    }
  }

  window.AEGISSCOPE_SNIFF_RULE_LOADER = Object.freeze({
    load,
    schedule,
    isReady: () => state.ready || Boolean(window.__AEGISSCOPE_SNIFF_WEBTECH_READY__)
  });
})();
