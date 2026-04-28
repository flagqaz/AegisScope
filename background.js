const tabScripts = new Map();

function getTabBucket(tabId) {
  if (!tabScripts.has(tabId)) {
    tabScripts.set(tabId, new Map());
  }
  return tabScripts.get(tabId);
}

function recordScript(tabId, url, meta = {}) {
  if (tabId < 0 || !url) return;
  if (!/^https?:|^file:|^blob:|^data:/.test(url)) return;
  const bucket = getTabBucket(tabId);
  const existing = bucket.get(url) || { url, count: 0, source: 'network' };
  existing.count += 1;
  existing.method = meta.method || existing.method;
  existing.statusCode = meta.statusCode ?? existing.statusCode;
  existing.fromCache = meta.fromCache ?? existing.fromCache;
  existing.type = meta.type || existing.type || 'script';
  existing.lastSeen = Date.now();
  bucket.set(url, existing);
}

chrome.webRequest.onCompleted.addListener(
  (details) => {
    if (details.tabId < 0) return;
    const isScript = details.type === 'script' || /\.m?js(\?|$)/i.test(details.url);
    if (!isScript) return;
    recordScript(details.tabId, details.url, {
      method: details.method,
      statusCode: details.statusCode,
      fromCache: details.fromCache,
      type: details.type
    });
  },
  { urls: ['<all_urls>'] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    tabScripts.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScripts.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'GET_SCRIPTS') {
    const tabId = message.tabId;
    const bucket = tabScripts.get(tabId);
    sendResponse({
      scripts: bucket ? Array.from(bucket.values()) : []
    });
    return true;
  }

  if (message?.type === 'CLEAR_SCRIPTS') {
    tabScripts.delete(message.tabId);
    sendResponse({ ok: true });
    return true;
  }

  if (message?.type === 'CONTENT_SCRIPTS_FOUND') {
    const tabId = sender.tab?.id;
    if (tabId == null) {
      sendResponse({ ok: false });
      return true;
    }
    for (const item of message.items || []) {
      if (item.url) {
        recordScript(tabId, item.url, { type: 'script' });
        const entry = getTabBucket(tabId).get(item.url);
        if (entry) entry.source = 'dom';
      }
    }
    if (message.inline?.length) {
      const bucket = getTabBucket(tabId);
      for (const inline of message.inline) {
        const key = `inline:${inline.hash}`;
        bucket.set(key, {
          url: key,
          inline: true,
          content: inline.content,
          length: inline.length,
          source: 'inline',
          lastSeen: Date.now()
        });
      }
    }
    sendResponse({ ok: true });
    return true;
  }
});
