const tabScripts = new Map();
const tabObservations = new Map();

function getTabBucket(tabId) {
  if (!tabScripts.has(tabId)) {
    tabScripts.set(tabId, new Map());
  }
  return tabScripts.get(tabId);
}

function getObservation(tabId) {
  if (!tabObservations.has(tabId)) {
    tabObservations.set(tabId, {
      main: null,
      resources: new Map(),
      updatedAt: Date.now()
    });
  }
  return tabObservations.get(tabId);
}

function normalizeHeaders(responseHeaders = []) {
  const headers = {};
  for (const header of responseHeaders || []) {
    const name = String(header?.name || '').toLowerCase();
    if (!name) continue;
    headers[name] = headers[name] || [];
    headers[name].push(String(header.value || header.binaryValue || ''));
  }
  return headers;
}

function recordObservation(details) {
  if (details.tabId < 0 || !details.url) return;
  if (!/^https?:|^file:/.test(details.url)) return;
  const observation = getObservation(details.tabId);
  const item = {
    url: details.url,
    method: details.method,
    statusCode: details.statusCode,
    statusLine: details.statusLine,
    ip: details.ip || '',
    fromCache: details.fromCache,
    type: details.type,
    frameId: details.frameId,
    parentFrameId: details.parentFrameId,
    headers: normalizeHeaders(details.responseHeaders),
    lastSeen: Date.now()
  };

  if (details.type === 'main_frame' && details.frameId === 0) {
    observation.main = item;
  }

  const key = `${details.type}:${details.url}`;
  observation.resources.set(key, item);
  if (observation.resources.size > 800) {
    const first = observation.resources.keys().next().value;
    observation.resources.delete(first);
  }
  observation.updatedAt = Date.now();
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
    recordObservation(details);
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
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading' && changeInfo.url) {
    tabScripts.delete(tabId);
    tabObservations.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScripts.delete(tabId);
  tabObservations.delete(tabId);
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

  if (message?.type === 'GET_SNIFF_DATA') {
    const observation = tabObservations.get(message.tabId);
    sendResponse({
      main: observation?.main || null,
      resources: observation ? Array.from(observation.resources.values()) : [],
      scripts: tabScripts.get(message.tabId) ? Array.from(tabScripts.get(message.tabId).values()) : [],
      updatedAt: observation?.updatedAt || 0
    });
    return true;
  }

  if (message?.type === 'CLEAR_SCRIPTS') {
    tabScripts.delete(message.tabId);
    tabObservations.delete(message.tabId);
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
