const tabScripts = new Map();
const tabObservations = new Map();
const tabCopyUnlock = new Map();
const COPY_UNLOCK_STORAGE_KEY = 'aegisscope_copy_unlock_hosts_v1';
const COPY_UNLOCK_PRELOAD_ID = 'aegisscope-copy-unlock-preload';
const COPY_UNLOCK_MATCHES = ['http://*/*', 'https://*/*', 'file://*/*'];
const WEBRTC_STORAGE_KEY = 'aegisscope_webrtc_guard_v1';
const WEBRTC_PRELOAD_ID = 'aegisscope-webrtc-guard-preload';
const WEBRTC_MATCHES = ['http://*/*', 'https://*/*', 'file://*/*'];

ensureCopyUnlockPreloadRegistered().catch(() => {});
restoreWebrtcGuard().catch(() => {});

chrome.runtime.onInstalled.addListener(() => {
  ensureCopyUnlockPreloadRegistered().catch(() => {});
  restoreWebrtcGuard().catch(() => {});
});

chrome.runtime.onStartup?.addListener(() => {
  ensureCopyUnlockPreloadRegistered().catch(() => {});
  restoreWebrtcGuard().catch(() => {});
});

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
  if (changeInfo.status === 'loading') {
    tabScripts.delete(tabId);
    tabObservations.delete(tabId);
    (async () => {
      const url = changeInfo.url || await getTabUrl(tabId);
      await autoApplyCopyUnlock(tabId, url);
    })().catch(() => {});
  } else if (changeInfo.status === 'complete') {
    (async () => {
      const url = changeInfo.url || await getTabUrl(tabId);
      await autoApplyCopyUnlock(tabId, url);
    })().catch(() => {});
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabScripts.delete(tabId);
  tabObservations.delete(tabId);
  tabCopyUnlock.delete(tabId);
});

function getUrlHost(url) {
  try {
    return new URL(url || '').host;
  } catch {
    return '';
  }
}

async function getCopyUnlockHosts() {
  const data = await chrome.storage.local.get(COPY_UNLOCK_STORAGE_KEY);
  const hosts = data?.[COPY_UNLOCK_STORAGE_KEY];
  return Array.isArray(hosts) ? hosts.filter(Boolean) : [];
}

async function setCopyUnlockHost(host, enabled) {
  if (!host) return getCopyUnlockHosts();
  const hosts = await getCopyUnlockHosts();
  const next = enabled
    ? Array.from(new Set([...hosts, host]))
    : hosts.filter((item) => item !== host);
  await chrome.storage.local.set({ [COPY_UNLOCK_STORAGE_KEY]: next });
  return next;
}

async function getTabUrl(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    return tab?.url || '';
  } catch {
    return '';
  }
}

async function getCopyUnlockState(tabId) {
  const url = await getTabUrl(tabId);
  const host = getUrlHost(url);
  const hosts = await getCopyUnlockHosts();
  const tabState = tabCopyUnlock.get(tabId) || null;
  return {
    enabled: Boolean(tabState?.enabled),
    options: tabState?.options || { aggressive: true },
    host,
    hostEnabled: Boolean(host && hosts.includes(host))
  };
}

async function ensureCopyUnlockPreloadRegistered() {
  if (!chrome.scripting?.registerContentScripts) return;
  try {
    const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [COPY_UNLOCK_PRELOAD_ID] });
    if (registered?.length) await chrome.scripting.unregisterContentScripts({ ids: [COPY_UNLOCK_PRELOAD_ID] });
  } catch {}
  try {
    await chrome.scripting.registerContentScripts([{
      id: COPY_UNLOCK_PRELOAD_ID,
      matches: COPY_UNLOCK_MATCHES,
      js: ['copy-unlock.js'],
      runAt: 'document_start',
      allFrames: true,
      world: 'MAIN'
    }]);
  } catch {}
}

function defaultWebrtcConfig() {
  return {
    policy: 'default',
    strongBlock: false,
    updatedAt: 0
  };
}

function normalizeWebrtcConfig(config = {}) {
  const allowed = new Set([
    'default',
    'default_public_and_private_interfaces',
    'default_public_interface_only',
    'disable_non_proxied_udp'
  ]);
  const base = defaultWebrtcConfig();
  const policy = allowed.has(config.policy) ? config.policy : base.policy;
  return {
    policy,
    strongBlock: Boolean(config.strongBlock),
    updatedAt: Number(config.updatedAt || 0)
  };
}

function isWebrtcEnabled(config) {
  return Boolean(config && (config.policy !== 'default' || config.strongBlock));
}

async function getWebrtcConfig() {
  const data = await chrome.storage.local.get(WEBRTC_STORAGE_KEY);
  return normalizeWebrtcConfig(data?.[WEBRTC_STORAGE_KEY]);
}

async function saveWebrtcConfig(config) {
  const safe = normalizeWebrtcConfig({ ...config, updatedAt: Date.now() });
  await chrome.storage.local.set({ [WEBRTC_STORAGE_KEY]: safe });
  return safe;
}

function privacySet(setting, options) {
  return new Promise((resolve, reject) => {
    if (!setting?.set) {
      resolve(null);
      return;
    }
    try {
      setting.set(options, () => {
        const err = chrome.runtime.lastError;
        if (err) reject(new Error(err.message));
        else resolve(true);
      });
    } catch (err) {
      reject(err);
    }
  });
}

function privacyGet(setting) {
  return new Promise((resolve) => {
    if (!setting?.get) {
      resolve(null);
      return;
    }
    try {
      setting.get({}, (value) => resolve(value || null));
    } catch {
      resolve(null);
    }
  });
}

function getWebrtcApiSupport() {
  const network = chrome.privacy?.network || {};
  return {
    modern: Boolean(network.webRTCIPHandlingPolicy),
    multipleRoutes: Boolean(network.webRTCMultipleRoutesEnabled),
    nonProxiedUdp: Boolean(network.webRTCNonProxiedUdpEnabled)
  };
}

function hasWebrtcPrivacyApi() {
  const support = getWebrtcApiSupport();
  return support.modern || support.multipleRoutes || support.nonProxiedUdp;
}

function legacyWebrtcValues(policy) {
  return {
    multipleRoutes: policy === 'default' || policy === 'default_public_and_private_interfaces',
    nonProxiedUdp: policy !== 'disable_non_proxied_udp'
  };
}

async function setWebrtcPrivacyPolicy(policy) {
  const network = chrome.privacy?.network;
  const support = getWebrtcApiSupport();
  if (!hasWebrtcPrivacyApi()) {
    throw new Error('当前浏览器不支持 WebRTC 隐私策略 API');
  }
  if (support.modern) {
    await privacySet(network.webRTCIPHandlingPolicy, { value: policy, scope: 'regular' });
  }
  const legacy = legacyWebrtcValues(policy);
  if (support.multipleRoutes) {
    await privacySet(network.webRTCMultipleRoutesEnabled, { value: legacy.multipleRoutes, scope: 'regular' }).catch(() => {});
  }
  if (support.nonProxiedUdp) {
    await privacySet(network.webRTCNonProxiedUdpEnabled, {
      value: legacy.nonProxiedUdp,
      scope: 'regular'
    }).catch(() => {});
  }
  if (support.modern) return privacyGet(network.webRTCIPHandlingPolicy);
  return { value: policy };
}

async function ensureWebrtcPreloadRegistered(strongBlock) {
  if (!chrome.scripting?.registerContentScripts) return false;
  try {
    const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [WEBRTC_PRELOAD_ID] });
    if (registered?.length) await chrome.scripting.unregisterContentScripts({ ids: [WEBRTC_PRELOAD_ID] });
  } catch {}
  if (!strongBlock) return false;
  try {
    await chrome.scripting.registerContentScripts([{
      id: WEBRTC_PRELOAD_ID,
      matches: WEBRTC_MATCHES,
      js: ['webrtc-guard.js'],
      runAt: 'document_start',
      allFrames: true,
      world: 'MAIN'
    }]);
    return true;
  } catch {
    return false;
  }
}

async function injectWebrtcGuard(tabId) {
  if (!tabId) return 0;
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ['webrtc-guard.js'],
      world: 'MAIN',
      injectImmediately: true
    });
    return Array.isArray(results) ? results.length : 0;
  } catch (err) {
    const message = err.message || '';
    if (/Unexpected property|Invalid value for 'world'|injectImmediately/i.test(message)) {
      const results = await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        files: ['webrtc-guard.js']
      });
      return Array.isArray(results) ? results.length : 0;
    }
    if (/Cannot access|Missing host permission|No frame|The extensions gallery cannot be scripted|Cannot script/i.test(message)) {
      return 0;
    }
    throw err;
  }
}

async function getWebrtcState() {
  const config = await getWebrtcConfig();
  let currentPolicy = null;
  const support = getWebrtcApiSupport();
  let apiSupported = hasWebrtcPrivacyApi();
  if (support.modern) currentPolicy = await privacyGet(chrome.privacy.network.webRTCIPHandlingPolicy);
  let registered = false;
  try {
    const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [WEBRTC_PRELOAD_ID] });
    registered = Boolean(scripts?.length);
  } catch {}
  return {
    ok: true,
    enabled: isWebrtcEnabled(config),
    apiSupported,
    support,
    registered,
    config,
    currentPolicy: currentPolicy?.value || ''
  };
}

async function applyWebrtcGuard(tabId, input = {}) {
  const next = normalizeWebrtcConfig(input);
  const saved = await saveWebrtcConfig(next);
  const apiSupported = hasWebrtcPrivacyApi();
  if (!apiSupported && saved.policy !== 'default' && !saved.strongBlock) {
    throw new Error('当前浏览器未开放 WebRTC 隐私策略 API，可勾选强阻断模式后继续防护');
  }
  let currentPolicy = { value: saved.policy };
  let privacyError = '';
  if (apiSupported) {
    try {
      currentPolicy = await setWebrtcPrivacyPolicy(saved.policy);
    } catch (err) {
      privacyError = err.message || String(err);
      if (!saved.strongBlock) throw err;
    }
  } else if (saved.policy !== 'default') {
    privacyError = '当前浏览器未开放 WebRTC 隐私策略 API，已使用页面强阻断模式';
  }
  const registered = await ensureWebrtcPreloadRegistered(saved.strongBlock);
  const injectedFrames = saved.strongBlock ? await injectWebrtcGuard(tabId) : 0;
  return {
    ok: true,
    enabled: isWebrtcEnabled(saved),
    apiSupported,
    config: saved,
    currentPolicy: currentPolicy?.value || saved.policy,
    privacyError,
    registered,
    injectedFrames
  };
}

async function restoreWebrtcGuard() {
  const config = await getWebrtcConfig();
  if (isWebrtcEnabled(config) && hasWebrtcPrivacyApi()) {
    await setWebrtcPrivacyPolicy(config.policy).catch(() => {});
  }
  await ensureWebrtcPreloadRegistered(config.strongBlock).catch(() => {});
}

async function testWebrtcPage(tabId) {
  if (!tabId) return { ok: false, error: 'Missing tabId' };
  const results = await chrome.scripting.executeScript({
    target: { tabId, allFrames: true },
    world: 'MAIN',
    func: () => {
      const mediaDevices = navigator.mediaDevices || null;
      const exposed = {
        RTCPeerConnection: typeof window.RTCPeerConnection !== 'undefined' || typeof window.webkitRTCPeerConnection !== 'undefined' || typeof window.mozRTCPeerConnection !== 'undefined',
        RTCSessionDescription: typeof window.RTCSessionDescription !== 'undefined' || typeof window.webkitRTCSessionDescription !== 'undefined' || typeof window.mozRTCSessionDescription !== 'undefined',
        getUserMedia: typeof navigator.getUserMedia !== 'undefined' || typeof navigator.webkitGetUserMedia !== 'undefined' || typeof navigator.mozGetUserMedia !== 'undefined',
        mediaDevices: Boolean(mediaDevices),
        enumerateDevices: typeof mediaDevices?.enumerateDevices === 'function',
        RTCDataChannel: typeof window.RTCDataChannel !== 'undefined',
        RTCIceCandidate: typeof window.RTCIceCandidate !== 'undefined'
      };
      return { href: location.href, exposed };
    }
  });
  const frames = (results || []).map((item) => item?.result).filter(Boolean);
  const exposedCount = frames.reduce((sum, frame) => sum + Object.values(frame.exposed || {}).filter(Boolean).length, 0);
  return {
    ok: true,
    frames: frames.length,
    exposedCount,
    protected: exposedCount === 0,
    details: frames.slice(0, 10)
  };
}

async function injectCopyUnlock(tabId, enabled, options = {}) {
  const target = { tabId, allFrames: true };
  try {
    await chrome.scripting.executeScript({
      target,
      files: ['copy-unlock.js'],
      world: 'MAIN',
      injectImmediately: true
    });
  } catch (err) {
    const message = err.message || '';
    if (/Unexpected property|Invalid value for 'world'|injectImmediately/i.test(message)) {
      await chrome.scripting.executeScript({
        target,
        files: ['copy-unlock.js']
      });
    } else if (!/Cannot access|Missing host permission|No frame|The extensions gallery cannot be scripted|Cannot script/i.test(message)) {
      throw err;
    }
  }
  let results;
  try {
    results = await chrome.scripting.executeScript({
      target,
      world: 'MAIN',
      injectImmediately: true,
      func: (payload) => window.__AEGISSCOPE_COPY_UNLOCK__?.apply(payload),
      args: [{ enabled, options }]
    });
  } catch (err) {
    const message = err.message || '';
    if (!/Unexpected property|Invalid value for 'world'|injectImmediately/i.test(message)) throw err;
    results = await chrome.scripting.executeScript({
      target,
      func: (payload) => window.__AEGISSCOPE_COPY_UNLOCK__?.apply(payload),
      args: [{ enabled, options }]
    });
  }
  return (results || []).map((item) => item?.result).filter(Boolean);
}

async function applyCopyUnlock(tabId, enabled, options = {}, hostEnabled = false) {
  const url = await getTabUrl(tabId);
  const host = getUrlHost(url);
  const safeOptions = {
    aggressive: options.aggressive !== false,
    persist: Boolean(enabled && hostEnabled)
  };
  if (host) await setCopyUnlockHost(host, Boolean(enabled && hostEnabled));
  const frameStates = await injectCopyUnlock(tabId, Boolean(enabled), safeOptions);
  if (enabled) {
    tabCopyUnlock.set(tabId, { enabled: true, options: safeOptions, host, updatedAt: Date.now() });
  } else {
    tabCopyUnlock.delete(tabId);
  }
  const hosts = await getCopyUnlockHosts();
  return {
    ok: true,
    enabled: Boolean(enabled),
    options: safeOptions,
    host,
    hostEnabled: Boolean(host && hosts.includes(host)),
    frames: frameStates.length,
    scanned: frameStates.reduce((sum, item) => sum + (item.scanned || 0), 0),
    changed: frameStates.reduce((sum, item) => sum + (item.changed || 0), 0),
    blockedListeners: frameStates.reduce((sum, item) => sum + (item.blockedListeners || 0), 0),
    copiedFallbacks: frameStates.reduce((sum, item) => sum + (item.copiedFallbacks || 0), 0),
    adapterHits: frameStates.reduce((sum, item) => sum + (item.adapterHits || 0), 0),
    lastAdapter: frameStates.map((item) => item.lastAdapter).filter(Boolean)[0] || ''
  };
}

async function autoApplyCopyUnlock(tabId, url) {
  const host = getUrlHost(url);
  if (!host) return;
  const hosts = await getCopyUnlockHosts();
  if (!hosts.includes(host)) return;
  await applyCopyUnlock(tabId, true, { aggressive: true }, true);
}

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

  if (message?.type === 'GET_COPY_UNLOCK_STATE') {
    getCopyUnlockState(message.tabId)
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (message?.type === 'SET_COPY_UNLOCK') {
    (async () => {
      try {
        const result = await applyCopyUnlock(message.tabId, message.enabled, message.options || {}, message.hostEnabled);
        sendResponse(result || { ok: false, error: '解除复制未返回结果' });
      } catch (err) {
        sendResponse({ ok: false, error: err.message || String(err) });
      }
    })();
    return true;
  }

  if (message?.type === 'GET_WEBRTC_STATE') {
    getWebrtcState()
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
    return true;
  }

  if (message?.type === 'SET_WEBRTC_GUARD') {
    (async () => {
      try {
        const result = await applyWebrtcGuard(message.tabId, message.config || {});
        sendResponse(result || { ok: false, error: 'WebRTC guard returned no result' });
      } catch (err) {
        sendResponse({ ok: false, error: err.message || String(err) });
      }
    })();
    return true;
  }

  if (message?.type === 'TEST_WEBRTC_PAGE') {
    testWebrtcPage(message.tabId)
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
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
