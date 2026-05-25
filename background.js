const tabScripts = new Map();
const tabObservations = new Map();
const tabCopyUnlock = new Map();
const COPY_UNLOCK_STORAGE_KEY = 'aegisscope_copy_unlock_hosts_v1';
const COPY_UNLOCK_PRELOAD_ID = 'aegisscope-copy-unlock-preload';
const COPY_UNLOCK_MATCHES = ['http://*/*', 'https://*/*', 'file://*/*'];
const WEBRTC_STORAGE_KEY = 'aegisscope_webrtc_guard_v1';
const WEBRTC_PRELOAD_ID = 'aegisscope-webrtc-guard-preload';
const WEBRTC_MATCHES = ['http://*/*', 'https://*/*', 'file://*/*'];
const UA_STORAGE_KEY = 'aegisscope_ua_simple_v1';
const UA_MAIN_SCRIPT_ID = 'aegisscope-ua-simple-main';
const UA_ISOLATED_SCRIPT_ID = 'aegisscope-ua-simple-isolated';
const UA_RULE_ID_START = 330000;
const UA_RULE_ID_END = 330199;
const UA_MATCHES = ['http://*/*', 'https://*/*'];
const UA_RESOURCE_TYPES = [
  'main_frame',
  'sub_frame',
  'stylesheet',
  'script',
  'image',
  'font',
  'object',
  'xmlhttprequest',
  'ping',
  'csp_report',
  'media',
  'websocket',
  'other'
];

ensureCopyUnlockPreloadRegistered().catch(() => {});
restoreWebrtcGuard().catch(() => {});
restoreUaSimple().catch(() => {});

chrome.runtime.onInstalled.addListener(() => {
  ensureCopyUnlockPreloadRegistered().catch(() => {});
  restoreWebrtcGuard().catch(() => {});
  restoreUaSimple().catch(() => {});
});

chrome.runtime.onStartup?.addListener(() => {
  ensureCopyUnlockPreloadRegistered().catch(() => {});
  restoreWebrtcGuard().catch(() => {});
  restoreUaSimple().catch(() => {});
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

function uaProfiles() {
  return [
    ['chrome_windows', 'Chrome / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'],
    ['chrome_windows_legacy', 'Chrome 109 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'],
    ['chrome_mac', 'Chrome / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'],
    ['chrome_linux', 'Chrome / Linux', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'],
    ['edge_windows', 'Edge / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0'],
    ['edge_mac', 'Edge / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0'],
    ['edge_android', 'Edge / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 EdgA/125.0.0.0'],
    ['firefox_windows', 'Firefox / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0'],
    ['firefox_mac', 'Firefox / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0'],
    ['firefox_linux', 'Firefox / Linux', 'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0'],
    ['firefox_android', 'Firefox / Android', 'Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0'],
    ['safari_mac', 'Safari / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'],
    ['safari_ios', 'Safari / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'],
    ['safari_ipad', 'Safari / iPad', 'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'],
    ['chrome_ios', 'Chrome / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.0.0 Mobile/15E148 Safari/604.1'],
    ['edge_ios', 'Edge / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/125.0.0.0 Mobile/15E148 Safari/605.1.15'],
    ['firefox_ios', 'Firefox / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/126.0 Mobile/15E148 Safari/605.1.15'],
    ['chrome_android', 'Chrome / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36'],
    ['android_webview', 'Android WebView', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro Build/AP1A.240505.005) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36'],
    ['samsung_android', 'Samsung Internet / Android', 'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36'],
    ['opera_windows', 'Opera / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/110.0.0.0'],
    ['opera_android', 'Opera / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 OPR/82.0.0.0'],
    ['uc_android', 'UC Browser / Android', 'Mozilla/5.0 (Linux; U; Android 14; zh-CN; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 UCBrowser/15.0.0.0 Mobile Safari/537.36'],
    ['qq_android', 'QQ Browser / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 MQQBrowser/14.0 Mobile Safari/537.36'],
    ['quark_android', 'Quark / Android', 'Mozilla/5.0 (Linux; U; Android 14; zh-CN; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Quark/7.0.0.0 Mobile Safari/537.36'],
    ['wechat_windows', 'WeChat / Windows Link', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090b19) XWEB/11581 Flue'],
    ['wechat_windows_miniprogram', 'WeChat MiniProgram / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090551) XWEB/11581'],
    ['wechat_mac', 'WeChat / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/6.8.0(0x16080000) MacWechat/3.8.9(0x13080911) XWEB/1227 Flue'],
    ['wechat_ios', 'WeChat / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.62(0x18003e3a) NetType/WIFI Language/zh_CN'],
    ['wechat_ipad', 'WeChat / iPad', 'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.58(0x18003a35) NetType/WIFI Language/zh_CN'],
    ['wechat_android', 'WeChat XWeb / Android', 'Mozilla/5.0 (Linux; Android 14; M2102K1C Build/UKQ1.240624.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.136 Mobile Safari/537.36 XWEB/1340059 MMWEBSDK/20250201 MMWEBID/6946 MicroMessenger/8.0.58.2841(0x28003A35) WeChat/arm64 Weixin NetType/WIFI Language/zh_CN ABI/arm64'],
    ['wechat_android_xweb', 'WeChat XWeb / Android 12', 'Mozilla/5.0 (Linux; Android 12; FOA-AL00 Build/HUAWEIFOA-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.188 Mobile Safari/537.36 XWEB/1260117 MMWEBSDK/20240801 MMWEBID/4272 MicroMessenger/8.0.51.2720(0x28003339) WeChat/arm64 Weixin NetType/4G Language/zh_CN ABI/arm64'],
    ['wechat_android_miniprogram', 'WeChat MiniProgram / Android', 'Mozilla/5.0 (Linux; Android 11; IN2023 Build/RP1A.201005.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/78.0.3904.62 XWEB/2693 MMWEBSDK/201101 Mobile Safari/537.36 MMWEBID/8064 MicroMessenger/7.0.21.1783(0x27001543) Process/appbrand0 NetType/WIFI Language/zh_CN ABI/arm64 WeChat/arm64 miniProgram'],
    ['alipay_android', 'Alipay / Android', 'Mozilla/5.0 (Linux; U; Android 14; zh-CN; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 AlipayClient/10.5.0'],
    ['alipay_android_nebula', 'Alipay Nebula / Android', 'Mozilla/5.0 (Linux; U; Android 9; zh-CN; MRD-AL00 Build/HUAWEIMRD-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/69.0.3497.100 UWS/3.22.2.66 Mobile Safari/537.36 UCBS/3.22.2.66_230817192015 NebulaSDK/1.8.100112 Nebula AlipayDefined(nt:WIFI,ws:320|0|2.25) AliApp(AP/10.5.78.8000) AlipayClient/10.5.78.8000 Language/zh-Hans useStatusBar/true isConcaveScreen/true Region/CNAriver/1.0.0 DTN/2.0'],
    ['alipay_ios', 'Alipay / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Ariver/1.1.0 AliApp(AP/10.6.80.6000) Nebula WK RVKType(0) AlipayDefined(nt:WIFI,ws:393|788|3.0) AlipayClient/10.6.80.6000 Alipay Language/zh-Hans Region/CN NebulaX/1.0.0 DTN/2.0'],
    ['alipay_ipad', 'Alipay / iPad', 'Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Ariver/1.1.0 AliApp(AP/10.6.80.6000) Nebula WK RVKType(0) AlipayDefined(nt:WIFI,ws:820|1180|2.0) AlipayClient/10.6.80.6000 Alipay Language/zh-Hans Region/CN NebulaX/1.0.0 DTN/2.0'],
    ['alipay_windows_debug', 'Alipay Debug / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 AliApp(AP/10.6.80.6000) AlipayClient/10.6.80.6000 Alipay Language/zh-Hans Region/CN'],
    ['alipay_mac_debug', 'Alipay Debug / macOS', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 AliApp(AP/10.6.80.6000) AlipayClient/10.6.80.6000 Alipay Language/zh-Hans Region/CN'],
    ['dingtalk_android', 'DingTalk / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 DingTalk/7.6.0'],
    ['dingtalk_windows', 'DingTalk / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 DingTalk/7.6.0'],
    ['feishu_android', 'Feishu / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 Lark/7.20.0'],
    ['feishu_windows', 'Feishu / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Lark/7.20.0'],
    ['taobao_android', 'Taobao / Android', 'Mozilla/5.0 (Linux; U; Android 15; zh-CN; V2307A Build/AP3A.240905.015.A1) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.58 UWS/5.12.9.0 Mobile Safari/537.36 AliApp(TB/10.46.10) UCBS/2.11.1.1 WindVane/8.5.0'],
    ['weibo_ios', 'Weibo / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Weibo'],
    ['baiduspider', 'Baidu Spider', 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)'],
    ['googlebot', 'Googlebot', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    ['bingbot', 'Bingbot', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
    ['sogou_spider', 'Sogou Spider', 'Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)'],
    ['360_spider', '360 Spider', 'Mozilla/5.0 (compatible; 360Spider; +http://www.so.com/help/help_3_2.html)'],
    ['chrome_windows_latest', 'Chrome 126 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'],
    ['chrome_windows_old_80', 'Chrome 80 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36'],
    ['ie11_windows', 'IE 11 / Windows', 'Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko'],
    ['edge_legacy_windows', 'Edge Legacy / Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'],
    ['iphone_15_safari', 'Safari / iPhone 15', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'],
    ['huawei_android', 'Huawei Browser / Android', 'Mozilla/5.0 (Linux; Android 14; HUAWEI ALN-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 HuaweiBrowser/15.0.0.0'],
    ['xiaomi_android', 'Mi Browser / Android', 'Mozilla/5.0 (Linux; U; Android 14; zh-CN; 23127PN0CC) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/18.0.0'],
    ['vivo_android', 'vivo Browser / Android', 'Mozilla/5.0 (Linux; Android 14; V2304A) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 VivoBrowser/19.0.0.0'],
    ['oppo_android', 'OPPO Browser / Android', 'Mozilla/5.0 (Linux; Android 14; PHZ110) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 HeyTapBrowser/45.0.0.0'],
    ['baidu_android', 'Baidu App / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/125.0.0.0 Mobile Safari/537.36 baiduboxapp/13.60.0.10'],
    ['baidu_ios', 'Baidu App / iPhone', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 baiduboxapp/13.60.0.10'],
    ['toutiao_android', 'Toutiao / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 NewsArticle/9.8.0'],
    ['douyin_android', 'Douyin / Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 aweme_280000'],
    ['googlebot_mobile', 'Googlebot Smartphone', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
    ['bingbot_mobile', 'Bingbot Mobile', 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
    ['yandexbot', 'YandexBot', 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)']
  ].map(([id, name, ua]) => ({ id, name, ua }));
}

function defaultUaConfig() {
  return {
    enabled: false,
    mode: 'tab',
    tabId: null,
    host: '',
    profileId: 'chrome_windows',
    ua: '',
    exposeUserAgentData: true,
    protectedKeywords: [
      'google.com/recaptcha',
      'gstatic.com/recaptcha',
      'accounts.google.com',
      'accounts.youtube.com',
      'challenges.cloudflare.com'
    ],
    updatedAt: 0
  };
}

function normalizeUaHost(value) {
  return String(value || '').replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim().toLowerCase();
}

function normalizeUaConfig(input = {}, tabId = null) {
  const base = defaultUaConfig();
  const mode = ['tab', 'host', 'global'].includes(input.mode) ? input.mode : base.mode;
  const protectedKeywords = Array.isArray(input.protectedKeywords)
    ? input.protectedKeywords
    : String(input.protectedKeywords || '').split(/[\n,]+/);
  return {
    ...base,
    enabled: Boolean(input.enabled),
    mode,
    tabId: mode === 'tab' ? Number(input.tabId || tabId || 0) || null : null,
    host: normalizeUaHost(input.host),
    profileId: String(input.profileId || base.profileId),
    ua: String(input.ua || '').trim(),
    exposeUserAgentData: input.exposeUserAgentData !== false,
    protectedKeywords: protectedKeywords.map((item) => String(item || '').trim()).filter(Boolean),
    updatedAt: Number(input.updatedAt || Date.now())
  };
}

async function getUaConfig() {
  const data = await chrome.storage.local.get(UA_STORAGE_KEY);
  return normalizeUaConfig(data?.[UA_STORAGE_KEY]);
}

async function saveUaConfig(input, tabId) {
  const config = normalizeUaConfig({ ...input, updatedAt: Date.now() }, tabId);
  await chrome.storage.local.set({ [UA_STORAGE_KEY]: config });
  return config;
}

function selectedUa(config) {
  if (config.ua) return config.ua;
  return uaProfiles().find((profile) => profile.id === config.profileId)?.ua || uaProfiles()[0].ua;
}

function uaPayloadSignature(payload) {
  const text = JSON.stringify(payload || {});
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return String(hash >>> 0);
}

function parseUaPayload(ua, exposeUserAgentData = true) {
  const firefox = /Firefox\/([\d.]+)/i.exec(ua);
  const edge = /Edg\/([\d.]+)/i.exec(ua);
  const chrome = /(?:Chrome|CriOS)\/([\d.]+)/i.exec(ua);
  const opera = /OPR\/([\d.]+)/i.exec(ua);
  const safari = /Version\/([\d.]+).*Safari\//i.exec(ua);
  const isChromium = Boolean(chrome || edge || opera);
  const browserName = edge ? 'Microsoft Edge' : opera ? 'Opera' : chrome ? 'Google Chrome' : '';
  const version = (edge || opera || chrome || firefox || safari || [])[1] || '';
  const major = (version.split('.')[0] || '125').replace(/\D/g, '') || '125';
  const mobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile/i.test(ua);
  const ios = /iPhone|iPad|iPod/i.test(ua);
  const android = /Android/i.test(ua);
  let platform = 'Win32';
  let chPlatform = 'Windows';
  if (/Macintosh|Mac OS X/i.test(ua) && !ios) { platform = 'MacIntel'; chPlatform = 'macOS'; }
  else if (ios) { platform = /iPad/i.test(ua) ? 'iPad' : 'iPhone'; chPlatform = 'iOS'; }
  else if (android) { platform = 'Linux armv8l'; chPlatform = 'Android'; }
  else if (/Linux/i.test(ua)) { platform = 'Linux x86_64'; chPlatform = 'Linux'; }
  const payload = {
    enabled: true,
    ua,
    appVersion: firefox ? `5.0 (${ua.split('(')[1]?.split(')')[0] || ''})` : ua.replace(/^Mozilla\//, '').replace(/^Opera\//, ''),
    platform,
    vendor: safari ? 'Apple Computer, Inc.' : firefox ? '' : 'Google Inc.',
    product: ua.includes('Gecko') ? 'Gecko' : '',
    productSub: firefox ? '20100101' : '20030107',
    oscpu: firefox ? '' : '[delete]',
    buildID: firefox ? '20181001000000' : '[delete]',
    userAgentData: null
  };
  if (exposeUserAgentData && isChromium) {
    const brands = [{ brand: 'Chromium', version: major }, { brand: browserName, version: major }];
    payload.userAgentData = {
      brands,
      mobile,
      platform: chPlatform,
      architecture: android || ios ? 'arm' : 'x86',
      bitness: android || ios ? '' : '64',
      model: android ? 'Android' : '',
      platformVersion: '',
      uaFullVersion: `${major}.0.0.0`,
      fullVersionList: brands.map((item) => ({ ...item, version: `${major}.0.0.0` }))
    };
  }
  payload.signature = uaPayloadSignature(payload);
  return payload;
}

function uaClientHintHeaders(payload) {
  const names = ['sec-ch-ua-platform', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-full-version', 'sec-ch-ua-full-version-list', 'sec-ch-ua-model', 'sec-ch-ua-platform-version'];
  if (!payload.userAgentData) return names.map((header) => ({ header, operation: 'remove' }));
  const data = payload.userAgentData;
  const brands = data.brands.map((item) => `"${item.brand}";v="${item.version}"`).join(', ');
  const full = data.fullVersionList.map((item) => `"${item.brand}";v="${item.version}"`).join(', ');
  return [
    { header: 'sec-ch-ua-platform', operation: 'set', value: `"${data.platform}"` },
    { header: 'sec-ch-ua', operation: 'set', value: brands },
    { header: 'sec-ch-ua-mobile', operation: 'set', value: data.mobile ? '?1' : '?0' },
    { header: 'sec-ch-ua-arch', operation: 'set', value: `"${data.architecture}"` },
    { header: 'sec-ch-ua-bitness', operation: 'set', value: `"${data.bitness}"` },
    { header: 'sec-ch-ua-full-version', operation: 'set', value: `"${data.uaFullVersion}"` },
    { header: 'sec-ch-ua-full-version-list', operation: 'set', value: full },
    { header: 'sec-ch-ua-model', operation: 'set', value: `"${data.model}"` },
    { header: 'sec-ch-ua-platform-version', operation: 'set', value: `"${data.platformVersion}"` }
  ];
}

function uaModifyAction(payload, bridge = false) {
  const action = {
    type: 'modifyHeaders',
    requestHeaders: [
      { header: 'user-agent', operation: 'set', value: payload.ua },
      ...uaClientHintHeaders(payload)
    ]
  };
  if (bridge) {
    action.responseHeaders = [{
      header: 'server-timing',
      operation: 'set',
      value: `aegisscope-ua;dur=0;desc="${encodeURIComponent(JSON.stringify(payload))}"`
    }];
  }
  return action;
}

function uaRules(config) {
  if (!config.enabled) return [];
  if (config.mode === 'tab' && !config.tabId) return [];
  if (config.mode === 'host' && !config.host) return [];
  const payload = parseUaPayload(selectedUa(config), config.exposeUserAgentData);
  const rules = [];
  let id = UA_RULE_ID_START;
  const baseCondition = {};
  if (config.mode === 'tab') baseCondition.tabIds = [config.tabId];
  if (config.mode === 'host') baseCondition.requestDomains = [config.host];
  rules.push({
    id: id++,
    priority: config.mode === 'tab' ? 3 : 1,
    action: uaModifyAction(payload, false),
    condition: { ...baseCondition, resourceTypes: UA_RESOURCE_TYPES }
  });
  rules.push({
    id: id++,
    priority: config.mode === 'tab' ? 3 : 1,
    action: uaModifyAction(payload, true),
    condition: { ...baseCondition, resourceTypes: ['main_frame', 'sub_frame'] }
  });
  for (const keyword of config.protectedKeywords.slice(0, 40)) {
    const regexFilter = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    rules.push({
      id: id++,
      priority: 99,
      action: { type: 'allowAllRequests' },
      condition: { regexFilter, resourceTypes: ['main_frame', 'sub_frame'] }
    });
  }
  return rules;
}

async function replaceUaRules(config) {
  const existing = await chrome.declarativeNetRequest.getSessionRules();
  const removeRuleIds = (existing || []).map((rule) => rule.id).filter((id) => id >= UA_RULE_ID_START && id <= UA_RULE_ID_END);
  const addRules = uaRules(config);
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules });
  return addRules.length;
}

async function ensureUaScripts(config) {
  if (!chrome.scripting?.registerContentScripts) return false;
  const ids = [UA_MAIN_SCRIPT_ID, UA_ISOLATED_SCRIPT_ID];
  try {
    const registered = await chrome.scripting.getRegisteredContentScripts({ ids });
    if (registered?.length) await chrome.scripting.unregisterContentScripts({ ids: registered.map((item) => item.id) });
  } catch {}
  if (!config.enabled) return false;
  const common = { matches: UA_MATCHES, allFrames: true, runAt: 'document_start' };
  try {
    await chrome.scripting.registerContentScripts([{ id: UA_MAIN_SCRIPT_ID, js: ['ua-page.js'], world: 'MAIN', ...common }]);
    await chrome.scripting.registerContentScripts([{ id: UA_ISOLATED_SCRIPT_ID, js: ['ua-isolated.js'], world: 'ISOLATED', ...common }]);
    return true;
  } catch {
    return false;
  }
}

function uaConfigMatches(config, tabId, href = '') {
  if (!config.enabled) return false;
  if (config.protectedKeywords.some((item) => item && href.includes(item))) return false;
  if (config.mode === 'tab') return Number(config.tabId) === Number(tabId);
  if (config.mode === 'host') {
    const host = normalizeUaHost(getUrlHost(href));
    return host === config.host || host.endsWith(`.${config.host}`);
  }
  return config.mode === 'global';
}

async function injectUa(tabId, config) {
  if (!tabId || !config.enabled) return 0;
  const href = await getTabUrl(tabId);
  if (!uaConfigMatches(config, tabId, href)) return 0;
  const payload = parseUaPayload(selectedUa(config), config.exposeUserAgentData);
  try {
    await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['ua-page.js'], world: 'MAIN', injectImmediately: true });
    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      world: 'MAIN',
      injectImmediately: true,
      func: (data) => window.__AEGISSCOPE_APPLY_UA__?.(data, 'manual'),
      args: [payload]
    });
    return Array.isArray(results) ? results.length : 0;
  } catch {
    return 0;
  }
}

async function restoreUaSimple() {
  const config = await getUaConfig();
  await replaceUaRules(config).catch(() => {});
  await ensureUaScripts(config).catch(() => {});
}

async function getUaState(tabId) {
  const config = await getUaConfig();
  return { ok: true, config, profiles: uaProfiles(), ruleCount: uaRules(config).length };
}

async function setUaState(tabId, input, reload = false) {
  const config = await saveUaConfig(input, tabId);
  const ruleCount = await replaceUaRules(config);
  const registered = await ensureUaScripts(config);
  const injectedFrames = await injectUa(tabId, config);
  if (reload && tabId) await chrome.tabs.reload(tabId, { bypassCache: true }).catch(() => {});
  return { ok: true, config, profiles: uaProfiles(), ruleCount, registered, injectedFrames };
}

async function resetUaState(tabId) {
  const config = await saveUaConfig(defaultUaConfig(), tabId);
  const ruleCount = await replaceUaRules(config);
  const registered = await ensureUaScripts(config);
  return { ok: true, config, profiles: uaProfiles(), ruleCount, registered };
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

  if (message?.type === 'GET_UA_STATE') {
    getUaState(message.tabId)
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
    return true;
  }

  if (message?.type === 'SET_UA_STATE') {
    setUaState(message.tabId, message.config || {}, Boolean(message.reload))
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
    return true;
  }

  if (message?.type === 'RESET_UA_STATE') {
    resetUaState(message.tabId)
      .then(sendResponse)
      .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
    return true;
  }

  if (message?.type === 'GET_UA_PAYLOAD') {
    (async () => {
      const config = await getUaConfig();
      const tabId = sender.tab?.id;
      const href = message.href || sender.url || '';
      const payload = uaConfigMatches(config, tabId, href)
        ? parseUaPayload(selectedUa(config), config.exposeUserAgentData)
        : null;
      sendResponse({ ok: true, payload });
    })().catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
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
