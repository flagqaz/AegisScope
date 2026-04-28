const els = {
  list: document.getElementById('list'),
  empty: document.getElementById('empty'),
  count: document.getElementById('count'),
  status: document.getElementById('status'),
  search: document.getElementById('search'),
  filterType: document.getElementById('filterType'),
  refresh: document.getElementById('refresh'),
  downloadAll: document.getElementById('downloadAll'),
  securityScan: document.getElementById('securityScan'),
  vulnScan: document.getElementById('vulnScan'),
  vueTools: document.getElementById('vueTools'),
  clear: document.getElementById('clear'),
  rowTpl: document.getElementById('row-tpl'),
  viewer: document.getElementById('viewer'),
  viewerTitle: document.getElementById('viewer-title'),
  viewerContent: document.getElementById('viewer-content'),
  viewerClose: document.getElementById('viewer-close'),
  termsDialog: document.getElementById('termsDialog'),
  termsAcceptCheck: document.getElementById('termsAcceptCheck'),
  termsAgree: document.getElementById('termsAgree'),
  termsDecline: document.getElementById('termsDecline')
};

let currentTabId = null;
let currentTabHost = '';
let scripts = [];
const downloadFetchCache = new Map();
const TERMS_ACCEPTED_KEY = 'aegisscope_terms_accepted_v1';

bootstrap().catch((err) => setStatus(`初始化失败: ${err.message}`));

async function bootstrap() {
  const accepted = await hasAcceptedTerms();
  if (!accepted) await requireTermsAcceptance();
  await init();
}

async function hasAcceptedTerms() {
  try {
    const data = await chrome.storage.local.get(TERMS_ACCEPTED_KEY);
    return Boolean(data?.[TERMS_ACCEPTED_KEY]);
  } catch {
    return false;
  }
}

function requireTermsAcceptance() {
  return new Promise((resolve) => {
    const dialog = els.termsDialog;
    const checkbox = els.termsAcceptCheck;
    const agree = els.termsAgree;
    const decline = els.termsDecline;
    agree.disabled = true;
    checkbox.checked = false;
    checkbox.addEventListener('change', () => {
      agree.disabled = !checkbox.checked;
    });
    agree.addEventListener('click', async () => {
      if (!checkbox.checked) return;
      await chrome.storage.local.set({ [TERMS_ACCEPTED_KEY]: true });
      dialog.close('accepted');
      resolve();
    }, { once: true });
    decline.addEventListener('click', () => window.close(), { once: true });
    dialog.addEventListener('cancel', (event) => event.preventDefault());
    if (typeof dialog.showModal === 'function') dialog.showModal();
  });
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    setStatus('未找到活动标签页');
    return;
  }
  currentTabId = tab.id;
  try { currentTabHost = new URL(tab.url).host; } catch { currentTabHost = ''; }

  await scanPage();
  await loadScripts();

  els.refresh.addEventListener('click', async () => {
    setStatus('正在重新扫描...');
    await scanPage();
    await loadScripts();
  });
  els.downloadAll.addEventListener('click', downloadAll);
  els.securityScan.addEventListener('click', openSecurityScan);
  els.vulnScan.addEventListener('click', openVulnScan);
  els.vueTools.addEventListener('click', openVueTools);
  els.clear.addEventListener('click', clearScripts);
  els.search.addEventListener('input', render);
  els.filterType.addEventListener('change', render);
  els.viewerClose.addEventListener('click', () => els.viewer.close());
}

async function scanPage() {
  try {
    await chrome.scripting.executeScript({
      target: { tabId: currentTabId, allFrames: true },
      files: ['content.js']
    });
  } catch (err) {
    setStatus(`扫描失败 (可能为受限页面): ${err.message}`);
  }
}

async function loadScripts() {
  const resp = await chrome.runtime.sendMessage({ type: 'GET_SCRIPTS', tabId: currentTabId });
  scripts = resp?.scripts || [];
  render();
  setStatus(`共 ${scripts.length} 条记录 · ${currentTabHost || '当前页面'}`);
}

function render() {
  const keyword = els.search.value.trim().toLowerCase();
  const filter = els.filterType.value;

  const filtered = scripts.filter((s) => {
    if (filter === 'external' && s.inline) return false;
    if (filter === 'inline' && !s.inline) return false;
    if (filter === 'thirdparty') {
      if (s.inline) return false;
      try {
        const host = new URL(s.url).host;
        if (!currentTabHost || host === currentTabHost || host.endsWith('.' + currentTabHost)) return false;
      } catch { return false; }
    }
    if (!keyword) return true;
    return (s.url || '').toLowerCase().includes(keyword) ||
           (s.content || '').toLowerCase().includes(keyword);
  });

  els.list.innerHTML = '';
  els.count.textContent = String(filtered.length);
  els.empty.classList.toggle('visible', filtered.length === 0);

  for (const s of filtered) {
    els.list.appendChild(renderRow(s));
  }
}

function renderRow(s) {
  const node = els.rowTpl.content.cloneNode(true);
  const li = node.querySelector('.row');
  const urlEl = node.querySelector('.url');
  const metaEl = node.querySelector('.meta');
  const checkbox = node.querySelector('.select');

  if (s.inline) {
    urlEl.textContent = `[内联脚本] ${s.length} 字符`;
    urlEl.title = '内联脚本';
    metaEl.innerHTML = '<span class="tag inline">inline</span>';
    node.querySelector('.download').textContent = '保存';
    node.querySelector('.open').disabled = true;
  } else {
    urlEl.textContent = s.url;
    urlEl.title = s.url;
    const tags = [];
    if (s.fromCache) tags.push('<span class="tag cache">cache</span>');
    if (isThirdParty(s.url)) tags.push('<span class="tag thirdparty">3rd</span>');
    if (s.statusCode) tags.push(`<span class="tag">${s.statusCode}</span>`);
    if (s.method && s.method !== 'GET') tags.push(`<span class="tag">${s.method}</span>`);
    metaEl.innerHTML = tags.join(' ');
  }

  checkbox.dataset.key = s.url;

  li.querySelector('.copy').addEventListener('click', () => copyText(s.inline ? s.content : s.url));
  li.querySelector('.open').addEventListener('click', () => {
    if (!s.inline) chrome.tabs.create({ url: s.url });
  });
  li.querySelector('.download').addEventListener('click', () => downloadOne(s));
  li.querySelector('.view').addEventListener('click', () => viewScript(s));

  return node;
}

function isThirdParty(url) {
  if (!currentTabHost) return false;
  try {
    const host = new URL(url).host;
    return host && host !== currentTabHost && !host.endsWith('.' + currentTabHost);
  } catch { return false; }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text || '');
    setStatus('已复制');
  } catch (err) {
    setStatus(`复制失败: ${err.message}`);
  }
}

function getFilenameFromUrl(url) {
  try {
    const u = new URL(url);
    const last = u.pathname.split('/').filter(Boolean).pop() || 'script.js';
    return last.includes('.') ? last : last + '.js';
  } catch {
    return 'script.js';
  }
}

async function downloadOne(s) {
  if (s.inline) {
    const blob = new Blob([s.content || ''], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    await chrome.downloads.download({
      url,
      filename: `js-extractor/${currentTabHost || 'inline'}/inline-${s.url.replace('inline:', '')}.js`,
      saveAs: false
    });
    return;
  }
  await chrome.downloads.download({
    url: s.url,
    filename: `js-extractor/${currentTabHost || 'site'}/${getFilenameFromUrl(s.url)}`,
    saveAs: false
  });
}

async function downloadAll() {
  downloadFetchCache.clear();
  setStatus('正在收集页面代码...');
  await scanPage();
  await loadScripts();

  const files = [];
  const failures = [];
  const usedNames = new Set();
  const snapshot = await getPageSnapshot();
  const host = currentTabHost || snapshot.host || 'site';

  if (snapshot.html) {
    addZipFile(files, usedNames, 'page/index.html', snapshot.html);
  } else if (snapshot.error) {
    failures.push(`HTML: ${snapshot.error}`);
  }

  const resources = new Map();
  for (const s of scripts) {
    if (s.inline) continue;
    resources.set(s.url, { url: s.url, kind: 'script' });
  }
  for (const item of snapshot.resources || []) {
    if (!item.url) continue;
    resources.set(item.url, item);
  }

  const queue = Array.from(resources.values());
  const queued = new Set(queue.map((item) => item.url));
  const enqueue = (url, kind = 'resource') => {
    if (!url || queued.has(url)) return;
    queued.add(url);
    queue.push({ url, kind, discovered: true });
  };

  let done = 0;
  for (let i = 0; i < queue.length && i < 600; i++) {
    const item = queue[i];
    done++;
    setStatus(`正在打包 ${done} / ${queue.length}: ${truncateText(item.url, 60)}`);
    try {
      const fetched = await fetchCodeResource(item.url);
      const path = makeZipPath(item.url, item.kind || 'resource');
      addZipFile(files, usedNames, path, fetched.data);
      for (const related of discoverDownloadRelatedCodeUrls(fetched.text, item.url)) {
        enqueue(related, /\.map(?:[?#]|$)/i.test(related) ? 'sourcemap' : 'script');
      }
    } catch (err) {
      failures.push(`${item.url}: ${err.message}`);
    }
  }

  for (const s of scripts.filter((x) => x.inline)) {
    const hash = s.url.replace('inline:', '') || String(Date.now());
    addZipFile(files, usedNames, `inline/inline-${safeName(hash)}.js`, s.content || '');
  }

  if (!files.length) {
    setStatus('无可下载内容');
    return;
  }

  setStatus(`正在生成 ZIP，${files.length} 个文件...`);
  const zipBlob = createZip(files);
  const url = URL.createObjectURL(zipBlob);
  await chrome.downloads.download({
    url,
    filename: `js-extractor/${safeName(host)}-code-${Date.now()}.zip`,
    saveAs: true
  });
  setStatus(`已生成 ZIP：${files.length} 个文件，失败 ${failures.length} 个`);
}

async function getPageSnapshot() {
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: currentTabId },
      func: collectPageCodeSnapshot
    });
    return result?.result || { resources: [] };
  } catch (err) {
    return { resources: [], error: err.message };
  }
}

function collectPageCodeSnapshot() {
  const excludedExt = new Set([
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico',
    '.svg', '.tif', '.tiff', '.mp4', '.webm', '.mp3', '.wav', '.ogg', '.woff',
    '.woff2', '.ttf', '.otf', '.eot'
  ]);
  const codeExt = new Set([
    '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
    '.json', '.map', '.wasm', '.html', '.htm', '.xml', '.txt'
  ]);
  const resources = new Map();

  const extOf = (url) => {
    try {
      const pathname = new URL(url).pathname.toLowerCase();
      const filename = pathname.split('/').pop() || '';
      const dot = filename.lastIndexOf('.');
      return dot >= 0 ? filename.slice(dot) : '';
    } catch {
      return '';
    }
  };

  const isCodeUrl = (url, kind) => {
    const ext = extOf(url);
    if (excludedExt.has(ext)) return false;
    if (kind === 'script' || kind === 'document') return true;
    return codeExt.has(ext);
  };

  const add = (rawUrl, kind = 'resource') => {
    if (!rawUrl) return;
    let absolute;
    try {
      absolute = new URL(rawUrl, location.href).href;
    } catch {
      return;
    }
    if (!isCodeUrl(absolute, kind)) return;
    resources.set(absolute, { url: absolute, kind });
  };

  for (const el of document.querySelectorAll('script[src]')) add(el.src || el.getAttribute('src'), 'script');
  for (const el of document.querySelectorAll('iframe[src], frame[src]')) add(el.src || el.getAttribute('src'), 'document');
  for (const el of document.querySelectorAll('link[href]')) {
    const rel = (el.rel || '').toLowerCase();
    const as = (el.as || '').toLowerCase();
    if (rel.includes('stylesheet') || rel.includes('icon') || (rel.includes('preload') && as === 'style')) continue;
    add(el.href || el.getAttribute('href'), rel.includes('manifest') ? 'manifest' : 'resource');
  }
  for (const entry of performance.getEntriesByType('resource')) {
    add(entry.name, entry.initiatorType === 'script' ? 'script' : 'resource');
  }

  return {
    url: location.href,
    host: location.host,
    title: document.title,
    html: '<!DOCTYPE html>\n' + document.documentElement.outerHTML,
    resources: Array.from(resources.values())
  };
}

async function fetchCodeResource(url) {
  if (downloadFetchCache.has(url)) return downloadFetchCache.get(url);
  let sameOrigin = false;
  try {
    sameOrigin = currentTabHost && new URL(url).host === currentTabHost;
  } catch { /* ignore */ }
  const res = await fetch(url, { credentials: sameOrigin ? 'include' : 'omit', cache: 'force-cache' });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = new Uint8Array(await res.arrayBuffer());
  let text = '';
  if (data.length <= 8 * 1024 * 1024) {
    try { text = new TextDecoder('utf-8').decode(data); } catch { text = ''; }
  }
  const item = { data, text };
  downloadFetchCache.set(url, item);
  if (downloadFetchCache.size > 800) {
    const first = downloadFetchCache.keys().next().value;
    downloadFetchCache.delete(first);
  }
  return item;
}

function discoverDownloadRelatedCodeUrls(source, baseUrl) {
  if (!source || typeof source !== 'string') return [];
  const out = new Set();
  const add = (raw) => {
    if (!isDownloadCodeUrl(raw)) return;
    try {
      const u = new URL(raw, baseUrl);
      out.add(u.href);
    } catch { /* ignore */ }
  };

  let m;
  const mapRe = /\/\/[#@]\s*sourceMappingURL=([^\s"'<>]+)/g;
  while ((m = mapRe.exec(source)) !== null) add(m[1]);

  const stringRe = /["'`]((?:(?:https?:)?\/\/|\/|\.{1,2}\/|(?:static|assets|js|dist|chunks|_next|_nuxt)\/)[^"'`\s<>]{1,220}\.(?:js|mjs|cjs|map)(?:\?[^"'`\s<>]*)?)["'`]/gi;
  while ((m = stringRe.exec(source)) !== null) add(m[1]);

  if (/\b(?:__webpack_require__|webpackChunk|webpackJsonp|__webpack_modules__)\b/.test(source)) {
    const basePath = guessDownloadWebpackBasePath(source, baseUrl);
    const pairMapRe = /\{\s*((?:"?[\w@~.-]+"?\s*:\s*"?[\w@~.-]+"?\s*,?\s*){2,})\}/g;
    let mm, maps = 0;
    while ((mm = pairMapRe.exec(source.slice(0, 250000))) !== null && maps < 8) {
      maps++;
      const pairs = [...mm[1].matchAll(/"?([\w@~.-]+)"?\s*:\s*"?([\w@~.-]+)"?/g)];
      for (const p of pairs.slice(0, 80)) {
        const name = p[1], hash = p[2];
        if (/^[\w@~.-]{1,80}$/.test(name) && /^[a-f0-9]{5,}$/i.test(hash)) {
          add(`${basePath}${name}.${hash}.js`);
        }
      }
    }
  }

  return Array.from(out).slice(0, 160);
}

function isDownloadCodeUrl(raw) {
  const s = String(raw || '').trim();
  if (!s || s.length > 240 || s.startsWith('data:') || s.startsWith('blob:')) return false;
  if (!/\.(?:js|mjs|cjs|map)(?:[?#]|$)/i.test(s)) return false;
  if (/[<>{}*$|\\\s]/.test(s)) return false;
  return /^(?:(?:https?:)?\/\/|\/|\.{1,2}\/|(?:static|assets|js|dist|chunks|_next|_nuxt)\/)/i.test(s);
}

function guessDownloadWebpackBasePath(source, baseUrl) {
  const publicPath = source.match(/__webpack_require__\.p\s*=\s*["'`]([^"'`]+)["'`]/);
  if (publicPath && publicPath[1] && !/^(?:auto|\/)$/.test(publicPath[1])) {
    try { return new URL(publicPath[1], baseUrl).href; } catch { /* ignore */ }
  }
  try {
    const u = new URL(baseUrl);
    const parts = u.pathname.split('/');
    parts.pop();
    return u.origin + parts.join('/') + '/';
  } catch {
    return '';
  }
}

function addZipFile(files, usedNames, path, content) {
  const normalized = uniquePath(path, usedNames);
  const data = content instanceof Uint8Array ? content : utf8Bytes(String(content ?? ''));
  files.push({ name: normalized, data });
}

function makeZipPath(url, kind) {
  if (/^data:/i.test(url)) return `resources/${kind || 'resource'}-${hashString(url)}.txt`;
  try {
    const u = new URL(url);
    const pathname = decodeURIComponent(u.pathname || '/');
    let parts = pathname.split('/').filter(Boolean).map(safeName);
    if (!parts.length) parts = ['index'];
    let filename = parts.pop();
    if (!/\.[A-Za-z0-9]{1,8}$/.test(filename)) {
      filename += kind === 'script' ? '.js' : kind === 'document' ? '.html' : '.txt';
    }
    const prefix = kind === 'script' ? 'scripts' : kind === 'document' ? 'frames' : 'resources';
    return [prefix, safeName(u.host), ...parts.slice(-4), filename].join('/');
  } catch {
    return `resources/${safeName(url).slice(0, 80) || 'resource'}.txt`;
  }
}

function uniquePath(path, usedNames) {
  let clean = path.split('/').map((part) => safeName(part)).filter(Boolean).join('/');
  if (!clean) clean = 'file.txt';
  if (!usedNames.has(clean)) {
    usedNames.add(clean);
    return clean;
  }
  const slash = clean.lastIndexOf('/');
  const dot = clean.lastIndexOf('.');
  const hasExt = dot > slash;
  const base = hasExt ? clean.slice(0, dot) : clean;
  const ext = hasExt ? clean.slice(dot) : '';
  let i = 2;
  while (usedNames.has(`${base}-${i}${ext}`)) i++;
  clean = `${base}-${i}${ext}`;
  usedNames.add(clean);
  return clean;
}

function safeName(name) {
  return String(name || '')
    .replace(/[\\/:*?"<>|#%&{}$!'@+`=]/g, '_')
    .replace(/\s+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '') || 'unnamed';
}

function truncateText(text, max) {
  const s = String(text || '');
  return s.length > max ? s.slice(0, max - 1) + '...' : s;
}

function hashString(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16);
}

function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function createZip(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const now = new Date();
  const time = ((now.getHours() & 31) << 11) | ((now.getMinutes() & 63) << 5) | ((now.getSeconds() / 2) & 31);
  const date = (((now.getFullYear() - 1980) & 127) << 9) | (((now.getMonth() + 1) & 15) << 5) | (now.getDate() & 31);

  for (const file of files) {
    const nameBytes = utf8Bytes(file.name);
    const data = file.data;
    const crc = crc32(data);

    const local = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true);
    lv.setUint16(8, 0, true);
    lv.setUint16(10, time, true);
    lv.setUint16(12, date, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    localParts.push(local, data);

    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, time, true);
    cv.setUint16(14, date, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);
    centralParts.push(central);

    offset += local.length + data.length;
  }

  const centralSize = centralParts.reduce((sum, p) => sum + p.length, 0);
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, files.length, true);
  ev.setUint16(10, files.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);

  return new Blob([...localParts, ...centralParts, end], { type: 'application/zip' });
}

function crc32(data) {
  if (!crc32.table) {
    crc32.table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crc32.table[i] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = crc32.table[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

async function openSecurityScan() {
  const url = chrome.runtime.getURL(`scan.html?tabId=${currentTabId}`);
  await chrome.tabs.create({ url });
}

async function openVulnScan() {
  const url = chrome.runtime.getURL(`vuln-scan.html?tabId=${currentTabId}`);
  await chrome.tabs.create({ url });
}

async function openVueTools() {
  const url = chrome.runtime.getURL(`vue-tools.html?tabId=${currentTabId}`);
  await chrome.tabs.create({ url });
}

async function clearScripts() {
  await chrome.runtime.sendMessage({ type: 'CLEAR_SCRIPTS', tabId: currentTabId });
  scripts = [];
  render();
  setStatus('已清空当前标签页记录');
}

async function viewScript(s) {
  els.viewerTitle.textContent = s.inline ? '内联脚本' : s.url;
  if (s.inline) {
    els.viewerContent.textContent = s.content || '(空)';
  } else {
    els.viewerContent.textContent = '加载中...';
    try {
      const res = await fetch(s.url);
      const text = await res.text();
      els.viewerContent.textContent = text.length > 500000
        ? text.slice(0, 500000) + '\n/* ...内容已截断 */'
        : text;
    } catch (err) {
      els.viewerContent.textContent = `加载失败: ${err.message}`;
    }
  }
  els.viewer.showModal();
}

function setStatus(msg) {
  els.status.textContent = msg;
}
