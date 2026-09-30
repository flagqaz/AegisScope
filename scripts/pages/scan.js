// resource-profile:flagqaz/AegisScope:110c2940854f9b04:fec7ab17349930d9
const params = new URLSearchParams(location.search);
const targetTabId = Number(params.get('tabId'));

const els = {
  origin: document.getElementById('origin'),
  riskLevel: document.getElementById('riskLevel'),
  riskScore: document.getElementById('riskScore'),
  progress: document.getElementById('progress'),
  progressSub: document.getElementById('progressSub'),
  detectedLibs: document.getElementById('detected-libs'),
  detectedAlgos: document.getElementById('detected-algos'),
  detectedDecryptions: document.getElementById('detected-decryptions'),
  detectedBundlers: document.getElementById('detected-bundlers'),
  detectedFrameworks: document.getElementById('detected-frameworks'),
  detectedObfuscation: document.getElementById('detected-obfuscation'),
  detectedApis: document.getElementById('detected-apis'),
  detectedRoutes: document.getElementById('detected-routes'),
  detectedModules: document.getElementById('detected-modules'),
  detectedWeak: document.getElementById('detected-weak'),
  detectedExposures: document.getElementById('detected-exposures'),
  results: document.getElementById('results'),
  search: document.getElementById('search'),
  severity: document.getElementById('severity'),
  category: document.getElementById('category'),
  confidence: document.getElementById('confidence'),
  groupByFile: document.getElementById('groupByFile'),
  rescan: document.getElementById('rescan'),
  exportJson: document.getElementById('exportJson'),
  exportMd: document.getElementById('exportMd'),
  confActionable: document.getElementById('conf-actionable'),
  confBreakdown: document.getElementById('conf-breakdown'),
  viewer: document.getElementById('viewer'),
  viewerTitle: document.getElementById('viewer-title'),
  viewerContent: document.getElementById('viewer-content'),
  viewerClose: document.getElementById('viewer-close')
};

let perFileResults = [];
let aggregate = null;
let scanning = false;
let scanSession = null;
let renderLimit = 200;
const SCAN_MAX_RESOURCE_BYTES = 8 * 1024 * 1024;
const SCAN_FETCH_TIMEOUT_MS = 15000;
const scanTextCache = new Map(); // No source bodies retained here; results keep evidence snippets only.
const MiB = 1024 * 1024;
const scanProfiles = {
  standard: { resourceBytes: 8 * MiB, totalBytes: 96 * MiB, items: 2400, findings: 20000, perRule: 1000 },
  expanded: { resourceBytes: 32 * MiB, totalBytes: 384 * MiB, items: 9600, findings: 50000, perRule: 5000 }
};
const stopButton = document.getElementById('stopScan');
const expandButton = document.getElementById('expandedScan');
const coverageElement = document.getElementById('coverage');
els.rescan.addEventListener('click', () => runScanOptimized());
stopButton.addEventListener('click', () => stopScan());
expandButton.addEventListener('click', () => runScanOptimized('expanded'));
els.exportJson.addEventListener('click', () => exportJson().catch(showExportError));
els.exportMd.addEventListener('click', () => exportMd().catch(showExportError));
for (const el of [els.search, els.severity, els.category, els.confidence, els.groupByFile]) {
  el.addEventListener(el === els.search ? 'input' : 'change', () => { renderLimit = 200; renderResults(); });
}
els.viewerClose.addEventListener('click', () => els.viewer.close());
window.addEventListener('pagehide', () => stopScan());

function issue(url, reason, type = 'coverage', session = scanSession) {
  if (!session) return;
  const key = `${type}:${url}:${reason}`;
  if (!session.issueKeys.has(key)) {
    session.issueKeys.add(key);
    session.issues.push({ url, reason, type });
  }
}
function setBusy(busy) {
  scanning = busy;
  els.rescan.disabled = expandButton.disabled = busy;
  stopButton.disabled = !busy;
  els.exportJson.disabled = els.exportMd.disabled = busy || !aggregate || !scanSession;
}
function stopScan(reason = '用户停止扫描') {
  if (!scanning || !scanSession || scanSession.cancelled) return;
  scanSession.cancelled = true;
  issue(scanSession.origin, reason, 'cancelled');
  for (const controller of scanSession.controllers) controller.abort();
  for (const cancel of scanSession.workers.values()) cancel();
  els.progress.textContent = '正在停止…';
}
function coverageSnapshot() {
  const s = scanSession;
  if (!s) return null;
  return {
    status: s.status, profile: s.profile, startedAt: s.startedAt, finishedAt: s.finishedAt,
    scope: '当前页面、可访问框架及发现的代码依赖；不证明未知或未加载资源无泄露。',
    discovered: s.queue.length + s.skipped, processed: s.done, skipped: s.skipped,
    analyzed: perFileResults.filter(f => !f.error).length,
    failed: perFileResults.filter(f => f.status === 'failed').length,
    truncated: perFileResults.filter(f => f.truncated).length,
    scannedBytes: s.bytes, limits: s.limits, issues: s.issues,
    complete: s.status === 'completed' && s.issues.length === 0,
    verification: '仅静态检测，未验证凭据有效性、接口权限或实际可利用性'
  };
}
function renderCoverage() {
  const c = coverageSnapshot();
  if (!c) { coverageElement.textContent = ''; return; }
  coverageElement.innerHTML = `<strong>${scanning ? '扫描进行中' : c.complete ? '已完成本轮发现资源的扫描' : '扫描范围不完整'}</strong>` +
    `<p>已分析 ${c.analyzed} · 失败 ${c.failed} · 截断 ${c.truncated} · 跳过 ${c.skipped} · ${formatBytes(c.scannedBytes)}</p>` +
    '<p>结果为静态检测线索，不代表凭据有效或漏洞可利用；未加载、无法访问及动态生成的未知资源可能不在本轮范围内。</p>' +
    (c.issues.length ? `<details><summary>查看 ${c.issues.length} 条覆盖说明（全部随报告导出）</summary><ul>${c.issues.slice(0, 100).map(x => `<li>${escapeHtml(x.url)}：${escapeHtml(x.reason)}</li>`).join('')}</ul>${c.issues.length > 100 ? '<p>更多说明请查看完整报告。</p>' : ''}</details>` : '');
}
function failureResult(item, error, status = 'failed') {
  return { file: item.url, requestedUrl: item.url, kind: item.kind, size: 0, status,
    error: error?.message || String(error), findings: [], stats: emptyStats() };
}

async function runScanOptimized(profile = 'standard') {
  if (scanning) return;
  if (!scanProfiles[profile]) profile = 'standard';
  perFileResults = []; aggregate = null; renderLimit = 200; scanTextCache.clear();
  const session = scanSession = {
    id: crypto.randomUUID(), profile, limits: { ...scanProfiles[profile] }, startedAt: new Date().toISOString(),
    status: 'running', origin: '', issues: [], issueKeys: new Set(), controllers: new Set(), workers: new Map(),
    queue: [], seen: new Set(), done: 0, skipped: 0, bytes: 0, reservedBytes: 0, findings: 0, cancelled: false
  };
  setBusy(true); updateAggregate(); aggregate = null;
  els.results.innerHTML = ''; els.origin.textContent = ''; els.riskLevel.textContent = '扫描中…';
  els.progress.textContent = '初始化'; els.progressSub.textContent = '';
  const enqueue = (item) => {
    if (session.cancelled) return;
    const key = item.key || (item.inline ? `inline:${item.url}` : item.url);
    if (!key || session.seen.has(key)) return;
    session.seen.add(key);
    if (session.queue.length >= session.limits.items) {
      session.skipped++; issue(item.url, '已达到本轮资源数量上限，请使用扩展扫描或分页面扫描', 'limit'); return;
    }
    session.queue.push(item);
  };
  const onUpdated = (id, change) => {
    if (id === targetTabId && change.url && change.url !== session.origin) stopScan('目标页面已跳转，请对新页面重新扫描');
  };
  const onRemoved = id => { if (id === targetTabId) stopScan('目标标签页已关闭'); };
  try {
    const tab = await chrome.tabs.get(targetTabId);
    session.origin = tab.url || ''; els.origin.textContent = session.origin;
    chrome.tabs.onUpdated.addListener(onUpdated); chrome.tabs.onRemoved.addListener(onRemoved);
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SCRIPTS', tabId: targetTabId });
    const frames = await getPageCodeResources(session);
    const liveTab = await chrome.tabs.get(targetTabId);
    if (liveTab.url !== session.origin) stopScan('初始化期间目标页面已跳转，请重新扫描');
    for (const frame of frames) {
      if (frame.html != null) enqueue({ url: `[页面HTML frame=${frame.frameId}] ${frame.url}`, baseUrl: frame.baseUrl || frame.url,
        inline: true, content: frame.html, kind: 'document', truncated: frame.truncated });
      if (frame.truncated) issue(frame.url, '页面 HTML 超过本轮采集上限', 'truncated');
      if (frame.omitted) issue(frame.url, `页面资源列表超出上限，至少遗漏 ${frame.omitted} 项`, 'limit');
      for (const item of frame.items || []) enqueue(item);
    }
    for (const s of resp?.scripts || []) {
      if (!s.inline) { enqueue({ ...s, kind: 'script' }); continue; }
      // Retain collected scripts removed from the DOM, with explicit snapshot provenance.
      if (typeof s.content !== 'string' || frames.some(f => f.html?.includes(s.content))) continue;
      const truncated = s.length > s.content.length || s.content.endsWith('/* ...truncated by collection limit */');
      enqueue({ ...s, url: `[采集快照] ${s.url}`, kind: 'collected-inline', collectedAt: s.lastSeen,
        baseUrl: session.origin, truncated });
      if (truncated) issue(s.url, '历史内联脚本在采集时被截断；当前 DOM 中已无法取得完整内容', 'truncated');
    }
    if (!session.queue.length) issue(session.origin, '没有可扫描资源，页面可能受限或已关闭', 'unavailable');
    let cursor = 0, lastPaint = 0;
    const work = async () => {
      while (!session.cancelled && cursor < session.queue.length) {
        const item = session.queue[cursor++];
        try {
          const results = await processScanItem(item, enqueue, session);
          if (!session.cancelled) perFileResults.push(...results);
        } catch (error) {
          const status = session.cancelled ? 'cancelled' : 'failed';
          perFileResults.push(failureResult(item, error, status));
          issue(item.url, session.cancelled ? '扫描已停止，此资源未完成' : error.message, status);
        }
        session.done++;
        els.progress.textContent = `${session.done} / ${session.queue.length}`;
        if (performance.now() - lastPaint > 350) {
          updateAggregate(); renderResults(); renderCoverage(); lastPaint = performance.now();
        }
      }
    };
    await Promise.all([work(), work()]);
    if (session.cancelled) {
      const pending = session.queue.slice(cursor);
      session.skipped += pending.length;
      for (const item of pending) issue(item.url, '停止时尚未扫描', 'cancelled');
    }
    session.status = session.cancelled ? 'cancelled' : session.issues.length ? 'partial' : 'completed';
  } catch (error) {
    session.status = session.cancelled ? 'cancelled' : 'failed';
    issue(session.origin || `tab:${targetTabId}`, error.message || String(error), 'initialization');
  } finally {
    chrome.tabs.onUpdated.removeListener(onUpdated); chrome.tabs.onRemoved.removeListener(onRemoved);
    session.finishedAt = new Date().toISOString();
    // Release queued DOM and SourceMap strings; only the evidence excerpts remain.
    for (const item of session.queue) delete item.content;
    setBusy(false); updateAggregate(); setBusy(false); renderResults(); renderCoverage();
    els.progress.textContent = ({ completed: '完成', partial: '部分完成', cancelled: '已停止', failed: '扫描失败' })[session.status];
    els.progressSub.textContent = `已处理 ${session.done} / ${session.queue.length} · ${aggregate.findings} 条线索 · ${session.issues.length} 条覆盖说明`;
  }
}

function analyzeInWorker(source, meta, session) {
  return new Promise((resolve, reject) => {
    if (session.cancelled) { reject(new Error('扫描已停止')); return; }
    const worker = new Worker(chrome.runtime.getURL('scripts/lib/leak-worker.js'));
    const finish = (error, result) => {
      clearTimeout(timer); session.workers.delete(worker); worker.terminate();
      error ? reject(error) : resolve(result);
    };
    const timer = setTimeout(() => finish(new Error('规则分析超时，已终止该文件；结果不完整')), 30000);
    session.workers.set(worker, () => finish(new Error('扫描已停止')));
    worker.onmessage = ({ data }) => finish(data.error ? new Error(data.error) : null, data.result);
    worker.onerror = event => finish(new Error(event.message || '规则分析线程失败'));
    worker.postMessage({ source, meta });
  });
}
async function processScanItem(item, enqueue, session = scanSession) {
  if (session.cancelled) throw new Error('扫描已停止');
  if (session.bytes >= session.limits.totalBytes || session.findings >= session.limits.findings) {
    session.skipped++; issue(item.url, '已达到本轮总量上限，请扩展扫描或分页面扫描', 'limit');
    return [failureResult(item, '本轮总量上限，未扫描', 'skipped')];
  }
  let read;
  const budget = Math.min(session.limits.resourceBytes, session.limits.totalBytes - session.bytes - session.reservedBytes);
  if (budget <= 0) {
    session.skipped++; issue(item.url, '本轮读取预算已耗尽或被其他资源占用，请扩展扫描或分页面扫描', 'limit');
    return [failureResult(item, '读取预算不足，未扫描', 'skipped')];
  }
  session.reservedBytes += budget;
  try {
    if (item.inline) read = await readResponseTextLimited(new Response(item.content || ''), budget);
    else read = await fetchCodeForScan(item.url, session, budget);
  } finally { session.reservedBytes -= budget; delete item.content; }
  session.bytes += read.bytes;
  const source = read.text, actualUrl = read.responseUrl || item.baseUrl || item.url;
  const truncated = !!(item.truncated || read.truncated);
  if (truncated) issue(item.url, `内容被截断，本文件仅扫描 ${formatBytes(read.bytes)}；可使用扩展扫描`, 'truncated');
  if (read.decodeWarning) issue(item.url, read.decodeWarning, 'encoding');
  const meta = { url: actualUrl, originalUrl: item.url, analysisLimits: { perRule: session.limits.perRule,
    findings: Math.max(1, session.limits.findings - session.findings) }, contextSize: 800 };
  const analyzed = await analyzeInWorker(source, meta, session);
  if (analyzed.findings.length > session.limits.findings - session.findings) {
    analyzed.findings = analyzed.findings.slice(0, Math.max(0, session.limits.findings - session.findings));
    analyzed.stats.bySeverity = emptyStats().bySeverity;
    analyzed.stats.byConfidence = emptyStats().byConfidence;
    analyzed.stats.byCategory = {};
    for (const f of analyzed.findings) {
      analyzed.stats.bySeverity[f.severity]++; analyzed.stats.byConfidence[f.confidence]++;
      analyzed.stats.byCategory[f.category] = (analyzed.stats.byCategory[f.category] || 0) + 1;
    }
    issue(item.url, '达到本轮命中总量上限，部分命中未保留', 'limit');
  }
  session.findings += analyzed.findings.length;
  if (analyzed.stats.ruleLimits?.length) issue(item.url, `规则命中数量达到上限：${analyzed.stats.ruleLimits.join('、')}`, 'limit');
  if (analyzed.stats.validationErrors?.length) issue(item.url, `规则校验异常：${analyzed.stats.validationErrors.join('、')}`, 'analysis');
  const result = { file: item.url, requestedUrl: item.url, responseUrl: read.responseUrl, kind: item.kind,
    parentMap: item.parentMap, collectedAt: item.collectedAt, size: read.bytes, status: truncated ? 'truncated' : 'analyzed', truncated,
    encoding: read.encoding, findings: analyzed.findings, stats: analyzed.stats };
  if (!session.cancelled && item.kind !== 'collected-inline') {
    for (const url of discoverRelatedCodeUrls(source, actualUrl)) enqueue({ url, kind: /\.map(?:[?#]|$)/i.test(url) ? 'sourcemap' : 'chunk' });
    if (item.kind === 'sourcemap' || /\.map(?:[?#]|$)/i.test(item.url)) {
      enqueueSourceMap(source, actualUrl, enqueue, session);
    } else {
      const annotation = read.sourceMap || findSourceMapAnnotation(source);
      if (annotation) {
        if (annotation.startsWith('data:')) {
          try { enqueueSourceMap(decodeInlineMap(annotation), actualUrl, enqueue, session); }
          catch (e) { issue(item.url, `内联 SourceMap 无法解析：${e.message}`, 'sourcemap'); }
        } else {
          try { enqueue({ url: new URL(annotation, actualUrl).href, kind: 'sourcemap' }); }
          catch { issue(item.url, 'SourceMap 地址无法解析', 'sourcemap'); }
        }
      }
    }
  }
  return [result];
}

async function fetchCodeForScan(url, session = scanSession, budget = session.limits.resourceBytes) {
  const target = new URL(url, location.href);
  if (!['http:', 'https:', 'file:', 'data:'].includes(target.protocol)) throw new Error('此资源协议无法在扫描页读取');
  if (target.username || target.password) throw new Error('不读取 URL 中嵌入认证信息的资源');
  const controller = new AbortController(); session.controllers.add(controller);
  const timer = setTimeout(() => controller.abort(), SCAN_FETCH_TIMEOUT_MS);
  let sameOrigin = false;
  try { sameOrigin = new URL(session.origin).origin === target.origin; } catch {}
  try {
    const res = await fetch(target.href, { credentials: sameOrigin ? 'include' : 'omit', cache: 'no-store', signal: controller.signal });
    if (!res.ok) { await res.body?.cancel().catch(() => {}); throw new Error(`HTTP ${res.status} ${res.statusText}`.trim()); }
    const type = res.headers.get('content-type') || '';
    if (/^(?:image|audio|video|font)\/|application\/(?:wasm|zip|pdf)/i.test(type)) {
      await res.body?.cancel().catch(() => {}); throw new Error(`非文本资源（${type}），未执行文本规则扫描`);
    }
    const read = await readResponseTextLimited(res, budget);
    if (/\.(?:[cm]?js|map)(?:[?#]|$)/i.test(target.href) && /^\s*(?:<!doctype\s+html|<html\b)/i.test(read.text)) throw new Error('请求代码资源却返回 HTML 页面，可能为登录页或错误页');
    return { ...read, responseUrl: res.url, sourceMap: res.headers.get('sourcemap') || res.headers.get('x-sourcemap') || '' };
  } catch (error) {
    if (error.name === 'AbortError') throw new Error(session.cancelled ? '扫描已停止' : '资源读取超时');
    throw error;
  } finally { clearTimeout(timer); session.controllers.delete(controller); }
}

async function readResponseTextLimited(response, maxBytes) {
  const reader = response.body.getReader();
  let bytes = 0, truncated = false;
  const parts = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = Math.max(0, maxBytes - bytes);
      if (value.length > remaining) {
        parts.push(value.slice(0, remaining)); bytes += remaining; truncated = true;
        await reader.cancel(); break;
      }
      parts.push(value); bytes += value.length;
      // Read one more chunk at the exact boundary to distinguish complete from truncated.
    }
  } finally { reader.releaseLock(); }
  const body = new Uint8Array(bytes);
  let offset = 0; for (const part of parts) { body.set(part, offset); offset += part.length; }
  const charset = /charset\s*=\s*["']?([^;\s"']+)/i.exec(response.headers.get('content-type') || '')?.[1];
  let encoding = charset || 'utf-8', decodeWarning = '';
  if (body[0] === 0xff && body[1] === 0xfe) encoding = 'utf-16le';
  else if (body[0] === 0xfe && body[1] === 0xff) encoding = 'utf-16be';
  else if (body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) encoding = 'utf-8';
  let decoder;
  try { decoder = new TextDecoder(encoding, { fatal: true }); }
  catch { encoding = 'utf-8'; decoder = new TextDecoder(encoding, { fatal: true }); decodeWarning = '响应字符集不受支持，已按 UTF-8 尝试解码'; }
  let text;
  try { text = decoder.decode(body, { stream: truncated }); }
  catch { text = new TextDecoder(encoding).decode(body, { stream: truncated }); decodeWarning = '内容含无法按响应字符集解码的字节，部分检测可能受影响'; }
  return { text, bytes, truncated, encoding, decodeWarning };
}

async function getPageCodeResources(session) {
  const options = { maxItems: session.limits.items, maxChars: session.limits.resourceBytes };
  let frames;
  try { frames = await chrome.scripting.executeScript({ target: { tabId: targetTabId, allFrames: true }, func: collectPageCodeResources, args: [options] }); }
  catch (e) {
    issue(session.origin, `部分框架无法读取：${e.message}`, 'frame');
    frames = await chrome.scripting.executeScript({ target: { tabId: targetTabId }, func: collectPageCodeResources, args: [options] });
  }
  const results = frames.filter(x => x.result).map(x => ({ ...x.result, frameId: x.frameId }));
  const loaded = new Set(results.map(x => x.url));
  for (const frame of results) for (const url of frame.frameUrls || []) {
    if (!loaded.has(url)) issue(url, '框架未能完成实时 DOM 采集，仅尝试已发现的资源', 'frame');
  }
  return results;
}

function collectPageCodeResources(options = {}) {
  const maxItems = options.maxItems || 2400;
  let omitted = 0;
  const excludedExt = new Set([
    '.css', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico',
    '.svg', '.tif', '.tiff', '.mp4', '.webm', '.mp3', '.wav', '.ogg', '.m3u8',
    '.aac', '.flac', '.woff', '.woff2', '.ttf', '.otf', '.eot'
  ]);
  const codeExt = new Set([
    '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.vue', '.svelte',
    '.json', '.map', '.wasm', '.html', '.htm', '.xml', '.txt'
  ]);
  const items = new Map();

  const extOf = (url) => {
    try {
      const pathname = new URL(url, location.href).pathname.toLowerCase();
      const filename = pathname.split('/').pop() || '';
      const dot = filename.lastIndexOf('.');
      return dot >= 0 ? filename.slice(dot) : '';
    } catch {
      return '';
    }
  };

  const add = (rawUrl, kind = 'resource') => {
    if (!rawUrl) return;
    let url;
    try { url = new URL(rawUrl, location.href); } catch { return; }
    if (!/^https?:|^file:|^blob:|^data:/.test(url.href)) return;
    const ext = extOf(url.href);
    if (excludedExt.has(ext)) return;
    if (!codeExt.has(ext) && kind !== 'script' && kind !== 'document' && kind !== 'manifest') return;
    if (items.size >= maxItems && !items.has(url.href)) { omitted++; return; }
    items.set(url.href, { url: url.href, kind });
  };

  for (const el of document.querySelectorAll('script[src]')) {
    add(el.src || el.getAttribute('src'), 'script');
  }
  for (const el of document.querySelectorAll('iframe[src], frame[src]')) {
    add(el.src || el.getAttribute('src'), 'document');
  }
  for (const el of document.querySelectorAll('link[href]')) {
    const rel = (el.rel || '').toLowerCase();
    const as = (el.as || '').toLowerCase();
    if (rel.includes('stylesheet') || rel.includes('icon') || (rel.includes('preload') && as === 'style')) continue;
    add(el.href || el.getAttribute('href'), rel.includes('manifest') ? 'manifest' : 'resource');
  }
  for (const entry of performance.getEntriesByType('resource')) {
    const type = entry.initiatorType || 'resource';
    if (['css', 'img', 'image', 'audio', 'video', 'font'].includes(type)) continue;
    add(entry.name, type === 'iframe' ? 'document' : type === 'script' ? 'script' : 'resource');
  }

  const html = '<!DOCTYPE html>\n' + document.documentElement.outerHTML;
  const maxChars = options.maxChars || 8 * 1024 * 1024;
  return { url: location.href, baseUrl: document.baseURI, html: html.slice(0, maxChars), truncated: html.length > maxChars, omitted,
    frameUrls: Array.from(document.querySelectorAll('iframe[src],frame[src]'), el => el.src), items: Array.from(items.values()) };
}

function analyzeFile(file, source, meta = {}) {
  const result = self.JS_EXTRACTOR_ANALYZER.analyzeSource(source, { ...meta, url: file });
  return { file, size: new TextEncoder().encode(source).length, findings: result.findings, stats: result.stats };
}

function discoverRelatedCodeUrls(source, baseUrl) {
  const out = new Set();
  const add = (raw, mode = 'script') => {
    if (mode === 'map' ? !isLikelySourceMapUrl(raw) : !isLikelyRuntimeCodeUrl(raw)) return;
    try {
      const url = new URL(raw, baseUrl);
      if (/\/(?:node_modules|coverage|examples?|test|tests?|docs?|README|CHANGELOG)\//i.test(url.pathname)) return;
      out.add(url.href);
    } catch { /* ignore */ }
  };

  let m;
  const jsStringRe = /["'`]((?:(?:https?:)?\/\/|\/|\.{1,2}\/|(?:static|assets|js|dist|chunks|_next|_nuxt|tinymce|videoPlayer)\/)[^"'`\s<>]{1,220}\.(?:js|mjs|cjs|map)(?:\?[^"'`\s<>]*)?)["'`]/gi;
  while ((m = jsStringRe.exec(source)) !== null) add(m[1]);

  const webpackConcatRe = /(?:u|miniCssF)\s*=\s*function\s*\([^)]*\)\s*\{[\s\S]{0,1200}?return\s+([^;]+);/g;
  while ((m = webpackConcatRe.exec(source)) !== null) {
    const literals = [...m[1].matchAll(/["']([^"']+)["']/g)].map((x) => x[1]).join('');
    if (/\.(?:js|mjs|cjs)(?:[?#]|$)/i.test(literals)) add(literals.replace(/\+.*$/, ''));
  }

  for (const url of discoverWebpackRuntimeChunks(source, baseUrl)) add(url);
  for (const url of discoverFrameworkAssets(source, baseUrl)) add(url);

  const imports = /(?:\b(?:import|export)\s+(?:[^;\n]{0,240}?\s+from\s*)?|\b(?:import|require)\s*\(\s*)["']([^"'\s]+)["']/g;
  while ((m = imports.exec(source)) !== null) {
    if (/^(?:\.{1,2}\/|\/|https?:\/\/)/.test(m[1])) {
      try { const u = new URL(m[1], baseUrl); if (/\.(?:[cm]?js|jsx|tsx?|vue)(?:[?#]|$)/i.test(u.href)) out.add(u.href); } catch {}
    }
  }
  return Array.from(out);
}

function discoverFrameworkAssets(source, baseUrl) {
  const out = new Set();
  const add = (raw) => {
    try {
      const u = new URL(raw, baseUrl);
      if (isLikelyRuntimeCodeUrl(u.href)) out.add(u.href);
    } catch { /* ignore */ }
  };

  const patterns = [
    /["'`]((?:\/_next\/static\/|_next\/static\/)[^"'`\s<>]+\.js(?:\?[^"'`\s<>]*)?)["'`]/g,
    /["'`]((?:\/_nuxt\/|_nuxt\/)[^"'`\s<>]+\.js(?:\?[^"'`\s<>]*)?)["'`]/g,
    /["'`]((?:\/static\/js\/|static\/js\/)[^"'`\s<>]+\.js(?:\?[^"'`\s<>]*)?)["'`]/g,
    /["'`]((?:\/assets\/|assets\/)[^"'`\s<>]+(?:chunk|vendor|app|index|main)[^"'`\s<>]*\.js(?:\?[^"'`\s<>]*)?)["'`]/gi
  ];
  for (const re of patterns) {
    let m, count = 0;
    while ((m = re.exec(source)) !== null) {
      add(m[1]);
      count++;
    }
  }
  return Array.from(out);
}

function discoverWebpackRuntimeChunks(source, baseUrl) {
  const out = new Set();
  if (!/\b(?:__webpack_require__|webpackChunk|webpackJsonp|__webpack_modules__)\b/.test(source)) return [];

  const basePath = guessWebpackBasePath(source, baseUrl);
  const addCandidate = (raw) => {
    try {
      const u = new URL(raw, baseUrl);
      if (isLikelyRuntimeCodeUrl(u.href)) out.add(u.href);
    } catch { /* ignore */ }
  };
  const joinChunk = (name, hash, suffix = '.js') => {
    const cleanName = String(name || '').replace(/^["']|["']$/g, '');
    const cleanHash = String(hash || '').replace(/^["']|["']$/g, '');
    if (!cleanName || !cleanHash || cleanName.length > 80 || cleanHash.length > 80) return;
    if (!/^[\w@~.-]+$/.test(cleanName) || !/^[a-f0-9]{5,}$/i.test(cleanHash)) return;
    addCandidate(`${basePath}${cleanName}.${cleanHash}${suffix.startsWith('.') ? suffix : `.${suffix}`}`);
  };

  const blocks = [];
  const runtimeRe = /__webpack_require__\.[up]\s*=\s*function\s*\([^)]*\)\s*\{[\s\S]{0,5000}?\}/g;
  let m;
  while ((m = runtimeRe.exec(source)) !== null) blocks.push(m[0]);
  blocks.push(source.slice(0, 250000));

  for (const block of blocks) {
    const suffix = detectChunkSuffix(block);

    const pairMapRe = /\{\s*((?:"?[\w@~.-]+"?\s*:\s*"?[\w@~.-]+"?\s*,?\s*){2,})\}/g;
    let mapMatch, maps = [];
    while ((mapMatch = pairMapRe.exec(block)) !== null && maps.length < 8) {
      const pairs = parseSimpleObjectPairs(mapMatch[1]);
      if (pairs.length >= 2 && pairs.length <= 220) maps.push(pairs);
    }

    for (const pairs of maps) {
      const hashPairs = pairs.filter(([, v]) => /^[a-f0-9]{5,}$/i.test(v));
      if (!hashPairs.length) continue;
      for (const [k, v] of hashPairs.slice(0, 80)) joinChunk(k, v, suffix);
    }
  }

  return Array.from(out);
}

function parseSimpleObjectPairs(text) {
  const pairs = [];
  const re = /"?([\w@~.-]+)"?\s*:\s*"?([\w@~.-]+)"?/g;
  let m;
  while ((m = re.exec(text)) !== null) pairs.push([m[1], m[2]]);
  return pairs;
}

function detectChunkSuffix(block) {
  const m = block.match(/["'](\.[a-f0-9]{5,}\.js|\.chunk\.js|\.js)["']/i) ||
    block.match(/["']([^"']*\.js)["']/i);
  if (!m) return '.js';
  const s = m[1];
  if (/^\./.test(s)) return s.replace(/^\.[a-f0-9]{5,}/i, '');
  const tail = s.match(/(\.chunk\.js|\.js)$/i);
  return tail ? tail[1] : '.js';
}

function guessWebpackBasePath(source, baseUrl) {
  const publicPath = source.match(/__webpack_require__\.p\s*=\s*["'`]([^"'`]+)["'`]/) ||
    source.match(/\bpublicPath\s*[:=]\s*["'`]([^"'`]+)["'`]/);
  if (publicPath && publicPath[1] && !/^(?:auto|\/)$/.test(publicPath[1])) {
    try { return new URL(publicPath[1], baseUrl).href; } catch { /* ignore */ }
  }
  try {
    const u = new URL(baseUrl);
    const parts = u.pathname.split('/');
    parts.pop();
    const dir = parts.join('/') + '/';
    if (/(?:static|assets|js|chunks|_next|_nuxt|dist)\//i.test(dir)) return u.origin + dir;
    return u.origin + dir;
  } catch {
    return '';
  }
}

function isLikelySourceMapUrl(raw) {
  if (!raw || typeof raw !== 'string') return false;
  const s = raw.trim();
  if (!s || s.startsWith('data:') || s.startsWith('blob:')) return false;
  if (s.length > 240) return false;
  if (!/\.map(?:[?#]|$)/i.test(s)) return false;
  if (/[<>{}*$|\\\s]/.test(s)) return false;
  if (/%20|%7B|%7D|%24|%7C/i.test(s)) return false;
  return true;
}

function isLikelyRuntimeCodeUrl(raw) {
  if (!raw || typeof raw !== 'string') return false;
  const s = raw.trim();
  if (!s || s.startsWith('data:') || s.startsWith('blob:')) return false;
  if (s.length > 240) return false;
  if (!/\.(?:js|mjs|cjs|map)(?:[?#]|$)/i.test(s)) return false;
  if (/[<>{}*$|\\\s]/.test(s)) return false;
  if (/%20|%7B|%7D|%24|%7C/i.test(s)) return false;
  if (/^(?:node|npm|yarn|pnpm|cross-env|eslint|jest|cat|please|following)\b/i.test(s)) return false;
  if (/^(?:[a-z]{2}(?:-[a-z]{2})?|index|main|style|omit|enquire)\.js(?:[?#]|$)/i.test(s)) return false;
  if (!/^(?:(?:https?:)?\/\/|\/|\.{1,2}\/|(?:static|assets|js|dist|chunks|_next|_nuxt|tinymce|videoPlayer)\/)/i.test(s)) return false;
  return true;
}

function findSourceMapAnnotation(source) {
  const re = /(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL=([^\s*]+)/g;
  let match, value = '';
  while ((match = re.exec(source))) value = match[1];
  return value;
}
function decodeInlineMap(url) {
  const match = /^data:application\/json([^,]*),(.*)$/s.exec(url);
  if (!match) throw new Error('不支持的内联映射格式');
  if (/;base64/i.test(match[1])) {
    const bytes = Uint8Array.from(atob(decodeURIComponent(match[2])), c => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }
  return decodeURIComponent(match[2]);
}
function enqueueSourceMap(text, mapUrl, enqueue, session) {
  let root;
  try { root = JSON.parse(text.replace(/^\)\]\}'[^\n]*\n/, '')); }
  catch { issue(mapUrl, 'SourceMap JSON 无法解析（可能被截断）', 'sourcemap'); return; }
  let index = 0;
  const walk = (map, depth = 0) => {
    if (!map || map.version !== 3) { issue(mapUrl, 'SourceMap 格式或版本不受支持', 'sourcemap'); return; }
    if (depth > 20) { issue(mapUrl, 'SourceMap 分段嵌套超过保护上限', 'limit'); return; }
    if (Array.isArray(map.sections)) {
      for (const section of map.sections) {
        if (section.map) walk(section.map, depth + 1);
        else if (section.url) {
          try { enqueue({ url: new URL(section.url, mapUrl).href, kind: 'sourcemap' }); }
          catch { issue(mapUrl, 'SourceMap 分段地址无效', 'sourcemap'); }
        } else issue(mapUrl, 'SourceMap 分段缺少内容', 'sourcemap');
      }
      return;
    }
    if (!Array.isArray(map.sources)) { issue(mapUrl, 'SourceMap 缺少 sources', 'sourcemap'); return; }
    for (let i = 0; i < map.sources.length; i++) {
      if (session.queue.length >= session.limits.items) {
        const omitted = map.sources.length - i;
        session.skipped += omitted;
        issue(mapUrl, `本轮资源数量达到上限，此映射还有 ${omitted} 个来源未加入扫描`, 'limit');
        return;
      }
      const raw = map.sources[i], content = map.sourcesContent?.[i];
      let resolved = raw || `anonymous-${index}.js`;
      try {
        const base = map.sourceRoot ? new URL(String(map.sourceRoot).replace(/\/?$/, '/'), mapUrl).href : mapUrl;
        resolved = new URL(resolved, base).href;
      } catch {}
      const key = `map:${mapUrl}:${index++}`;
      if (typeof content === 'string') enqueue({ key, url: `[sourcemap] ${resolved} (${mapUrl} #${index})`,
        baseUrl: resolved, parentMap: mapUrl, kind: 'mapped-source', inline: true, content });
      else if (/^https?:\/\//i.test(resolved) && /\.(?:[cm]?js|jsx|tsx?|vue|svelte|json)(?:[?#]|$)/i.test(resolved)) {
        enqueue({ url: resolved, kind: 'mapped-source', parentMap: mapUrl });
      } else issue(`${mapUrl} → ${resolved}`, 'SourceMap 不含源码，且来源无法作为代码资源获取', 'sourcemap');
    }
  };
  walk(root);
}

function emptyStats() {
  return {
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byConfidence: { confirmed: 0, likely: 0, suspected: 0 },
    byCategory: {}, cryptoLibs: [], cryptoAlgos: [], decryptions: [],
    bundlers: [], frameworks: [], obfuscation: [], apiEndpoints: [],
    routes: [], moduleHints: [], exposures: []
  };
}

function updateAggregate() {
  // Count repeated bundles/inline copies once for risk scoring, while retaining every location.
  const unique = new Map();
  for (const file of perFileResults) for (const f of file.findings) {
    const key = JSON.stringify([f.ruleId, f.match]);
    const previous = unique.get(key);
    if (!previous || sortFindingDesc(f, previous) < 0) unique.set(key, f);
  }
  const all = self.JS_EXTRACTOR_ANALYZER.aggregateReport(perFileResults);
  const distinct = self.JS_EXTRACTOR_ANALYZER.aggregateReport([{ findings: Array.from(unique.values()), stats: emptyStats() }]);
  aggregate = { ...all, score: distinct.score, uniqueFindings: distinct.findings, uniqueActionable: distinct.actionable };
  if (aggregate.level === '安全') aggregate.level = aggregate.findings ? '存在待核验线索' : '未发现线索';
  if (!perFileResults.some(f => !f.error)) aggregate.level = scanning ? '扫描中…' : '无有效扫描结果';
  else if (!aggregate.findings && scanSession?.issues.length) aggregate.level = '覆盖不完整';

  els.riskLevel.textContent = aggregate.level;
  els.riskScore.textContent = `score ${aggregate.score} · ${aggregate.uniqueFindings} 条独立线索 / ${aggregate.findings} 处命中`;

  // 严重度计数：仅显示 actionable（confirmed+likely）作为主指标
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    document.getElementById('cnt-' + sev).textContent =
      String(aggregate.actionableBySeverity[sev] || 0);
    const subEl = document.getElementById(`cnt-${sev}-conf`);
    if (subEl) {
      const totalSev = aggregate.bySeverity[sev] || 0;
      const susp = totalSev - (aggregate.actionableBySeverity[sev] || 0);
      subEl.textContent = susp > 0 ? `+${susp} 疑似` : '待核验';
    }
  }

  els.confActionable.textContent = String(aggregate.actionable);
  els.confBreakdown.textContent =
    `高置信 ${aggregate.byConfidence.confirmed} · 较可信 ${aggregate.byConfidence.likely} · 疑似 ${aggregate.byConfidence.suspected}`;

  els.detectedLibs.textContent = aggregate.cryptoLibs.length ? aggregate.cryptoLibs.join('、') : '未识别';
  els.detectedAlgos.textContent = aggregate.cryptoAlgos.length ? aggregate.cryptoAlgos.join('、') : '未识别';
  els.detectedDecryptions.innerHTML = aggregate.decryptions?.length
    ? aggregate.decryptions.map((d) =>
        `<span class="tag crypto-algo" title="${escapeAttr(d.decrypt)}">${escapeHtml(d.name)}</span>` +
        `<span class="decrypt-note">${escapeHtml(d.decrypt)}</span>`).join(' ')
    : '<span class="tag">未识别</span>';
  els.detectedBundlers.innerHTML = aggregate.bundlers?.length
    ? aggregate.bundlers.map((b) => `<span class="tag crypto-lib">${escapeHtml(b)}</span>`).join(' ')
    : '<span class="tag">未识别</span>';
  if (els.detectedFrameworks) {
    els.detectedFrameworks.innerHTML = aggregate.frameworks?.length
      ? aggregate.frameworks.map((b) => `<span class="tag crypto-lib">${escapeHtml(b)}</span>`).join(' ')
      : '<span class="tag">未识别</span>';
  }
  els.detectedObfuscation.innerHTML = aggregate.obfuscation?.length
    ? aggregate.obfuscation.map((o) =>
        `<span class="tag ${o.severity === 'high' ? 'crypto-vuln' : ''}">${escapeHtml(o.name)} ×${o.count}</span>`).join(' ')
    : '<span class="tag">未发现</span>';
  els.detectedApis.innerHTML = aggregate.apiEndpoints?.length
    ? aggregate.apiEndpoints.slice(0, 20).map((api) =>
        `<span class="tag api" title="${escapeAttr(api.value)}">${escapeHtml(truncate(api.value, 80))} ×${api.count}</span>`).join(' ')
    : '<span class="tag">未发现</span>';
  if (els.detectedRoutes) {
    els.detectedRoutes.innerHTML = aggregate.routes?.length
      ? aggregate.routes.slice(0, 28).map((route) =>
          `<span class="tag api ${route.sensitive ? 'crypto-vuln' : ''}" title="${escapeAttr(route.value)}">${escapeHtml(truncate(route.value, 80))} ×${route.count}</span>`).join(' ')
      : '<span class="tag">未发现</span>';
  }
  if (els.detectedModules) {
    els.detectedModules.innerHTML = aggregate.moduleHints?.length
      ? aggregate.moduleHints.slice(0, 24).map((mod) =>
          `<span class="tag" title="${escapeAttr(mod.value)}">${escapeHtml(truncate(mod.value, 72))} ×${mod.count}</span>`).join(' ')
      : '<span class="tag">未发现</span>';
  }

  const weak = collectWeakAlgos();
  els.detectedWeak.innerHTML = weak.length
    ? weak.map((w) => `<span class="tag crypto-vuln">${escapeHtml(w)}</span>`).join(' ')
    : '<span class="tag">未发现</span>';

  els.detectedExposures.innerHTML = aggregate.exposures.length
    ? aggregate.exposures.map((e) =>
        `<span class="tag">${escapeHtml(e.name)} ×${e.count}</span>`).join(' ')
    : '<span class="tag">未发现</span>';
}

function collectWeakAlgos() {
  const set = new Set();
  for (const f of perFileResults) {
    for (const fi of f.findings) {
      if (fi.category === 'crypto-vuln' && fi.confidence !== 'suspected') set.add(fi.ruleName);
    }
  }
  return Array.from(set);
}

function passConfidenceFilter(fi) {
  const mode = els.confidence.value;
  if (mode === 'confirmed') return fi.confidence === 'confirmed';
  if (mode === 'all') return true;
  // actionable 默认：confirmed + likely
  return fi.confidence === 'confirmed' || fi.confidence === 'likely';
}

function renderResults() {
  const keyword = els.search.value.trim().toLowerCase();
  const sevF = els.severity.value;
  const catF = els.category.value;
  const grouped = els.groupByFile.checked;

  const filteredFiles = perFileResults.map((f) => {
    const findings = f.findings.filter((x) => {
      if (!passConfidenceFilter(x)) return false;
      if (sevF !== 'all' && x.severity !== sevF) return false;
      if (catF !== 'all' && x.category !== catF) return false;
      if (!keyword) return true;
      return (x.ruleName + ' ' + x.match + ' ' + f.file).toLowerCase().includes(keyword);
    }).sort(sortFindingDesc);
    return { ...f, findings };
  }).filter((f) => f.findings.length > 0 || f.error).sort(sortFileGroupDesc);

  els.results.innerHTML = '';
  if (filteredFiles.length === 0) {
    const totalActionable = perFileResults.reduce(
      (a, f) => a + f.findings.filter(passConfidenceFilter).length, 0);
    els.results.innerHTML = totalActionable === 0 && perFileResults.length > 0
      ? '<div class="empty">已扫描内容在当前过滤条件下未发现线索。请同时查看上方覆盖说明；此结果不代表网站不存在泄露。</div>'
      : '<div class="empty">未匹配到结果</div>';
    return;
  }

  let shown = 0;
  if (grouped) {
    for (const f of filteredFiles) {
      if (shown >= renderLimit) break;
      const subset = f.findings.slice(0, renderLimit - shown);
      els.results.appendChild(renderFileGroup({ ...f, findings: subset }));
      shown += Math.max(1, subset.length);
    }
  } else {
    const flat = [];
    for (const f of filteredFiles) {
      for (const finding of f.findings) flat.push({ file: f, finding });
    }
    flat.sort((a, b) => sortFindingDesc(a.finding, b.finding));
    const wrap = document.createElement('div');
    wrap.className = 'file-group';
    const head = document.createElement('div');
    head.className = 'file-header';
    head.innerHTML = `<span class="url">所有 finding（按置信度+严重度）</span><span class="badges"><span class="tag">${flat.length}</span></span>`;
    wrap.appendChild(head);
    const list = document.createElement('div');
    list.className = 'findings';
    for (const f of filteredFiles.filter(f => f.error).slice(0, renderLimit)) {
      els.results.appendChild(renderFileGroup(f)); shown++;
    }
    const visible = flat.slice(0, Math.max(0, renderLimit - shown));
    for (const item of visible) list.appendChild(renderFinding(item.finding, item.file));
    shown += visible.length;
    wrap.appendChild(list);
    els.results.appendChild(wrap);
  }
  if (filteredFiles.reduce((n, f) => n + Math.max(1, f.findings.length), 0) > shown) {
    const button = document.createElement('button');
    button.textContent = '显示更多（完整结果已包含在导出报告中）';
    button.addEventListener('click', () => { renderLimit += 200; renderResults(); });
    els.results.appendChild(button);
  }
}

function sortFindingDesc(a, b) {
  const A = self.JS_EXTRACTOR_ANALYZER;
  const ds = (A.SEVERITY_WEIGHT[b.severity] ?? -1) - (A.SEVERITY_WEIGHT[a.severity] ?? -1);
  if (ds !== 0) return ds;
  const dc = (A.CONFIDENCE_WEIGHT[b.confidence] ?? -1) - (A.CONFIDENCE_WEIGHT[a.confidence] ?? -1);
  if (dc !== 0) return dc;
  return (a.line || 0) - (b.line || 0);
}

function sortFileGroupDesc(a, b) {
  const topA = a.findings?.[0] || {};
  const topB = b.findings?.[0] || {};
  const byTop = sortFindingDesc(topA, topB);
  if (byTop !== 0) return byTop;
  const byCount = (b.findings?.length || 0) - (a.findings?.length || 0);
  if (byCount !== 0) return byCount;
  return String(a.file || '').localeCompare(String(b.file || ''));
}

function getReportFiles(filterFn = () => true, includeEmpty = false) {
  const files = perFileResults.map((f) => ({
    ...f,
    findings: f.findings.filter(filterFn).sort(sortFindingDesc)
  }));
  const withFindings = files.filter((f) => f.findings.length > 0).sort(sortFileGroupDesc);
  if (!includeEmpty) return withFindings;
  const empty = files.filter((f) => f.findings.length === 0)
    .sort((a, b) => String(a.file || '').localeCompare(String(b.file || '')));
  return withFindings.concat(empty);
}

function renderFileGroup(f) {
  const wrap = document.createElement('section');
  wrap.className = 'file-group';

  const head = document.createElement('div');
  head.className = 'file-header';
  const counts = countBySeverity(f.findings);
  const badges = ['critical', 'high', 'medium', 'low']
    .filter((s) => counts[s])
    .map((s) => `<span class="sev-badge ${s}">${counts[s]}</span>`)
    .join('');
  head.innerHTML = `
    <span class="url" title="${escapeAttr(f.file)}">${escapeHtml(f.file)}</span>
    <span class="badges">
      ${f.error ? `<span class="tag crypto-vuln">未完成</span>` : ''}
      ${f.kind === 'collected-inline' ? '<span class="tag">历史采集快照</span>' : ''}
      ${f.truncated ? '<span class="tag">内容截断</span>' : ''}
      <span class="tag">${formatBytes(f.size)}</span>
      ${badges}
    </span>`;
  wrap.appendChild(head);
  head.addEventListener('click', () => wrap.classList.toggle('collapsed'));

  if (f.error) {
    const list = document.createElement('div');
    list.className = 'findings';
    list.innerHTML = `<div class="empty">此资源未完成扫描: ${escapeHtml(f.error)}</div>`;
    wrap.appendChild(list);
    return wrap;
  }

  const list = document.createElement('div');
  list.className = 'findings';
  for (const fi of f.findings) list.appendChild(renderFinding(fi, f));
  wrap.appendChild(list);
  return wrap;
}

function countBySeverity(findings) {
  const c = {};
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

function renderFinding(fi, fileObj) {
  const node = document.createElement('div');
  node.className = 'finding ' + fi.confidence;

  node.innerHTML = `
    <div><span class="sev-badge ${fi.severity}">${sevLabel(fi.severity)}</span></div>
    <div class="body">
      <div>
        <span class="name">${escapeHtml(fi.ruleName)}</span>
        <span class="conf-badge ${fi.confidence}">${confLabel(fi.confidence)}</span>
        <span class="tag ${fi.category}">${fi.category}</span>
        <span class="pos">L${fi.line}:${fi.col}</span>
      </div>
      <div class="desc">${escapeHtml(fi.description || '')}</div>
      ${fi.evidence ? `<div class="evidence">✓ 证据：${escapeHtml(fi.evidence)}</div>` : ''}
      ${fi.exploit ? `<div class="exploit">潜在影响（需核验）：${escapeHtml(fi.exploit)}</div>` : ''}
      ${fi.recommendation ? `<div class="recommend">建议：${escapeHtml(fi.recommendation)}</div>` : ''}
      <div class="ctx">${renderContextHtml(fi.context)}</div>
    </div>
    <div class="actions">
      <button class="copy">复制</button>
      <button class="view">查看上下文</button>
    </div>`;

  node.querySelector('.copy').addEventListener('click', () => navigator.clipboard.writeText(fi.match));
  node.querySelector('.view').addEventListener('click', () => openViewer(fileObj, fi));
  return node;
}

function renderContextHtml(ctx) {
  if (!ctx) return '';
  return escapeHtml(ctx.before.slice(-80)) + '<em>' + escapeHtml(truncate(ctx.match, 500)) + '</em>' + escapeHtml(ctx.after.slice(0, 80));
}

function openViewer(fileObj, fi) {
  els.viewerTitle.textContent = `${fi.ruleName}  @  ${fileObj.file}  (L${fi.line})`;
  const { before = '', match: matchPart = fi.match || '', after = '' } = fi.context || {};
  els.viewerContent.innerHTML =
    escapeHtml(before) + '<mark>' + escapeHtml(matchPart) + '</mark>' + escapeHtml(after);
  els.viewer.showModal();
}

function sevLabel(s) {
  return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' })[s] || s;
}
function confLabel(c) {
  return ({ confirmed: '高置信（静态）', likely: '较可信（静态）', suspected: '疑似' })[c] || c;
}
function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function escapeAttr(str) { return escapeHtml(str); }
function truncate(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }
function formatBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1024 / 1024).toFixed(2) + ' MB';
}

async function exportJson() {
  if (!canExport()) return;
  const payload = {
    schemaVersion: 2,
    scanId: scanSession.id,
    origin: els.origin.textContent,
    exportedAt: new Date().toISOString(),
    coverage: coverageSnapshot(),
    aggregate,
    files: getReportFiles(() => true, true).map((f) => ({
      file: f.file, size: f.size, error: f.error, status: f.status, truncated: f.truncated,
      requestedUrl: f.requestedUrl, responseUrl: f.responseUrl, parentMap: f.parentMap, encoding: f.encoding,
      kind: f.kind, collectedAt: f.collectedAt,
      stats: f.stats,
      findings: f.findings.map(({ context, ...rest }) => rest)
    }))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  await downloadReportBlob(blob, `scan-report-${Date.now()}.json`);
}

async function exportMd() {
  if (!canExport()) return;
  const lines = [];
  lines.push(`# 玄镜 AegisScope 泄露扫描报告`);
  lines.push(`- 来源: ${els.origin.textContent}`);
  lines.push(`- 时间: ${new Date().toLocaleString()}`);
  lines.push(`- 综合风险: **${aggregate.level}** (score=${aggregate.score})`);
  lines.push(`- 高置信/较可信线索: ${aggregate.actionable}（高置信 ${aggregate.byConfidence.confirmed} · 较可信 ${aggregate.byConfidence.likely}）`);
  lines.push(`- 疑似: ${aggregate.byConfidence.suspected}；独立线索 ${aggregate.uniqueFindings}；命中位置 ${aggregate.findings}`);
  const coverage = coverageSnapshot();
  lines.push(`- 扫描状态: ${coverage.status}；已分析 ${coverage.analyzed}；失败 ${coverage.failed}；截断 ${coverage.truncated}；跳过 ${coverage.skipped}`);
  lines.push(`- 范围: ${coverage.scope}`);
  lines.push(`- 判定方式: ${coverage.verification}`);
  for (const entry of coverage.issues) lines.push(`- 覆盖说明: ${entry.url} — ${entry.reason}`);
  if (aggregate.cryptoLibs.length) lines.push(`- 加密库: ${aggregate.cryptoLibs.join('、')}`);
  if (aggregate.cryptoAlgos.length) lines.push(`- 加密算法: ${aggregate.cryptoAlgos.join('、')}`);
  if (aggregate.decryptions?.length) {
    lines.push('- 解密/验证方式:');
    for (const d of aggregate.decryptions) lines.push(`  - ${d.name}: ${d.decrypt}`);
  }
  if (aggregate.bundlers?.length) lines.push(`- 打包器/框架: ${aggregate.bundlers.join('、')}`);
  if (aggregate.frameworks?.length) lines.push(`- 前端框架/库: ${aggregate.frameworks.join('、')}`);
  if (aggregate.obfuscation?.length) {
    lines.push('- 混淆/压缩特征:');
    for (const o of aggregate.obfuscation) lines.push(`  - ${o.name}: ${o.count} 次 / ${o.files} 个文件`);
  }
  if (aggregate.apiEndpoints?.length) {
    lines.push('- Top 接口线索:');
    for (const api of aggregate.apiEndpoints.slice(0, 30)) lines.push(`  - ${api.value}  (${api.count})`);
  }
  if (aggregate.routes?.length) {
    lines.push('- Top 路由线索:');
    for (const route of aggregate.routes.slice(0, 30)) lines.push(`  - ${route.value}  (${route.count}${route.sensitive ? ', sensitive' : ''})`);
  }
  if (aggregate.moduleHints?.length) {
    lines.push('- Top 模块路径:');
    for (const mod of aggregate.moduleHints.slice(0, 30)) lines.push(`  - ${mod.value}  (${mod.count})`);
  }
  lines.push('');
  lines.push('---');
  lines.push('');

  // Both reports include every confidence and every failed resource, independent of UI filters.
  for (const f of getReportFiles(() => true, true)) {
    const list = f.findings;
    lines.push(`## ${f.file}`);
    if (f.error) lines.push(`- 未完成: ${f.error}`);
    if (f.kind === 'collected-inline') lines.push('- 来源: 历史采集快照，当前 DOM 中未找到对应完整脚本；不追溯推测其依赖地址。');
    if (f.truncated) lines.push('- 内容被截断，检测范围不完整');
    if (f.responseUrl && f.responseUrl !== f.requestedUrl) lines.push(`- 实际响应: ${f.responseUrl}`);
    for (const fi of list) {
      lines.push(`### [${sevLabel(fi.severity)}/${confLabel(fi.confidence)}] ${fi.ruleName}  (L${fi.line})`);
      if (fi.description) lines.push(`- 描述: ${fi.description}`);
      if (fi.evidence) lines.push(`- 证据: ${fi.evidence}`);
      if (fi.exploit) lines.push(`- 利用: ${fi.exploit}`);
      if (fi.recommendation) lines.push(`- 建议: ${fi.recommendation}`);
      lines.push('- 命中（完整内容）:');
      const fence = '`'.repeat(Math.max(3, ...Array.from((fi.match || '').matchAll(/`+/g), m => m[0].length + 1)));
      lines.push(fence + 'text', fi.match || '', fence);
      lines.push('');
    }
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
  await downloadReportBlob(blob, `scan-report-${Date.now()}.md`);
}

async function downloadReportBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  try {
    await chrome.downloads.download({ url, filename: `js-extractor/${filename}`, saveAs: true });
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }
}

function canExport() {
  if (!scanning && aggregate && scanSession) return true;
  els.progressSub.textContent = scanning ? '扫描进行中，请完成或停止后导出本轮结果。' : '尚无本轮扫描结果可导出。';
  return false;
}
function showExportError(error) { els.progressSub.textContent = `导出失败：${error.message || error}`; }

runScanOptimized();
