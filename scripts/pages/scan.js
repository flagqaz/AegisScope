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
const scanTextCache = new Map();
let scanTextCacheChars = 0;
const SCAN_MAX_QUEUE_ITEMS = 1200;
const SCAN_MAX_RESOURCE_BYTES = 8 * 1024 * 1024;
const SCAN_MAX_CACHE_CHARS = 48 * 1024 * 1024;
const SCAN_FETCH_TIMEOUT_MS = 12000;

['critical', 'high', 'medium', 'low'].forEach((sev) => {
  document.getElementById('cnt-' + sev).textContent = '0';
});

els.rescan.addEventListener('click', () => runScanOptimized());
els.exportJson.addEventListener('click', exportJson);
els.exportMd.addEventListener('click', exportMd);
els.search.addEventListener('input', renderResults);
els.severity.addEventListener('change', renderResults);
els.category.addEventListener('change', renderResults);
els.confidence.addEventListener('change', renderResults);
els.groupByFile.addEventListener('change', renderResults);
els.viewerClose.addEventListener('click', () => els.viewer.close());

runScanOptimized();

async function runScanOptimized() {
  if (scanning) return;
  scanning = true;
  perFileResults = [];
  scanTextCache.clear();
  scanTextCacheChars = 0;
  els.results.innerHTML = '';
  els.riskLevel.textContent = '扫描中...';
  els.progress.textContent = '初始化';
  els.progressSub.textContent = '';

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SCRIPTS', tabId: targetTabId });
    const scripts = resp?.scripts || [];
    const pageResources = await getPageCodeResources();

    try {
      const tab = await chrome.tabs.get(targetTabId);
      els.origin.textContent = tab.url || '';
    } catch { /* ignore */ }

    if (scripts.length === 0 && !pageResources.items?.length && !pageResources.html) {
      els.results.innerHTML = '<div class="empty">未发现可扫描代码资源，请回到目标页面让插件抓取后再扫描。</div>';
      els.riskLevel.textContent = '无数据';
      return;
    }

    const queue = [];
    const seen = new Set();
    const discovered = { chunks: 0, maps: 0, sourceMapSources: 0, ignored404: 0 };
    const enqueue = (item) => {
      const key = item.inline ? `inline:${item.url}` : item.url;
      if (!key || seen.has(key) || queue.length >= SCAN_MAX_QUEUE_ITEMS) return;
      seen.add(key);
      queue.push(item);
    };
    if (pageResources.html) {
      enqueue({
        url: `[页面HTML] ${pageResources.url || els.origin.textContent || 'current-page'}`,
        inline: true,
        content: pageResources.html,
        kind: 'document'
      });
    }
    for (const item of pageResources.items || []) enqueue({ ...item, discovered: true });
    scripts.forEach((s) => enqueue({
      ...s,
      kind: s.inline ? 'inline' : 'script',
      discovered: !s.inline && s.source !== 'network' && !s.statusCode
    }));

    let done = 0;
    let active = 0;
    let cursor = 0;
    let lastPaint = 0;
    const concurrency = Math.min(6, Math.max(2, navigator.hardwareConcurrency || 4));

    await new Promise((resolve) => {
      const pump = () => {
        while (active < concurrency && cursor < queue.length) {
          const item = queue[cursor++];
          active++;
          processScanItem(item, enqueue, discovered)
            .then((results) => {
              for (const result of results) perFileResults.push(result);
            })
            .catch(() => {
              discovered.ignored404++;
            })
            .finally(() => {
              done++;
              active--;
              els.progress.textContent = `${done} / ${queue.length}`;
              els.progressSub.textContent = `chunks ${discovered.chunks} · maps ${discovered.maps} · sources ${discovered.sourceMapSources} · 忽略404 ${discovered.ignored404}`;
              const now = performance.now();
              if (now - lastPaint > 180 || done === queue.length) {
                updateAggregate();
                renderResults();
                lastPaint = now;
              }
              if (cursor >= queue.length && active === 0) resolve();
              else pump();
            });
        }
      };
      pump();
    });

    updateAggregate();
    renderResults();
    els.progress.textContent = `完成 ${perFileResults.length}`;
    const totalFindings = perFileResults.reduce((a, f) => a + f.findings.length, 0);
    els.progressSub.textContent = `${totalFindings} 条 finding · chunk ${discovered.chunks} · sourcemap ${discovered.maps} · 忽略无效资源 ${discovered.ignored404}`;
  } catch (err) {
    els.progress.textContent = '扫描失败';
    els.progressSub.textContent = err?.message || String(err);
    els.riskLevel.textContent = '可重试';
    if (!perFileResults.length) {
      els.results.innerHTML = '<div class="empty">扫描初始化失败，请检查目标页面后重新扫描。</div>';
    }
  } finally {
    scanning = false;
  }
}

async function processScanItem(item, enqueue, discovered) {
  const outputs = [];
  let source = '';

  if (item.inline) {
    source = item.content || '';
  } else {
    source = await readCodeForScan(item.url);
  }

  const fileName = item.inline ? `[内联] ${item.url}` : item.url;
  outputs.push(analyzeFile(fileName, source, item));

  if (!item.inline) {
    for (const url of discoverRelatedCodeUrls(source, item.url)) {
      if (/\.map(?:[?#]|$)/i.test(url)) discovered.maps++;
      else discovered.chunks++;
      enqueue({ url, kind: /\.map(?:[?#]|$)/i.test(url) ? 'sourcemap' : 'chunk', discovered: true });
    }
  }

  if (item.kind === 'sourcemap' || /\.map(?:[?#]|$)/i.test(item.url || '')) {
    for (const mapped of extractSourceMapSources(source, item.url)) {
      discovered.sourceMapSources++;
      outputs.push(analyzeFile(mapped.file, mapped.source, { url: mapped.file, sourcemap: item.url }));
      if (outputs.length > 80) break;
    }
  } else {
    const inlineMap = extractInlineSourceMap(source, item.url || fileName);
    if (inlineMap) {
      discovered.maps++;
      for (const mapped of inlineMap) {
        discovered.sourceMapSources++;
        outputs.push(analyzeFile(mapped.file, mapped.source, { url: mapped.file, sourcemap: item.url }));
        if (outputs.length > 80) break;
      }
    }
  }

  await new Promise((r) => setTimeout(r, 0));
  return outputs;
}

async function fetchCodeForScan(url) {
  const target = new URL(url, location.href);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_FETCH_TIMEOUT_MS);
  let sameOrigin = false;
  try {
    const originText = els.origin.textContent || '';
    sameOrigin = originText && new URL(originText).origin === target.origin;
  } catch { /* ignore */ }

  const options = {
    credentials: sameOrigin ? 'include' : 'omit',
    cache: 'force-cache',
    referrer: els.origin.textContent || undefined,
    signal: controller.signal
  };
  try {
    let res = await fetch(target.href, options);
    if (!res.ok && sameOrigin && target.search) {
      await res.body?.cancel?.().catch(() => {});
      const clean = new URL(target.href);
      clean.search = '';
      res = await fetch(clean.href, options);
    }
    if (!res.ok) await res.body?.cancel?.().catch(() => {});
    const text = res.ok ? await readResponseTextLimited(res, SCAN_MAX_RESOURCE_BYTES) : '';
    return { response: res, text };
  } finally {
    clearTimeout(timer);
  }
}

async function readCodeForScan(url) {
  if (scanTextCache.has(url)) return scanTextCache.get(url);
  const { response, text } = await fetchCodeForScan(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  scanTextCache.set(url, text);
  scanTextCacheChars += text.length;
  while (scanTextCache.size > 800 || scanTextCacheChars > SCAN_MAX_CACHE_CHARS) {
    const first = scanTextCache.keys().next().value;
    if (first == null) break;
    scanTextCacheChars -= String(scanTextCache.get(first) || '').length;
    scanTextCache.delete(first);
  }
  return text;
}

async function readResponseTextLimited(response, maxBytes) {
  const reader = response.body?.getReader?.();
  if (!reader) return (await response.text()).slice(0, maxBytes);
  const decoder = new TextDecoder();
  let total = 0;
  let text = '';
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = maxBytes - total;
      const chunk = value.byteLength > remaining ? value.subarray(0, remaining) : value;
      total += chunk.byteLength;
      text += decoder.decode(chunk, { stream: total < maxBytes });
      if (value.byteLength > remaining) break;
    }
    text += decoder.decode();
    if (total >= maxBytes) await reader.cancel().catch(() => {});
    return text;
  } finally {
    try { reader.releaseLock(); } catch {}
  }
}

async function getPageCodeResources() {
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: targetTabId },
      func: collectPageCodeResources
    });
    return result?.result || { items: [] };
  } catch {
    return { items: [] };
  }
}

function collectPageCodeResources() {
  const maxItems = 1200;
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
    items.set(url.href, { url: url.href, kind });
  };

  for (const el of document.querySelectorAll('script[src]')) {
    add(el.src || el.getAttribute('src'), 'script');
    if (items.size >= maxItems) break;
  }
  for (const el of document.querySelectorAll('iframe[src], frame[src]')) {
    if (items.size >= maxItems) break;
    add(el.src || el.getAttribute('src'), 'document');
  }
  for (const el of document.querySelectorAll('link[href]')) {
    if (items.size >= maxItems) break;
    const rel = (el.rel || '').toLowerCase();
    const as = (el.as || '').toLowerCase();
    if (rel.includes('stylesheet') || rel.includes('icon') || (rel.includes('preload') && as === 'style')) continue;
    add(el.href || el.getAttribute('href'), rel.includes('manifest') ? 'manifest' : 'resource');
  }
  for (const entry of performance.getEntriesByType('resource')) {
    if (items.size >= maxItems) break;
    const type = entry.initiatorType || 'resource';
    if (['css', 'img', 'image', 'audio', 'video', 'font'].includes(type)) continue;
    add(entry.name, type === 'iframe' ? 'document' : type === 'script' ? 'script' : 'resource');
  }

  return {
    url: location.href,
    html: ('<!DOCTYPE html>\n' + document.documentElement.outerHTML).slice(0, 2 * 1024 * 1024),
    items: Array.from(items.values())
  };
}

function analyzeFile(file, source, meta = {}) {
  const normalized = normalizeBundleSource(source);
  const result = self.JS_EXTRACTOR_ANALYZER.analyzeSource(normalized, { url: file, originalUrl: meta.url });
  return {
    file,
    inline: !!meta.inline,
    size: source.length,
    findings: result.findings,
    stats: result.stats,
    source: normalized
  };
}

function normalizeBundleSource(source) {
  if (!source || source.length < 5000) return source || '';
  const newlineCount = (source.match(/\n/g) || []).length;
  if (newlineCount > source.length / 4000) return source;
  return source
    .replace(/;/g, ';\n')
    .replace(/\{/g, '{\n')
    .replace(/\}/g, '\n}\n')
    .replace(/,(?=["'][A-Za-z0-9_$-]{2,}["']\s*:)/g, ',\n');
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
  const mapRe = /\/\/[#@]\s*sourceMappingURL=([^\s"'<>]+)/g;
  while ((m = mapRe.exec(source)) !== null) add(m[1], 'map');

  const jsStringRe = /["'`]((?:(?:https?:)?\/\/|\/|\.{1,2}\/|(?:static|assets|js|dist|chunks|_next|_nuxt|tinymce|videoPlayer)\/)[^"'`\s<>]{1,220}\.(?:js|mjs|cjs|map)(?:\?[^"'`\s<>]*)?)["'`]/gi;
  while ((m = jsStringRe.exec(source)) !== null) add(m[1]);

  const webpackConcatRe = /(?:u|miniCssF)\s*=\s*function\s*\([^)]*\)\s*\{[\s\S]{0,1200}?return\s+([^;]+);/g;
  while ((m = webpackConcatRe.exec(source)) !== null) {
    const literals = [...m[1].matchAll(/["']([^"']+)["']/g)].map((x) => x[1]).join('');
    if (/\.(?:js|mjs|cjs)(?:[?#]|$)/i.test(literals)) add(literals.replace(/\+.*$/, ''));
  }

  for (const url of discoverWebpackRuntimeChunks(source, baseUrl)) add(url);
  for (const url of discoverFrameworkAssets(source, baseUrl)) add(url);

  return Array.from(out).slice(0, 160);
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
      if (++count >= 80) break;
    }
  }
  return Array.from(out).slice(0, 120);
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

  return Array.from(out).slice(0, 120);
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

function extractInlineSourceMap(source, baseUrl) {
  const m = /sourceMappingURL=data:application\/json(?:;charset=[^;,]+)?;base64,([A-Za-z0-9+/=]+)/.exec(source);
  if (!m) return null;
  try {
    const json = decodeURIComponent(escape(atob(m[1])));
    return extractSourceMapSources(json, baseUrl + '#inline-map');
  } catch {
    return null;
  }
}

function extractSourceMapSources(mapText, mapUrl) {
  let map;
  try { map = JSON.parse(mapText); } catch { return []; }
  const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
  const sources = Array.isArray(map.sources) ? map.sources : [];
  const out = [];
  for (let i = 0; i < contents.length; i++) {
    const content = contents[i];
    if (!content || typeof content !== 'string') continue;
    const rawName = sources[i] || `source-${i}.js`;
    let file = rawName;
    try { file = new URL(rawName, mapUrl).href; } catch { /* keep raw */ }
    out.push({ file: `[sourcemap] ${file}`, source: content });
    if (out.length >= 120) break;
  }
  return out;
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
  aggregate = self.JS_EXTRACTOR_ANALYZER.aggregateReport(perFileResults);

  els.riskLevel.textContent = aggregate.level;
  els.riskScore.textContent = `score ${aggregate.score} · 可利用 ${aggregate.actionable} / 共 ${aggregate.findings}`;

  // 严重度计数：仅显示 actionable（confirmed+likely）作为主指标
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    document.getElementById('cnt-' + sev).textContent =
      String(aggregate.actionableBySeverity[sev] || 0);
    const subEl = document.getElementById(`cnt-${sev}-conf`);
    if (subEl) {
      const totalSev = aggregate.bySeverity[sev] || 0;
      const susp = totalSev - (aggregate.actionableBySeverity[sev] || 0);
      subEl.textContent = susp > 0 ? `+${susp} 疑似` : '已确认';
    }
  }

  els.confActionable.textContent = String(aggregate.actionable);
  els.confBreakdown.textContent =
    `已确认 ${aggregate.byConfidence.confirmed} · 大概率 ${aggregate.byConfidence.likely} · 疑似 ${aggregate.byConfidence.suspected}`;

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
  }).filter((f) => f.findings.length > 0).sort(sortFileGroupDesc);

  els.results.innerHTML = '';
  if (filteredFiles.length === 0) {
    const totalActionable = perFileResults.reduce(
      (a, f) => a + f.findings.filter(passConfidenceFilter).length, 0);
    els.results.innerHTML = totalActionable === 0 && perFileResults.length > 0
      ? '<div class="empty">✓ 当前过滤条件下未发现可利用漏洞。<br>如需查看模式匹配但未确认的项，请将「置信度」切换为「全部含疑似」。</div>'
      : '<div class="empty">未匹配到结果</div>';
    return;
  }

  if (grouped) {
    for (const f of filteredFiles) els.results.appendChild(renderFileGroup(f));
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
    for (const item of flat) list.appendChild(renderFinding(item.finding, item.file));
    wrap.appendChild(list);
    els.results.appendChild(wrap);
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
      ${f.error ? `<span class="tag crypto-vuln">加载失败</span>` : ''}
      <span class="tag">${formatBytes(f.size)}</span>
      ${badges}
    </span>`;
  wrap.appendChild(head);
  head.addEventListener('click', () => wrap.classList.toggle('collapsed'));

  if (f.error) {
    const list = document.createElement('div');
    list.className = 'findings';
    list.innerHTML = `<div class="empty">无法获取脚本内容: ${escapeHtml(f.error)}（CORS 或受限页面）</div>`;
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
      ${fi.exploit ? `<div class="exploit">${escapeHtml(fi.exploit)}</div>` : ''}
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
  return escapeHtml(ctx.before) + '<em>' + escapeHtml(ctx.match) + '</em>' + escapeHtml(ctx.after);
}

function openViewer(fileObj, fi) {
  els.viewerTitle.textContent = `${fi.ruleName}  @  ${fileObj.file}  (L${fi.line})`;
  const src = fileObj.source || '';
  const start = Math.max(0, fi.offset - 800);
  const end = Math.min(src.length, fi.offset + (fi.match?.length || 0) + 800);
  const before = src.slice(start, fi.offset);
  const matchPart = src.slice(fi.offset, fi.offset + fi.match.length);
  const after = src.slice(fi.offset + fi.match.length, end);
  els.viewerContent.innerHTML =
    escapeHtml(before) + '<mark>' + escapeHtml(matchPart) + '</mark>' + escapeHtml(after);
  els.viewer.showModal();
}

function sevLabel(s) {
  return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' })[s] || s;
}
function confLabel(c) {
  return ({ confirmed: '已确认', likely: '大概率', suspected: '疑似' })[c] || c;
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
  const payload = {
    origin: els.origin.textContent,
    exportedAt: new Date().toISOString(),
    aggregate,
    files: getReportFiles(() => true, true).map((f) => ({
      file: f.file, size: f.size, error: f.error,
      stats: f.stats,
      findings: f.findings.map(({ context, ...rest }) => rest)
    }))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  await downloadReportBlob(blob, `scan-report-${Date.now()}.json`);
}

async function exportMd() {
  const lines = [];
  lines.push(`# 玄镜 AegisScope 泄露扫描报告`);
  lines.push(`- 来源: ${els.origin.textContent}`);
  lines.push(`- 时间: ${new Date().toLocaleString()}`);
  lines.push(`- 综合风险: **${aggregate.level}** (score=${aggregate.score})`);
  lines.push(`- 可利用 finding: ${aggregate.actionable}（已确认 ${aggregate.byConfidence.confirmed} · 大概率 ${aggregate.byConfidence.likely}）`);
  lines.push(`- 疑似（默认隐藏）: ${aggregate.byConfidence.suspected}`);
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

  // 仅导出 actionable
  for (const f of getReportFiles((x) => x.confidence !== 'suspected')) {
    const list = f.findings;
    lines.push(`## ${f.file}`);
    for (const fi of list) {
      lines.push(`### [${sevLabel(fi.severity)}/${confLabel(fi.confidence)}] ${fi.ruleName}  (L${fi.line})`);
      if (fi.description) lines.push(`- 描述: ${fi.description}`);
      if (fi.evidence) lines.push(`- 证据: ${fi.evidence}`);
      if (fi.exploit) lines.push(`- 利用: ${fi.exploit}`);
      if (fi.recommendation) lines.push(`- 建议: ${fi.recommendation}`);
      lines.push('- 命中: `' + (fi.match || '').replace(/`/g, '\\`').slice(0, 200) + '`');
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
