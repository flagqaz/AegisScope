// Shared passive signal matcher for the popup and its cancellable worker.
const SNIFF_REGEX_CACHE = new Map();
const SNIFF_REGEX_CACHE_LIMIT = 8192;
const SNIFF_MAX_EVIDENCE_PER_RULE = 24;
const SNIFF_ANALYZE_SLICE_MS = 7;
const SNIFF_STRONG_SOURCES = new Set(['headers', 'cookies', 'meta', 'globals', 'vueRuntime', 'jqueryRuntime', 'reactRuntime', 'dom']);
const SNIFF_MEDIUM_SOURCES = new Set(['scriptSrc', 'resourceUrl', 'url', 'htmlAttr', 'bodyAttr']);
let sniffPreparedRuleCache = null;
let sniffTechnologyCatalogCache = null;

function normalizeSniffSignals(page = {}, runtime = {}, background = {}) {
  const main = background?.main || {};
  const headers = mergeSniffHeaders(main.headers || {});
  const resources = dedupeSniffResources([
    ...(background?.resources || []),
    ...(background?.scripts || []),
    ...(page.resources || [])
  ]);
  const scriptSrc = sniffUnique([
    ...(page.scriptSrc || []),
    ...resources
      .filter((item) => item.type === 'script' || /\.m?js(?:[?#]|$)/i.test(item.url || ''))
      .map((item) => item.url)
  ]);
  const resourceUrls = sniffUnique(resources.map((item) => item.url).filter(Boolean));
  const resourceHosts = sniffUnique(resourceUrls.map(sniffHost).filter(Boolean));
  const xhrHosts = sniffUnique(resources
    .filter((item) => /xmlhttprequest|fetch|beacon|ping/i.test(item.type || ''))
    .map((item) => sniffHost(item.url))
    .filter(Boolean));
  const xhrUrls = sniffUnique(resources.filter(item => /xmlhttprequest|fetch|beacon|ping/i.test(item.type || ''))
    .map(item => { try { const url = new URL(item.url); return url.hostname.toLowerCase() + url.pathname; } catch { return ''; } }).filter(Boolean));
  return {
    url: page.url || main.url || '',
    documentEpoch: page.documentEpoch,
    coverage: sniffUnique([...(page.coverage || []), ...(runtime.coverage || [])]),
    title: page.title || '',
    html: page.html || '',
    text: page.text || '',
    css: page.css || '',
    scripts: page.scripts || [],
    meta: page.meta || {},
    cookies: page.cookies || {},
    classNames: page.classNames || [],
    ids: page.ids || [],
    vueMarkers: page.vueMarkers || [],
    linkHrefs: page.linkHrefs || [],
    styleHrefs: page.styleHrefs || [],
    htmlAttrs: page.htmlAttrs || {},
    bodyAttrs: page.bodyAttrs || {},
    selectorMatches: page.selectorMatches || [],
    headers,
    resources,
    scriptSrc,
    resourceUrls,
    resourceHosts,
    xhrHosts,
    xhrUrls,
    globals: runtime.globals || {},
    globalScalars: runtime.globalScalars || {},
    vueRuntime: runtime.vueRuntime || [],
    jqueryRuntime: runtime.jqueryRuntime || [],
    reactRuntime: runtime.reactRuntime || [],
    domSignals: runtime.domSignals || [],
    main
  };
}

function mergeSniffHeaders(...items) {
  const out = {};
  for (const item of items) {
    for (const [key, value] of Object.entries(item || {})) {
      const name = key.toLowerCase();
      out[name] = sniffUnique([...(out[name] || []), ...sniffArray(value).map(String)]);
    }
  }
  return out;
}

function dedupeSniffResources(resources) {
  const seen = new Map();
  for (const item of resources || []) {
    if (!item?.url) continue;
    const type = item.type || item.kind || (item.inline ? 'inline-script' : 'resource');
    seen.set(`${type}:${item.url}`, {
      url: item.url,
      type,
      statusCode: item.statusCode || 0,
      fromCache: !!item.fromCache
    });
  }
  return Array.from(seen.values());
}

function analyzeSniffSignals(signals) {
  const rules = getPreparedSniffRules();
  const signalIndex = buildSniffSignalIndex(signals);
  const detected = [];
  for (const rule of rules) {
    const finding = analyzeSniffRule(signals, signalIndex, rule);
    if (finding) detected.push(finding);
  }
  return detected;
}

async function analyzeSniffSignalsCooperatively(signals, runSeq, onProgress) {
  const rules = await getPreparedSniffRulesCooperatively(runSeq);
  if (!rules || runSeq !== sniffRunSeq) return null;
  const signalIndex = buildSniffSignalIndex(signals);
  const detected = [];
  let sliceStartedAt = performance.now();
  for (const rule of rules) {
    if (runSeq !== sniffRunSeq) return null;
    const finding = analyzeSniffRule(signals, signalIndex, rule);
    if (finding) detected.push(finding);
    if (performance.now() - sliceStartedAt >= SNIFF_ANALYZE_SLICE_MS) {
      if (onProgress) onProgress(detected);
      await yieldSniffAnalysis();
      if (runSeq !== sniffRunSeq) return null;
      sliceStartedAt = performance.now();
    }
  }
  return detected;
}

function analyzeSniffRule(signals, signalIndex, rule) {
  const evidences = [];
  const patterns = new Map();
  let version = '';
  for (const matcher of rule.preparedMatchers || []) {
    if (!sniffMatcherCanRun(signals, signalIndex, matcher)) continue;
    for (const item of matchSniffSignal(signals, matcher, signalIndex)) {
      if (isGenericSniffEvidence(item)) continue;
      const prior = patterns.get(item.patternKey);
      if (prior) {
        prior.version = bestSniffVersion(prior.version, item.version);
        continue;
      }
      patterns.set(item.patternKey, item);
      evidences.push(item);
      version = bestSniffVersion(version, item.version);
      if (evidences.length >= SNIFF_MAX_EVIDENCE_PER_RULE) break;
    }
    if (evidences.length >= SNIFF_MAX_EVIDENCE_PER_RULE) break;
  }
  if (!evidences.length) return null;
  const uniqueEvidence = uniqueSniffEvidence(evidences);
  // Explicit runtime/header versions take precedence over filename guesses.
  version = bestSniffEvidenceVersion(uniqueEvidence) || version || inferSniffVersion(rule, uniqueEvidence);
  const score = scoreSniffFinding(rule, uniqueEvidence);
  const minScore = rule.minScore || 60;
  const minEvidence = rule.minEvidence || 1;
  if (isWeakSniffFinding(rule, uniqueEvidence, score)) return null;
  if (score < minScore || uniqueEvidence.length < minEvidence) return null;
  return {
    id: rule.id,
    name: rule.name,
    category: rule.category || '其他',
    version,
    score,
    evidences: uniqueEvidence.slice(0, 10),
    infers: rule.infers || [],
    excludes: rule.excludes || [],
    requires: rule.requires || [],
    requiresCategory: rule.requiresCategory || [],
    categoryIds: rule.categoryIds || []
  };
}

function yieldSniffAnalysis() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function sniffRequiredLiteral(pattern) {
  // Only a mandatory leading literal, with no alternation, may reject a regex.
  // This avoids quadratic unanchored `.+library` failures on long HTML.
  const source = String(pattern || '');
  let depth = 0, inClass = false;
  for (let at = 0; at < source.length; at++) {
    const char = source[at];
    if (char === '\\') { at++; continue; }
    if (char === '[') inClass = true;
    if (char === ']') inClass = false;
    if (inClass) continue;
    if (char === '(') depth++;
    if (char === ')') depth--;
    if (char === '|' && depth === 0) return '';
  }
  const text = source.replace(/^\^/, '').replace(/^\.\*[?]?|^\.\+[?]?/, '');
  let literal = '', i = 0;
  for (; i < text.length; i++) {
    const char = text[i];
    if (char === '\\') {
      if (!/[.\-/_ :@#=,!%&~<>"'`]/.test(text[i + 1] || '')) break;
      literal += text[++i];
    } else if (/[\^$.*+?()[\]{}|]/.test(char)) break;
    else literal += char;
  }
  if (text[i] === '?' || text[i] === '*' || text[i] === '{') literal = literal.slice(0, -1);
  return literal.length >= 3 ? literal.toLowerCase() : '';
}

function getPreparedSniffRules() {
  const rules = window.AEGISSCOPE_SNIFF_RULES || [];
  if (sniffPreparedRuleCache?.rules === rules) return sniffPreparedRuleCache.prepared;
  const prepared = rules.map((rule) => ({
    ...rule,
    preparedMatchers: (rule.matchers || []).map((matcher) => ({
      ...matcher,
      hintLower: String(matcher.hint || matcher.contains || sniffRequiredLiteral(matcher.regex)).toLowerCase(),
      keyLower: String(matcher.key || '').toLowerCase()
    }))
  }));
  sniffPreparedRuleCache = { rules, prepared };
  return prepared;
}

async function getPreparedSniffRulesCooperatively(runSeq) {
  const rules = window.AEGISSCOPE_SNIFF_RULES || [];
  if (sniffPreparedRuleCache?.rules === rules) return sniffPreparedRuleCache.prepared;
  const prepared = [];
  let sliceStartedAt = performance.now();
  for (const rule of rules) {
    if (runSeq !== sniffRunSeq) return null;
    prepared.push({
      ...rule,
      preparedMatchers: (rule.matchers || []).map((matcher) => ({
        ...matcher,
        hintLower: String(matcher.hint || matcher.contains || sniffRequiredLiteral(matcher.regex)).toLowerCase(),
        keyLower: String(matcher.key || '').toLowerCase()
      }))
    });
    if (performance.now() - sliceStartedAt >= SNIFF_ANALYZE_SLICE_MS) {
      await yieldSniffAnalysis();
      if (runSeq !== sniffRunSeq) return null;
      sliceStartedAt = performance.now();
    }
  }
  sniffPreparedRuleCache = { rules, prepared };
  return prepared;
}

function buildSniffSignalIndex(signals) {
  // Index each source once. A partial index must never veto a match in its tail.
  const incompleteHaystacks = new Set();
  const haystack = (items, limit = 1000000) => {
    const joined = sniffArray(items).join('\n');
    const text = joined.slice(0, limit).toLowerCase();
    if (joined.length > limit) incompleteHaystacks.add(text);
    return text;
  };
  return {
    incompleteHaystacks,
    available: new Set(['headers','cookies','meta','globals','htmlAttr','bodyAttr','title','url','text','html',
      'scriptSrc','scripts','css','className','id','vueMarker','vueRuntime','jqueryRuntime','reactRuntime',
      'dom','linkHref','styleHref','resourceUrl','resourceHost','xhrHost','xhrUrl','selector'].filter(source => sniffSourceAvailable(signals, source))),
    values: new Map(),
    selectors: new Set(signals.selectorMatches || []),
    headerKeys: new Set(Object.keys(signals.headers || {}).map((item) => item.toLowerCase())),
    metaKeys: new Set(Object.keys(signals.meta || {}).map((item) => item.toLowerCase())),
    cookieKeys: new Set(Object.keys(signals.cookies || {}).map((item) => item.toLowerCase())),
    globals: new Set(Object.keys(signals.globals || {})),
    htmlAttrs: new Set(Object.keys(signals.htmlAttrs || {}).map((item) => item.toLowerCase())),
    bodyAttrs: new Set(Object.keys(signals.bodyAttrs || {}).map((item) => item.toLowerCase())),
    haystacks: {
      html: haystack(signals.html),
      text: haystack(signals.text, 180000),
      css: haystack(signals.css, 240000),
      title: haystack(signals.title, 8000),
      url: haystack(signals.url, 8000),
      scripts: haystack(signals.scripts, 360000),
      scriptSrc: haystack(signals.scriptSrc, 360000),
      resourceUrl: haystack(signals.resourceUrls, 360000),
      resourceHost: haystack(signals.resourceHosts, 120000),
      xhrHost: haystack(signals.xhrHosts, 120000),
      xhrUrl: haystack(signals.xhrUrls, 360000),
      linkHref: haystack(signals.linkHrefs, 240000),
      styleHref: haystack(signals.styleHrefs, 180000),
      className: haystack(signals.classNames, 160000),
      id: haystack(signals.ids, 80000),
      vueMarker: haystack(signals.vueMarkers, 8000),
      vueRuntime: haystack(signals.vueRuntime, 12000),
      jqueryRuntime: haystack(signals.jqueryRuntime, 12000),
      reactRuntime: haystack(signals.reactRuntime, 12000),
      selector: haystack(signals.selectorMatches, 120000)
    }
  };
}

function sniffMatcherCanRun(signals, signalIndex, matcher) {
  if (!signalIndex.available.has(matcher.source || 'html')) return false;
  if (matcher.source === 'headers' && matcher.keyLower && !signalIndex.headerKeys.has(matcher.keyLower)) return false;
  if (matcher.source === 'meta' && matcher.keyLower && !signalIndex.metaKeys.has(matcher.keyLower)) return false;
  if (matcher.source === 'globals' && matcher.key && !signalIndex.globals.has(matcher.key)) return false;
  if (matcher.source === 'htmlAttr' && matcher.keyLower && !signalIndex.htmlAttrs.has(matcher.keyLower)) return false;
  if (matcher.source === 'bodyAttr' && matcher.keyLower && !signalIndex.bodyAttrs.has(matcher.keyLower)) return false;
  if (matcher.source === 'selector' && matcher.selector && !signalIndex.selectors.has(matcher.selector)) return false;
  if (matcher.source === 'cookies' && matcher.keyLower) {
    const hasCookie = /[_*]$/.test(matcher.keyLower)
      ? Array.from(signalIndex.cookieKeys).some((name) => name.startsWith(matcher.keyLower.replace(/\*$/, '')))
      : signalIndex.cookieKeys.has(matcher.keyLower);
    if (!hasCookie) return false;
  }
  if (matcher.hintLower) {
    const text = signalIndex.haystacks[matcher.source];
    if (typeof text === 'string' && text && !signalIndex.incompleteHaystacks.has(text) && !text.includes(matcher.hintLower)) return false;
  }
  return true;
}

function isWeakSniffFinding(rule, evidences, score) {
  if (evidences.every(isGenericSniffEvidence)) return true;
  const sourceTypes = new Set(evidences.map((item) => item.sourceType || ''));
  const hasStrong = evidences.some((item) => SNIFF_STRONG_SOURCES.has(item.sourceType) && (item.score || 0) >= 70);
  const hasMedium = evidences.some((item) => SNIFF_MEDIUM_SOURCES.has(item.sourceType) && (item.score || 0) >= 78);
  if (hasStrong || (hasMedium && score >= 82)) return false;
  if (evidences.length >= 2 && score >= 88) return false;
  const weakOnly = [...sourceTypes].every((source) => ['html', 'text', 'css', 'scripts', 'className', 'id'].includes(source));
  return weakOnly && score < Math.max(rule.minScore || 60, 86);
}

function isGenericSniffEvidence(evidence) {
  const value = String(evidence.value || '').trim().toLowerCase();
  if (evidence.sourceType === 'selector') {
    // A selector list is an OR: a generic branch cannot identify a technology.
    return value.split(',').some((selector) => {
      // Attribute existence and ordinary stylesheet links are generic too.
      const structural = selector.replace(/\[(?:class|id)\]/g, '*')
        .replace(/\[rel\s*=?\s*["']?stylesheet["']?\]/g, '')
        .replace(/\[href\s*[*$]\s*=\s*["']?\.css["']?\]/g, '');
      return /^(?:(?:html|body|head|script|style|link|meta|title|noscript|div|span|main|section|form|input|button|a|p|ul|li|img|iframe|canvas|table|header|footer|\*|:root|[.#](?:app|root|container|content|main))[\s>+~]*)+$/.test(structural.trim());
    });
  }
  return ['html', 'text'].includes(evidence.sourceType)
    && /^<\/?[a-z][a-z0-9]*(?:\s|\/?>)*$/.test(value);
}

function bestSniffEvidenceVersion(evidences) {
  const priority = ['globals', 'vueRuntime', 'jqueryRuntime', 'dom', 'meta', 'headers', 'scriptSrc', 'resourceUrl', 'html', 'scripts', 'text'];
  let best = '';
  for (const sourceType of priority) {
    const versions = evidences
      .filter((item) => item.sourceType === sourceType)
      .map((item) => item.version)
      .filter(Boolean);
    for (const version of versions) best = bestSniffVersion(best, version);
    if (best) return best;
  }
  return '';
}

function scoreSniffFinding(rule, evidences) {
  evidences = Array.from(new Map(evidences.map(item => [item.patternKey || `${item.sourceKey}:${item.value}`, item])).values());
  const uniqueSources = new Set(evidences.map((item) => item.sourceKey || item.source || ''));
  const sorted = [...evidences]
    .map((item) => Math.max(0, Math.min(100, item.score ?? 60)))
    .sort((a, b) => b - a);
  if (!sorted.length) return 0;
  let score = sorted[0];
  for (const extra of sorted.slice(1, 6)) {
    score += Math.max(2, Math.round(extra * 0.28));
  }
  if (uniqueSources.size > 1) score += Math.min(12, (uniqueSources.size - 1) * 4);
  if (rule.strongSourceBonus && evidences.some((item) => rule.strongSourceBonus.includes(item.sourceType))) {
    score += 6;
  }
  return Math.min(100, score);
}

function sniffSourceAvailable(signals, source) {
  if (!source) return Boolean(signals.html);
  if (source === 'headers') return Object.keys(signals.headers || {}).length > 0;
  if (source === 'cookies') return Object.keys(signals.cookies || {}).length > 0;
  if (source === 'meta') return Object.keys(signals.meta || {}).length > 0;
  if (source === 'globals') return Object.keys(signals.globals || {}).length > 0;
  if (source === 'scriptSrc') return Boolean(signals.scriptSrc?.length);
  if (source === 'scripts') return Boolean(signals.scripts?.length);
  if (source === 'css') return Boolean(signals.css);
  if (source === 'className') return Boolean(signals.classNames?.length);
  if (source === 'id') return Boolean(signals.ids?.length);
  if (source === 'vueMarker') return Boolean(signals.vueMarkers?.length);
  if (source === 'vueRuntime') return Boolean(signals.vueRuntime?.length);
  if (source === 'jqueryRuntime') return Boolean(signals.jqueryRuntime?.length);
  if (source === 'reactRuntime') return Boolean(signals.reactRuntime?.length);
  if (source === 'dom') return Boolean(signals.domSignals?.length);
  if (source === 'linkHref') return Boolean(signals.linkHrefs?.length);
  if (source === 'styleHref') return Boolean(signals.styleHrefs?.length);
  if (source === 'resourceUrl') return Boolean(signals.resourceUrls?.length);
  if (source === 'resourceHost') return Boolean(signals.resourceHosts?.length);
  if (source === 'xhrHost') return Boolean(signals.xhrHosts?.length);
  if (source === 'xhrUrl') return Boolean(signals.xhrUrls?.length);
  if (source === 'selector') return Boolean(signals.selectorMatches?.length);
  if (source === 'htmlAttr') return Boolean(Object.keys(signals.htmlAttrs || {}).length);
  if (source === 'bodyAttr') return Boolean(Object.keys(signals.bodyAttrs || {}).length);
  if (source === 'title') return Boolean(signals.title);
  if (source === 'url') return Boolean(signals.url);
  if (source === 'text') return Boolean(signals.text);
  return Boolean(signals.html);
}

function inferSniffVersion(rule, evidences) {
  const aliases = sniffVersionAliases(rule);
  for (const evidence of evidences || []) {
    const text = `${evidence.value || ''} ${evidence.context || ''}`;
    for (const pattern of rule.versionPatterns || []) {
      const version = sniffVersionMatch(text, pattern);
      if (version) return version;
    }
    for (const alias of aliases) {
      for (const pattern of sniffVersionPatternsForAlias(alias)) {
        const version = sniffVersionMatch(text, pattern);
        if (version) return version;
      }
    }
  }
  return '';
}

function sniffVersionAliases(rule) {
  const raw = sniffUnique([rule.id, rule.name, String(rule.name || '').replace(/\.js$/i, ''), String(rule.name || '').replace(/[^A-Za-z0-9]+/g, '')]);
  return sniffUnique(raw.flatMap((item) => {
    const text = String(item || '').toLowerCase();
    return [
      text.replace(/[^a-z0-9._-]+/g, ''),
      text.replace(/[^a-z0-9]+/g, '')
    ];
  })).filter((item) => item.length >= 2);
}

function sniffVersionPatternsForAlias(alias) {
  const safe = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return [
    `${safe}@([0-9]+(?:\\.[0-9A-Za-z_-]+){1,4})`,
    `@${safe}(?:/|%2F)[^\\s?#'"]+@([0-9]+(?:\\.[0-9A-Za-z_-]+){1,4})`,
    `${safe}(?:[._-]|%40)([0-9]+(?:\\.[0-9A-Za-z_-]+){1,4})(?:[._-]|/|%2F|$)`,
    `${safe}(?:/|%2F)([0-9]+(?:\\.[0-9A-Za-z_-]+){1,4})(?:/|%2F|$)`,
    `${safe}\\s*(?:/|:|v(?:ersion)?\\s*)\\s*([0-9]+(?:\\.[0-9A-Za-z_-]+){1,4})`
  ];
}

function sniffVersionMatch(text, pattern) {
  try {
    const match = sniffRegex(pattern).exec(String(text || ''));
    return sniffVersion(Array.from(match || []).slice(1).find(Boolean) || '');
  } catch {
    return '';
  }
}

function bestSniffVersion(current, candidate) {
  const left = sniffVersion(current);
  const right = sniffVersion(candidate);
  if (!right) return left;
  if (!left) return right;
  return sniffVersionWeight(right) > sniffVersionWeight(left) ? right : left;
}

function sniffVersionWeight(value) {
  const text = sniffVersion(value);
  if (!text) return 0;
  let weight = Math.min(40, text.length);
  if (/\d+\.\d+/.test(text)) weight += 20;
  if (/[A-Za-z]/.test(text) && /\d/.test(text)) weight += 4;
  if (/^\d{8,}$/.test(text)) weight -= 30;
  return weight;
}

function getSniffTechnologyCatalog() {
  const rules = window.AEGISSCOPE_SNIFF_RULES || [];
  if (sniffTechnologyCatalogCache?.rules === rules) return sniffTechnologyCatalogCache.value;
  const value = new Map();
  for (const rule of rules) {
    const prior = value.get(rule.name) || {};
    value.set(rule.name, {
      ...prior, name: rule.name, category: rule.category || prior.category,
      categoryIds: rule.categoryIds || prior.categoryIds || [],
      requires: rule.requires || prior.requires || [],
      requiresCategory: rule.requiresCategory || prior.requiresCategory || [],
      excludes: rule.excludes || prior.excludes || [],
      infers: rule.infers || prior.infers || []
    });
  }
  sniffTechnologyCatalogCache = { rules, value };
  return value;
}

function resolveSniffFindings(items) {
  const candidates = new Map(), catalog = getSniffTechnologyCatalog();
  for (const item of items) mergeSniffFinding(candidates, { ...item, ...(catalog.get(item.name) || {}) });
  const blocked = new Set();
  const eligible = (item, known) => {
    const techs = sniffArray(item.requires).filter(Boolean);
    const cats = sniffArray(item.requiresCategory).filter(Boolean);
    if (!techs.length && !cats.length) return true;
    // Alternative prerequisites follow the source schema; an unproven cycle cannot seed itself.
    return techs.some(name => known.has(name)) || cats.some(id =>
      [...known.values()].some(tech => sniffArray(tech.categoryIds).includes(Number(id))));
  };
  const build = () => {
    const known = new Map();
    let changed = true;
    while (changed) {
      changed = false;
      for (const [name, item] of candidates) {
        if (blocked.has(name) || known.get(name)?.direct || !eligible(item, known)) continue;
        known.set(name, { ...item, direct: true, evidences: [...item.evidences] });
        changed = true;
      }
      for (const item of Array.from(known.values())) {
        for (const raw of item.infers || []) {
          const edge = typeof raw === 'string' ? { name: raw, confidence: 100 } : raw;
          const name = edge?.name;
          const score = Math.min(80, item.score, edge?.confidence ?? 100);
          if (!name || name === item.name || blocked.has(name) || score <= 0) continue;
          const existing = known.get(name);
          if (existing && (existing.direct || existing.score >= score)) continue;
          known.set(name, {
            id: sniffSlug(name), name, category: sniffImpliedCategory(name),
            ...(catalog.get(name) || {}), score, version: sniffVersion(edge.version), direct: false,
            evidences: [{ source: '关联推断', sourceType: 'inferred', key: item.name,
              value: `${item.name} => ${name}`, context: `${item.name} => ${name}`, score }]
          });
          changed = true;
        }
      }
    }
    return known;
  };
  let known = build();
  // Rebuild from actual evidence after exclusions so orphaned dependencies/inferences disappear.
  while (true) {
    let changed = false;
    const ordered = [...known.values()].sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
    for (const item of ordered) {
      if (blocked.has(item.name)) continue;
      for (const excluded of item.excludes || []) {
        if (excluded && excluded !== item.name && known.has(excluded) && !blocked.has(excluded)) {
          blocked.add(excluded); changed = true;
        }
      }
    }
    if (!changed) break;
    known = build();
  }
  return [...known.values()].sort((a, b) =>
    sniffCategoryRank(a.category) - sniffCategoryRank(b.category) ||
    b.score - a.score || a.name.localeCompare(b.name)
  );
}

function mergeSniffFinding(byName, item) {
  const existing = byName.get(item.name);
  if (!existing) {
    byName.set(item.name, { ...item, evidences: [...(item.evidences || [])] });
    return;
  }
  existing.score = Math.max(existing.score, item.score);
  existing.version = bestSniffEvidenceVersion([...(existing.evidences || []), ...(item.evidences || [])]) || bestSniffVersion(existing.version, item.version);
  existing.evidences = uniqueSniffEvidence([...(existing.evidences || []), ...(item.evidences || [])]).slice(0, 8);
  existing.infers = sniffUnique([...(existing.infers || []), ...(item.infers || [])]);
  existing.excludes = sniffUnique([...(existing.excludes || []), ...(item.excludes || [])]);
  existing.requires = sniffUnique([...(existing.requires || []), ...(item.requires || [])]);
}

function matchSniffSignal(signals, matcher, signalIndex) {
  const valueKey = JSON.stringify([matcher.source, matcher.key, matcher.selector, matcher.property, matcher.attribute, !!matcher.text, !!matcher.scalar]);
  let values = signalIndex?.values.get(valueKey);
  if (!values) {
    values = valuesForSniffSource(signals, matcher);
    if (signalIndex) signalIndex.values.set(valueKey, values);
  }
  const out = [];
  if (matcher.confidence === 0) return out;
  const patternKey = JSON.stringify([matcher.source, matcher.key, matcher.selector, matcher.property, matcher.attribute,
    matcher.text, matcher.equals, matcher.regex, matcher.contains, matcher.all, matcher.exists]);
  for (const item of values) {
    const value = String(item.value ?? '');
    let matched = false;
    let matchText = '';
    let version = '';
    if (matcher.exists) {
      matched = item.value !== undefined && item.value !== null;
      matchText = value || '(存在，值为空)';
    } else if (matcher.equals != null) {
      matched = value === String(matcher.equals);
      matchText = value;
    } else if (matcher.all) {
      matched = sniffArray(matcher.all).every((part) => value.toLowerCase().includes(String(part).toLowerCase()));
      matchText = sniffArray(matcher.all).join(' + ');
    } else if (matcher.contains) {
      matched = value.toLowerCase().includes(String(matcher.contains).toLowerCase());
      matchText = matcher.contains;
    } else if (typeof matcher.regex === 'string') {
      if (matcher.hint && !value.toLowerCase().includes(String(matcher.hint).toLowerCase())) continue;
      const match = sniffRegex(matcher.regex).exec(value);
      matched = !!match;
      matchText = match?.[0] || '';
      if (matched) {
        if (matcher.versionTemplate) {
          version = resolveSniffVersionTemplate(matcher.versionTemplate, match);
        } else if (Array.isArray(matcher.version)) {
          version = matcher.version.map((index) => match?.[index]).find(Boolean) || '';
        } else if (matcher.version && match?.[matcher.version]) {
          version = match[matcher.version];
        }
        if (!version && matcher.versionRegex) {
          const versionMatch = sniffRegex(matcher.versionRegex).exec(value);
          version = Array.from(versionMatch || []).slice(1).find(Boolean) || '';
        }
        version = formatSniffMatcherVersion(version, matcher.versionFormat);
      }
    }
    if (matched) {
      out.push({
        source: item.source,
        sourceType: item.sourceType || matcher.source || '',
        sourceKey: `${item.source || ''}:${item.key || matcher.key || matcher.source || ''}`,
        patternKey,
        key: item.key || matcher.key || '',
        value: sniffCompact(matchText || value),
        context: sniffCompact(value),
        score: Math.min(matcher.score ?? 60, matcher.confidence ?? 100),
        version: sniffVersion(version)
      });
    }
  }
  return out;
}

function resolveSniffVersionTemplate(template, match) {
  // Templates are data, never evaluated as JavaScript.
  let value = String(template || '');
  value = value.replace(/\\(\d+)\?([^:]*):(.*)$/, (_, index, yes, no) => match?.[Number(index)] ? yes : no);
  return value.replace(/\\(\d+)/g, (_, index) => String(match?.[Number(index)] || '')).trim();
}

function formatSniffMatcherVersion(version, format) {
  const text = String(version || '').trim();
  if (format === 'jqueryCompact' && /^\d{2,4}$/.test(text)) {
    if (text.length === 2) return `${text[0]}.${text[1]}`;
    if (text.length === 3) return `${text[0]}.${text[1]}.${text[2]}`;
    return `${text[0]}.${text.slice(1, -1)}.${text.slice(-1)}`;
  }
  return text;
}

function valuesForSniffSource(signals, matcher) {
  if (matcher.source === 'headers') {
    if (!matcher.key) {
      return Object.entries(signals.headers || {})
        .flatMap(([key, values]) => sniffArray(values).map((value) => ({ source: 'Header', key, value })));
    }
    return sniffArray(signals.headers?.[String(matcher.key || '').toLowerCase()])
      .map((value) => ({ source: '响应头', key: matcher.key, value }));
  }
  if (matcher.source === 'cookies') {
    const key = String(matcher.key || '');
    const entries = Object.entries(signals.cookies || {});
    if (/[_*]$/.test(key)) {
      return entries
        .filter(([name]) => name.toLowerCase().startsWith(key.toLowerCase().replace(/\*$/, '')))
        .map(([name, value]) => ({ source: 'Cookie', key: name, value }));
    }
    const found = entries.find(([name]) => name.toLowerCase() === key.toLowerCase());
    return found ? [{ source: 'Cookie', key: found[0], value: found[1] }] : [];
  }
  if (matcher.source === 'meta') {
    return sniffArray(signals.meta?.[String(matcher.key || '').toLowerCase()])
      .map((value) => ({ source: 'Meta', key: matcher.key, value }));
  }
  if (matcher.source === 'globals') {
    const value = matcher.scalar && Object.prototype.hasOwnProperty.call(signals.globalScalars || {}, matcher.key)
      ? signals.globalScalars[matcher.key] : signals.globals?.[matcher.key];
    return typeof value === 'undefined' ? [] : [{ source: '运行时', key: matcher.key, value }];
  }
  if (matcher.source === 'scriptSrc') {
    return (signals.scriptSrc || []).map((value) => ({ source: '脚本', value }));
  }
  if (matcher.source === 'scripts') {
    return (signals.scripts || []).map((value, index) => ({ source: '内联脚本', key: `script#${index + 1}`, value }));
  }
  if (matcher.source === 'css') {
    return [{ source: 'CSS', value: signals.css || '' }];
  }
  if (matcher.source === 'className') {
    return (signals.classNames || []).map((value) => ({ source: 'Class', value }));
  }
  if (matcher.source === 'id') {
    return (signals.ids || []).map((value) => ({ source: 'ID', value }));
  }
  if (matcher.source === 'vueMarker') {
    return (signals.vueMarkers || []).map((value) => ({ source: 'Vue Marker', value }));
  }
  if (matcher.source === 'vueRuntime') {
    return (signals.vueRuntime || []).map((value) => ({ source: 'Vue Runtime', value }));
  }
  if (matcher.source === 'jqueryRuntime') {
    return (signals.jqueryRuntime || []).map((value) => ({ source: 'jQuery Runtime', value }));
  }
  if (matcher.source === 'reactRuntime') {
    return (signals.reactRuntime || []).map((value) => ({ source: 'React Runtime', value }));
  }
  if (matcher.source === 'dom') {
    return (signals.domSignals || []).filter(item => item.selector === matcher.selector &&
      item.property === (matcher.property || '') && item.attribute === (matcher.attribute || '') && item.text === !!matcher.text)
      .map(item => ({ source: 'DOM 条件', key: `${item.selector}:${item.property || item.attribute || 'text'}`, value: item.value }));
  }
  if (matcher.source === 'linkHref') {
    return (signals.linkHrefs || []).map((value) => ({ source: 'Link', value }));
  }
  if (matcher.source === 'styleHref') {
    return (signals.styleHrefs || []).map((value) => ({ source: '样式表', value }));
  }
  if (matcher.source === 'resourceUrl') {
    return (signals.resourceUrls || []).map((value) => ({ source: '资源', value }));
  }
  if (matcher.source === 'resourceHost') {
    return (signals.resourceHosts || []).map((value) => ({ source: '资源域名', value }));
  }
  if (matcher.source === 'xhrHost') {
    return (signals.xhrHosts || []).map((value) => ({ source: '接口域名', value }));
  }
  if (matcher.source === 'xhrUrl') {
    return (signals.xhrUrls || []).map((value) => ({ source: '接口路径', value }));
  }
  if (matcher.source === 'selector') {
    return (signals.selectorMatches || []).map((value) => ({ source: 'DOM选择器', value }));
  }
  if (matcher.source === 'htmlAttr') {
    const value = signals.htmlAttrs?.[String(matcher.key || '').toLowerCase()];
    return typeof value === 'undefined' ? [] : [{ source: 'HTML属性', key: matcher.key, value: value || String(matcher.key || '') }];
  }
  if (matcher.source === 'bodyAttr') {
    const value = signals.bodyAttrs?.[String(matcher.key || '').toLowerCase()];
    return typeof value === 'undefined' ? [] : [{ source: 'Body属性', key: matcher.key, value: value || String(matcher.key || '') }];
  }
  if (matcher.source === 'title') return [{ source: '标题', value: signals.title || '' }];
  if (matcher.source === 'url') return [{ source: 'URL', value: signals.url || '' }];
  if (matcher.source === 'text') return [{ source: '正文', value: signals.text || '' }];
  return [{ source: 'HTML', value: signals.html || '' }];
}


function sniffCategoryRank(category) {
  const order = ['内容管理系统（CMS）', '电子商务', '论坛', '网站构建器', '托管平台', 'Web App', '数据库', 'JavaScript 框架', 'JavaScript 库', '用户界面（UI）框架', 'CSS 框架', '字体脚本', '编程语言', 'Web 服务器', 'CDN', '支付', '分析工具', '标签管理器', '监控', '构建工具', '文档', 'API', '安全'];
  const index = order.indexOf(category);
  return index === -1 ? order.length : index;
}

function sniffImpliedCategory(name) {
  if (name === 'PHP' || name === 'Java' || name === 'ASP.NET') return '编程语言';
  if (name === 'React' || name === 'Vue.js') return 'JavaScript 框架';
  return '其他';
}

function uniqueSniffEvidence(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = `${item.source}|${item.key}|${item.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}


function sniffRegex(pattern) {
  const key = String(pattern || '');
  if (SNIFF_REGEX_CACHE.has(key)) return SNIFF_REGEX_CACHE.get(key);
  let regex;
  try { regex = new RegExp(key, 'i'); } catch { regex = /$a/; }
  if (SNIFF_REGEX_CACHE.size >= SNIFF_REGEX_CACHE_LIMIT) SNIFF_REGEX_CACHE.clear();
  SNIFF_REGEX_CACHE.set(key, regex);
  return regex;
}

function sniffVersion(value) {
  const text = String(value || '').trim().replace(/\.(?:min|slim|production|development)(?:\.(?:min|js|css))*$/i, '').replace(/\.(?:js|css)$/i, '');
  if (!/^[A-Za-z0-9._-]{1,24}$/.test(text)) return '';
  if (/^\d{10,}$/.test(text)) return '';
  return text;
}

function sniffCompact(value) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  return text.length > 180 ? `${text.slice(0, 177)}...` : text;
}

function sniffUnique(items) {
  return Array.from(new Set((items || []).filter((item) => item !== undefined && item !== null && item !== '')));
}

function sniffArray(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

function sniffSlug(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'item';
}

function sniffHost(value) {
  try { return new URL(value).hostname.toLowerCase(); } catch { return ''; }
}

