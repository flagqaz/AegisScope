// 安全分析引擎
// 执行规则正则 + validate() 主动校验 + 上下文要求/否决，输出归一化 finding。
//
// 输出 finding 默认带置信度：confirmed / likely / suspected
// suspected 通常是仅模式匹配未达确认条件，UI 默认隐藏。

const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CONFIDENCE_WEIGHT = { confirmed: 3, likely: 2, suspected: 1 };

function getLineCol(source, index) {
  let line = 1, col = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) { line++; col = 1; } else { col++; }
  }
  return { line, col };
}

function getContext(source, start, end, pad = 80) {
  const from = Math.max(0, start - pad);
  const to = Math.min(source.length, end + pad);
  return {
    before: source.slice(from, start),
    match: source.slice(start, end),
    after: source.slice(end, to)
  };
}

function dedupeKey(rule, value, line) {
  return `${rule.id}::${String(value).slice(0, 80)}::${line}`;
}

function bumpMap(map, value, extra = {}) {
  const key = String(value || '').trim();
  if (!key) return;
  const cur = map.get(key) || { value: key, count: 0, ...extra };
  cur.count++;
  map.set(key, cur);
}

function isLikelyEndpoint(value) {
  const v = String(value || '').trim();
  if (v.length < 2 || v.length > 260) return false;
  if (/\.(?:png|jpe?g|gif|webp|svg|css|woff2?|ttf|eot|ico|mp4|webm|mp3|wav)(?:[?#]|$)/i.test(v)) return false;
  if (/^(?:javascript:|mailto:|tel:|data:|blob:)/i.test(v)) return false;
  if (/^(?:https?:)?\/\//i.test(v)) return true;
  if (/^\/(?:api|admin|auth|user|v\d+|graphql|oauth|pay|order|upload|download|internal|openapi|gateway|captcha|login|logout|system|config)\b/i.test(v)) return true;
  if (/^(?:\.{1,2}\/)?(?:api|admin|auth|user|v\d+|graphql|oauth|pay|order|upload|download|internal|openapi|gateway|captcha|login|logout|system|config)\b/i.test(v)) return true;
  return false;
}

function isLikelyRoute(value) {
  const v = String(value || '').trim();
  if (!v || v.length > 140) return false;
  if (/^(?:https?:)?\/\//i.test(v)) return false;
  if (!/^\/[A-Za-z0-9_:@*?/-]*$/.test(v)) return false;
  if (/\.(?:js|css|png|jpe?g|gif|webp|svg|ico|map|woff2?)$/i.test(v)) return false;
  return true;
}

function collectCodeAssetMeta(source) {
  const apiEndpoints = new Map();
  const routes = new Map();
  const frameworks = new Set();
  const moduleHints = new Map();

  const addApi = (value, name) => {
    if (isLikelyEndpoint(value)) bumpMap(apiEndpoints, value, { name });
  };
  const addRoute = (value, name) => {
    if (isLikelyRoute(value)) bumpMap(routes, value, {
      name,
      sensitive: /\/(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|secret|token|debug|internal)\b/i.test(value)
    });
  };

  const endpointPatterns = [
    { name: 'fetch/open', regex: /\b(?:fetch|open|new\s+Request)\s*\(\s*["'`]([^"'`]{2,260})["'`]/g },
    { name: 'axios/request method', regex: /\b(?:axios|request|http|service|client|api)\s*\.\s*(?:get|post|put|patch|delete|head|options|request)\s*\(\s*["'`]([^"'`]{2,260})["'`]/gi },
    { name: 'request config url', regex: /\b(?:axios|request|http|service|client|api|ajax)\s*\(\s*\{[\s\S]{0,700}?\burl\s*:\s*["'`]([^"'`]{2,260})["'`]/gi },
    { name: 'miniapp request', regex: /\b(?:wx|uni|my|tt|swan)\.request\s*\(\s*\{[\s\S]{0,700}?\burl\s*:\s*["'`]([^"'`]{2,260})["'`]/gi },
    { name: 'jquery ajax', regex: /\$\.(?:ajax|get|post|getJSON)\s*\(\s*(?:\{[\s\S]{0,700}?\burl\s*:\s*)?["'`]([^"'`]{2,260})["'`]/gi },
    { name: 'baseURL', regex: /\b(?:baseURL|apiBase|baseApi|uploadUrl|downloadUrl|gatewayUrl)\s*[:=]\s*["'`]([^"'`]{2,260})["'`]/gi },
    { name: 'config endpoint', regex: /\b(?:url|path|endpoint|api|action)\s*:\s*["'`]([^"'`]{2,260})["'`]/gi }
  ];
  for (const pattern of endpointPatterns) {
    pattern.regex.lastIndex = 0;
    let m, count = 0;
    while ((m = pattern.regex.exec(source)) !== null) {
      addApi(m[1], pattern.name);
      if (++count >= 300) break;
    }
  }

  const routePatterns = [
    { name: 'vue/react route path', regex: /\bpath\s*:\s*["'`]([^"'`]{1,140})["'`]/g },
    { name: 'router addRoute', regex: /\b(?:addRoute|push|replace)\s*\(\s*["'`]([^"'`]{1,140})["'`]/g },
    { name: 'route redirect', regex: /\bredirect\s*:\s*["'`]([^"'`]{1,140})["'`]/g }
  ];
  for (const pattern of routePatterns) {
    pattern.regex.lastIndex = 0;
    let m, count = 0;
    while ((m = pattern.regex.exec(source)) !== null) {
      addRoute(m[1], pattern.name);
      if (++count >= 200) break;
    }
  }

  const frameworkPatterns = [
    ['Vue', /\b(?:createApp|new\s+Vue|VueRouter|vue-router|__VUE_DEVTOOLS_GLOBAL_HOOK__)\b/],
    ['Vuex/Pinia', /\b(?:createPinia|defineStore|new\s+Vuex\.Store|mapState|mapActions)\b/],
    ['React', /\b(?:React\.createElement|createRoot|useEffect|jsx-runtime|__REACT_DEVTOOLS_GLOBAL_HOOK__)\b/],
    ['Angular', /\b(?:ngVersion|ɵɵdefineComponent|platformBrowserDynamic|zone\.js)\b/],
    ['Axios', /\baxios(?:\.create|\s*\(|\.(?:get|post|request))\b/],
    ['jQuery', /\bjQuery\b|\$\.(?:ajax|get|post)\s*\(/],
    ['Element UI/Plus', /\b(?:el-button|ElMessage|ElementPlus|element-ui)\b/],
    ['Ant Design', /\b(?:antd|ant-design|ant-btn|Antd)\b/]
  ];
  for (const [name, regex] of frameworkPatterns) {
    regex.lastIndex = 0;
    if (regex.test(source)) frameworks.add(name);
  }

  const modulePatterns = [
    /webpack:\/\/\/?([^"'`\s<>?]{2,180})/g,
    /["'`]((?:\.{1,2}\/)?src\/(?:api|services?|views?|pages?|router|store|config)\/[^"'`\s<>]{1,180})["'`]/g,
    /["'`]((?:@\/)?(?:api|services?|views?|pages?|router|store|config)\/[^"'`\s<>]{1,180})["'`]/g
  ];
  for (const re of modulePatterns) {
    re.lastIndex = 0;
    let m, count = 0;
    while ((m = re.exec(source)) !== null) {
      bumpMap(moduleHints, m[1], { name: 'module path' });
      if (++count >= 160) break;
    }
  }

  return {
    apiEndpoints: Array.from(apiEndpoints.values()).sort((a, b) => b.count - a.count).slice(0, 300),
    routes: Array.from(routes.values()).sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || b.count - a.count).slice(0, 200),
    frameworks: Array.from(frameworks),
    moduleHints: Array.from(moduleHints.values()).sort((a, b) => b.count - a.count).slice(0, 200)
  };
}

function checkContextRequire(rule, source, offset, len) {
  if (!rule.contextRequire) return true;
  const w = rule.contextWindow || 240;
  const seg = source.slice(Math.max(0, offset - w), Math.min(source.length, offset + len + w));
  return rule.contextRequire.test(seg);
}
function checkContextDeny(rule, source, offset, len) {
  if (!rule.contextDeny) return false;
  const w = rule.contextWindow || 240;
  const seg = source.slice(Math.max(0, offset - w), Math.min(source.length, offset + len + w));
  return rule.contextDeny.test(seg);
}

function analyzeSource(source, meta = {}) {
  if (!source || typeof source !== 'string') return emptyResult();
  const R = self.JS_EXTRACTOR_RULES;
  if (!R) throw new Error('rules.js 未加载');

  const findings = [];
  const seen = new Set();
  const stats = {
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byConfidence: { confirmed: 0, likely: 0, suspected: 0 },
    byCategory: {}
  };

  for (const rule of R.RULES) {
    const re = rule.regex;
    if (!re) continue;
    re.lastIndex = 0;

    let m, perRule = 0;
    while ((m = re.exec(source)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++;
      const matched = m[0];
      const captured = m[1] !== undefined ? m[1] : matched;
      const start = m.index;
      const end = start + matched.length;

      // 上下文白/黑名单
      if (!checkContextRequire(rule, source, start, matched.length)) continue;
      if (checkContextDeny(rule, source, start, matched.length)) continue;

      // validate() 主动校验
      let severity = rule.severity || 'info';
      let confidence = rule.confidence || 'suspected';
      let evidence = '';
      if (typeof rule.validate === 'function') {
        let v;
        try {
          v = rule.validate({ match: matched, captured, source, offset: start });
        } catch { v = { drop: true }; }
        if (v && v.drop) continue;
        if (v) {
          if (v.severity) severity = v.severity;
          if (v.confidence) confidence = v.confidence;
          if (v.evidence) evidence = v.evidence;
        }
      }

      const { line, col } = getLineCol(source, start);
      const key = dedupeKey(rule, captured, line);
      if (seen.has(key)) continue;
      seen.add(key);

      const ctx = getContext(source, start, end);

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity,
        confidence,
        evidence,
        line, col, offset: start,
        match: matched.length > 240 ? matched.slice(0, 240) + '…' : matched,
        captured: String(captured).length > 240 ? String(captured).slice(0, 240) + '…' : captured,
        context: ctx,
        description: rule.description || '',
        exploit: rule.exploit || '',
        recommendation: rule.recommendation || '',
        meta
      });

      stats.bySeverity[severity] = (stats.bySeverity[severity] || 0) + 1;
      stats.byConfidence[confidence] = (stats.byConfidence[confidence] || 0) + 1;
      stats.byCategory[rule.category] = (stats.byCategory[rule.category] || 0) + 1;
      if (++perRule >= 200) break;
    }
  }

  // 元信息扫描（不进 findings）
  const cryptoLibs = new Set();
  const cryptoAlgos = new Set();
  const decryptions = new Map();
  const bundlers = new Set();
  const frameworks = new Set();
  const obfuscation = [];
  const apiEndpoints = new Map();
  const routes = new Map();
  const moduleHints = new Map();
  const exposures = [];
  for (const lib of R.META_RULES.cryptoLibs) {
    lib.regex.lastIndex = 0;
    if (lib.regex.test(source)) cryptoLibs.add(lib.name);
  }
  for (const al of R.META_RULES.cryptoAlgos) {
    al.regex.lastIndex = 0;
    if (al.regex.test(source)) {
      cryptoAlgos.add(al.name);
      if (al.decrypt) {
        decryptions.set(al.name, {
          name: al.name,
          family: al.family || '',
          decrypt: al.decrypt
        });
      }
    }
  }
  for (const bundler of R.META_RULES.bundlers || []) {
    bundler.regex.lastIndex = 0;
    if (bundler.regex.test(source)) bundlers.add(bundler.name);
  }
  for (const ob of R.META_RULES.obfuscators || []) {
    const re = new RegExp(ob.regex.source, (ob.regex.flags || '') + (ob.regex.flags?.includes('g') ? '' : 'g'));
    let count = 0, m3;
    while ((m3 = re.exec(source)) !== null) {
      if (m3.index === re.lastIndex) re.lastIndex++;
      count++;
      if (count >= 50) break;
    }
    if (count > 0) obfuscation.push({ name: ob.name, severity: ob.severity, count });
  }
  for (const api of R.META_RULES.apiPatterns || []) {
    const re = new RegExp(api.regex.source, (api.regex.flags || '') + (api.regex.flags?.includes('g') ? '' : 'g'));
    let count = 0, m4;
    while ((m4 = re.exec(source)) !== null) {
      if (m4.index === re.lastIndex) re.lastIndex++;
      const raw = String(m4[1] || '').trim();
      if (!raw || raw.length < 2) continue;
      if (/\.(?:png|jpe?g|gif|webp|svg|css|woff2?|ttf|map)(?:[?#]|$)/i.test(raw)) continue;
      if (!/[/?]/.test(raw)) continue;
      const key = raw.slice(0, 240);
      const cur = apiEndpoints.get(key) || { value: key, name: api.name, count: 0 };
      cur.count++;
      apiEndpoints.set(key, cur);
      if (++count >= 200) break;
    }
  }
  const richMeta = collectCodeAssetMeta(source);
  for (const api of richMeta.apiEndpoints) {
    const cur = apiEndpoints.get(api.value) || { ...api, count: 0 };
    cur.count += api.count;
    apiEndpoints.set(api.value, cur);
  }
  for (const route of richMeta.routes) {
    const cur = routes.get(route.value) || { ...route, count: 0 };
    cur.count += route.count;
    cur.sensitive = cur.sensitive || route.sensitive;
    routes.set(route.value, cur);
  }
  richMeta.frameworks.forEach((x) => frameworks.add(x));
  for (const mod of richMeta.moduleHints) {
    const cur = moduleHints.get(mod.value) || { ...mod, count: 0 };
    cur.count += mod.count;
    moduleHints.set(mod.value, cur);
  }
  for (const ex of R.META_RULES.exposures) {
    const re = new RegExp(ex.regex.source, (ex.regex.flags || '') + (ex.regex.flags?.includes('g') ? '' : 'g'));
    let count = 0, m2;
    while ((m2 = re.exec(source)) !== null) {
      if (m2.index === re.lastIndex) re.lastIndex++;
      count++;
      if (count >= 50) break;
    }
    if (count > 0) exposures.push({ name: ex.name, severity: ex.severity, count });
  }

  // 排序：严重性优先；同严重性再按置信度，保证高危结果始终在前。
  findings.sort((a, b) => {
    const ds = SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
    if (ds !== 0) return ds;
    const dc = CONFIDENCE_WEIGHT[b.confidence] - CONFIDENCE_WEIGHT[a.confidence];
    if (dc !== 0) return dc;
    return a.line - b.line;
  });

  return {
    findings,
    stats: {
      ...stats,
      cryptoLibs: Array.from(cryptoLibs),
      cryptoAlgos: Array.from(cryptoAlgos),
      decryptions: Array.from(decryptions.values()),
      bundlers: Array.from(bundlers),
      frameworks: Array.from(frameworks),
      obfuscation,
      apiEndpoints: Array.from(apiEndpoints.values()).sort((a, b) => b.count - a.count).slice(0, 200),
      routes: Array.from(routes.values()).sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || b.count - a.count).slice(0, 200),
      moduleHints: Array.from(moduleHints.values()).sort((a, b) => b.count - a.count).slice(0, 200),
      exposures
    }
  };
}

function emptyResult() {
  return {
    findings: [],
    stats: {
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byConfidence: { confirmed: 0, likely: 0, suspected: 0 },
      byCategory: {},
      cryptoLibs: [], cryptoAlgos: [], decryptions: [], bundlers: [], frameworks: [],
      obfuscation: [], apiEndpoints: [], routes: [], moduleHints: [], exposures: []
    }
  };
}

function aggregateReport(perFile) {
  const total = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const conf = { confirmed: 0, likely: 0, suspected: 0 };
  const libs = new Set(), algos = new Set();
  const decryptMap = new Map();
  const bundlers = new Set();
  const frameworks = new Set();
  const obMap = new Map();
  const apiMap = new Map();
  const routeMap = new Map();
  const moduleMap = new Map();
  const expoMap = new Map();
  let actionableScore = 0;     // 仅 confirmed+likely 计入风险评分
  let findings = 0;

  for (const f of perFile) {
    findings += f.findings.length;
    for (const fi of f.findings) {
      total[fi.severity] = (total[fi.severity] || 0) + 1;
      conf[fi.confidence] = (conf[fi.confidence] || 0) + 1;
      if (fi.confidence !== 'suspected') {
        actionableScore += (SEVERITY_WEIGHT[fi.severity] ?? 0) * 10 *
          (fi.confidence === 'confirmed' ? 1.0 : 0.6);
      }
    }
    (f.stats.cryptoLibs || []).forEach((x) => libs.add(x));
    (f.stats.cryptoAlgos || []).forEach((x) => algos.add(x));
    (f.stats.decryptions || []).forEach((d) => {
      const cur = decryptMap.get(d.name) || { ...d, files: 0 };
      cur.files += 1;
      decryptMap.set(d.name, cur);
    });
    (f.stats.bundlers || []).forEach((x) => bundlers.add(x));
    (f.stats.frameworks || []).forEach((x) => frameworks.add(x));
    (f.stats.obfuscation || []).forEach((o) => {
      const cur = obMap.get(o.name) || { name: o.name, severity: o.severity, count: 0, files: 0 };
      cur.count += o.count; cur.files += 1;
      obMap.set(o.name, cur);
    });
    (f.stats.apiEndpoints || []).forEach((api) => {
      const cur = apiMap.get(api.value) || { ...api, count: 0, files: 0 };
      cur.count += api.count; cur.files += 1;
      apiMap.set(api.value, cur);
    });
    (f.stats.routes || []).forEach((route) => {
      const cur = routeMap.get(route.value) || { ...route, count: 0, files: 0 };
      cur.count += route.count; cur.files += 1;
      cur.sensitive = cur.sensitive || route.sensitive;
      routeMap.set(route.value, cur);
    });
    (f.stats.moduleHints || []).forEach((mod) => {
      const cur = moduleMap.get(mod.value) || { ...mod, count: 0, files: 0 };
      cur.count += mod.count; cur.files += 1;
      moduleMap.set(mod.value, cur);
    });
    (f.stats.exposures || []).forEach((e) => {
      const cur = expoMap.get(e.name) || { name: e.name, severity: e.severity, count: 0, files: 0 };
      cur.count += e.count; cur.files += 1;
      expoMap.set(e.name, cur);
    });
  }

  // 风险等级仅看 confirmed/likely 的最高严重度
  const actionableBySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of perFile) {
    for (const fi of f.findings) {
      if (fi.confidence === 'suspected') continue;
      actionableBySev[fi.severity]++;
    }
  }
  let level = '安全';
  if (actionableBySev.critical > 0) level = '严重';
  else if (actionableBySev.high > 0) level = '高危';
  else if (actionableBySev.medium > 0) level = '中危';
  else if (actionableBySev.low > 0) level = '低危';

  return {
    files: perFile.length,
    findings,
    actionable: conf.confirmed + conf.likely,
    score: Math.round(actionableScore),
    level,
    bySeverity: total,
    byConfidence: conf,
    actionableBySeverity: actionableBySev,
    cryptoLibs: Array.from(libs),
    cryptoAlgos: Array.from(algos),
    decryptions: Array.from(decryptMap.values()),
    bundlers: Array.from(bundlers),
    frameworks: Array.from(frameworks),
    obfuscation: Array.from(obMap.values()).sort((a, b) => b.count - a.count),
    apiEndpoints: Array.from(apiMap.values()).sort((a, b) => b.count - a.count).slice(0, 300),
    routes: Array.from(routeMap.values()).sort((a, b) => Number(b.sensitive) - Number(a.sensitive) || b.count - a.count).slice(0, 300),
    moduleHints: Array.from(moduleMap.values()).sort((a, b) => b.count - a.count).slice(0, 300),
    exposures: Array.from(expoMap.values())
  };
}

if (typeof self !== 'undefined') {
  self.JS_EXTRACTOR_ANALYZER = {
    analyzeSource, aggregateReport,
    SEVERITY_WEIGHT, CONFIDENCE_WEIGHT
  };
}
