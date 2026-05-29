// resource-profile:flagqaz/AegisScope:0854f9b0432ef572:vue-tools
const params = new URLSearchParams(location.search);
const targetTabId = Number(params.get('tabId'));

const els = {
  origin: document.getElementById('origin'),
  analyze: document.getElementById('analyze'),
  restore: document.getElementById('restore'),
  exportJson: document.getElementById('exportJson'),
  enableEarly: document.getElementById('enableEarly'),
  refreshTarget: document.getElementById('refreshTarget'),
  vueStatus: document.getElementById('vueStatus'),
  vueMeta: document.getElementById('vueMeta'),
  routerStatus: document.getElementById('routerStatus'),
  routerMeta: document.getElementById('routerMeta'),
  routeCount: document.getElementById('routeCount'),
  sensitiveCount: document.getElementById('sensitiveCount'),
  guardCount: document.getElementById('guardCount'),
  guardMeta: document.getElementById('guardMeta'),
  routeSearch: document.getElementById('routeSearch'),
  routes: document.getElementById('routes'),
  details: document.getElementById('details'),
  status: document.getElementById('status'),
  confirmDialog: document.getElementById('confirmDialog'),
  confirmTitle: document.getElementById('confirmTitle'),
  confirmText: document.getElementById('confirmText'),
  confirmCancel: document.getElementById('confirmCancel'),
  confirmOk: document.getElementById('confirmOk')
};

let latest = null;
let currentTab = null;
let earlyTarget = null;
let earlyEnabled = false;

init().catch((err) => setStatus(`初始化失败: ${err.message}`, true));

async function init() {
  currentTab = await chrome.tabs.get(targetTabId);
  earlyTarget = getEarlyTarget(currentTab?.url || '');
  els.origin.textContent = currentTab?.url || '';
  els.analyze.addEventListener('click', analyze);
  els.restore.addEventListener('click', restoreVueRuntime);
  els.exportJson.addEventListener('click', exportJson);
  els.enableEarly?.addEventListener('click', enableEarlyMode);
  els.refreshTarget?.addEventListener('click', refreshTargetPage);
  els.routeSearch.addEventListener('input', renderRoutes);
  await refreshEarlyMode();
  await analyze();
}

function updateAuthorizedButtons() {
  if (els.enableEarly) {
    els.enableEarly.disabled = !earlyTarget;
    els.enableEarly.textContent = earlyEnabled ? '关闭增强模式' : '开启增强模式';
    els.enableEarly.classList.toggle('danger', earlyEnabled);
    els.enableEarly.classList.toggle('primary', !earlyEnabled);
  }
}

async function refreshEarlyMode() {
  if (!earlyTarget) {
    earlyEnabled = false;
    updateAuthorizedButtons();
    return;
  }
  try {
    const scripts = await chrome.scripting.getRegisteredContentScripts({ ids: [earlyTarget.id] });
    earlyEnabled = scripts.some((item) => item.id === earlyTarget.id);
  } catch {
    earlyEnabled = false;
  }
  updateAuthorizedButtons();
}

async function enableEarlyMode() {
  if (earlyEnabled) {
    await disableEarlyMode();
    return;
  }
  if (!earlyTarget) {
    setStatus('当前页面不支持开启增强模式。', true);
    return;
  }
  confirmAction(
    '开启授权增强模式',
    `请仅在已授权测试目标中使用。该操作会增强当前页面，并为 ${earlyTarget.match} 注册页面早期增强脚本。当前页面不会被强制刷新，可避免触发网站初始化登录态校验。`,
    async () => {
      await mutateVueRuntime('preflight');
      await registerEarlyContentScript();
      await injectEarlyScriptNow();
      await refreshEarlyMode();
      await new Promise((resolve) => setTimeout(resolve, 180));
      await analyze();
      setStatus('增强模式已开启，可以重新尝试路由跳转。');
    }
  );
}

async function disableEarlyMode() {
  if (!earlyTarget) return;
  await unregisterEarlyContentScript();
  const restored = await restoreEarlyRuntime();
  await refreshEarlyMode();
  setStatus(`增强模式已关闭，后续页面不再预注入。${restored?.restored != null ? `已恢复 ${restored.restored} 项。` : ''}`);
}

async function refreshTargetPage() {
  try {
    setStatus('正在刷新目标页面...');
    await chrome.tabs.reload(targetTabId);
    await waitForTabSettled(8000);
    await new Promise((resolve) => setTimeout(resolve, 700));
    await analyze();
    setStatus('目标页面已刷新，可以重新尝试路由跳转。');
  } catch (error) {
    setStatus(`刷新失败: ${error?.message || String(error)}`, true);
  }
}

async function registerEarlyContentScript() {
  await unregisterEarlyContentScript();
  await chrome.scripting.registerContentScripts([{
    id: earlyTarget.id,
    matches: [earlyTarget.match],
    js: ['scripts/injected/vue-early-guard.js'],
    runAt: 'document_start',
    world: 'MAIN',
    allFrames: false
  }]);
}

async function unregisterEarlyContentScript() {
  try {
    await chrome.scripting.unregisterContentScripts({ ids: [earlyTarget.id] });
  } catch {}
}

async function injectEarlyScriptNow() {
  try {
    await chrome.scripting.executeScript({
      target: { tabId: targetTabId },
      world: 'MAIN',
      files: ['scripts/injected/vue-early-guard.js']
    });
  } catch {}
}

async function restoreEarlyRuntime() {
  try {
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: targetTabId },
      world: 'MAIN',
      func: () => window.__AEGISSCOPE_VUE_EARLY_GUARD__?.restore?.()
    });
    return result?.result || null;
  } catch {}
  return null;
}

function getEarlyTarget(url) {
  try {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname) return null;
    const scheme = parsed.protocol === 'https:' ? 'https' : 'http';
    const host = parsed.hostname;
    return {
      id: `aegisscope-vue-early-${scheme}-${host.replace(/[^A-Za-z0-9_]/g, '_')}`.slice(0, 90),
      match: `${scheme}://${host}/*`
    };
  } catch {
    return null;
  }
}

async function analyze() {
  setStatus('分析中...');
  latest = await runInPage(analyzeVueRuntime);
  render(latest);
  setStatus(latest?.ok ? '分析完成' : `分析失败: ${latest?.error || 'unknown'}`, !latest?.ok);
}

async function mutateVueRuntime(action) {
  setStatus('执行中...');
  const result = await runInPage(mutatePageVueRuntime, [action]);
  latest = await runInPage(analyzeVueRuntime);
  render(latest);
  setStatus(result?.ok ? result.message : `执行失败: ${result?.error || 'unknown'}`, !result?.ok);
}

async function restoreVueRuntime() {
  setStatus('正在恢复 Vue 运行时...');
  const result = await runInPage(mutatePageVueRuntime, ['restore']);
  const early = await restoreEarlyRuntime();
  latest = await runInPage(analyzeVueRuntime);
  render(latest);
  const earlyText = early?.restored != null ? ` / 预注入恢复 ${early.restored}` : '';
  setStatus(result?.ok ? `${result.message}${earlyText}` : `恢复失败: ${result?.error || 'unknown'}${earlyText}`, !result?.ok);
}

async function runInPage(func, args = []) {
  const [result] = await chrome.scripting.executeScript({
    target: { tabId: targetTabId },
    world: 'MAIN',
    func,
    args
  });
  return result?.result;
}

function render(data) {
  const ok = data?.ok;
  const vue = data?.vue || {};
  const router = data?.router || {};
  const routes = data?.routes || [];
  const guards = data?.guards || {};
  const sensitive = routes.filter((r) => r.sensitive);
  const guardTotal = Object.values(guards).reduce((sum, n) => sum + (Number(n) || 0), 0);

  els.vueStatus.textContent = ok && vue.detected ? '\u5df2\u8bc6\u522b' : '\u672a\u53d1\u73b0';
  els.vueMeta.textContent = vue.detected
    ? `${vue.type || '\u672a\u77e5'} / ${vue.version || '\u672a\u77e5'} / \u6839\u8282\u70b9 ${vue.roots || 0}`
    : '\u672a\u53d1\u73b0 Vue \u8fd0\u884c\u65f6\u5b9e\u4f8b';
  els.routerStatus.textContent = router.detected ? '\u5df2\u8bc6\u522b' : '\u672a\u53d1\u73b0';
  els.routerMeta.textContent = router.detected
    ? `${router.mode || '\u672a\u77e5'} / ${router.source || '\u672a\u77e5'}`
    : '\u672a\u53d1\u73b0 Vue Router \u5b9e\u4f8b';
  els.routeCount.textContent = String(routes.length);
  els.sensitiveCount.textContent = `${sensitive.length} \u6761\u654f\u611f\u8def\u7531`;
  els.guardCount.textContent = String(guardTotal);
  els.guardMeta.textContent = Object.entries(guards)
    .filter(([, n]) => n)
    .map(([k, n]) => `${k}:${n}`)
    .join(' / ') || '-';
  els.details.textContent = JSON.stringify(data || {}, null, 2);
  renderRoutes();
}
function renderRoutes() {
  const keyword = els.routeSearch.value.trim().toLowerCase();
  const routes = (latest?.routes || []).filter((route) => {
    if (!keyword) return true;
    return JSON.stringify(route).toLowerCase().includes(keyword);
  });
  els.routes.innerHTML = '';
  if (!routes.length) {
    els.routes.innerHTML = '<div class="route"><div><div class="path">No routes</div><div class="meta">-</div></div></div>';
    return;
  }
  for (const route of routes) {
    const node = document.createElement('div');
    node.className = `route ${route.sensitive ? 'sensitive' : ''}`;
    const meta = route.meta && Object.keys(route.meta).length ? JSON.stringify(route.meta) : '-';
    const routePath = route.path || '';
    const canJump = isJumpableRoute(routePath);
    const jumpText = isDynamicRoute(routePath) ? '填参跳转' : '跳转';
    node.innerHTML = `
      <div>
        <div class="path">${escapeHtml(route.path || '(empty)')}</div>
        <div class="meta">${escapeHtml(route.name || 'anonymous')} · ${escapeHtml(meta)}</div>
      </div>
      <div class="tags">
        ${route.hasAuth ? '<span class="tag warn">auth</span>' : ''}
        ${route.beforeEnter ? '<span class="tag danger">beforeEnter</span>' : ''}
        ${route.children ? `<span class="tag">children ${route.children}</span>` : ''}
        <button class="jump" ${canJump ? '' : 'disabled'} title="跳转到这个路由">跳转</button>
      </div>`;
    const jump = node.querySelector('.jump');
    if (jump) jump.textContent = jumpText;
    jump?.addEventListener('click', () => jumpToRoute(routePath));
    els.routes.appendChild(node);
  }
}

function isJumpableRoute(path) {
  return !!path && typeof path === 'string' && path.startsWith('/');
}

function isDynamicRoute(path) {
  return typeof path === 'string' && /(?::[A-Za-z_$][\w$-]*|\*)/.test(path);
}

function resolveJumpPath(path) {
  if (!isDynamicRoute(path)) return path;
  let cancelled = false;
  let next = path.replace(/:([A-Za-z_$][\w$-]*)(\([^)]*\))?([?+*])?/g, (full, name, pattern = '', modifier = '') => {
    const optional = modifier === '?';
    const defaultValue = /(?:id|ID)$/.test(name) || /\\d|0-9/.test(pattern) ? '1' : name;
    const input = prompt(`请输入路由参数 ${name}`, defaultValue);
    if (input == null) {
      cancelled = true;
      return full;
    }
    if (!input && optional) return '';
    if (!input) {
      cancelled = true;
      return full;
    }
    const value = String(input);
    if (modifier === '+' || modifier === '*') {
      return value.split('/').map((part) => encodeURIComponent(part)).join('/');
    }
    return encodeURIComponent(value);
  });
  next = next.replace(/\*+/g, () => {
    const input = prompt('请输入通配路径', '');
    if (input == null) {
      cancelled = true;
      return '';
    }
    return String(input).split('/').map((part) => encodeURIComponent(part)).join('/');
  });
  if (cancelled) return '';
  return next.replace(/\/+/g, '/') || '/';
}

async function jumpToRoute(path) {
  if (!isJumpableRoute(path)) {
    setStatus('该路由无法直接跳转。', true);
    return;
  }
  const targetPath = resolveJumpPath(path);
  if (!targetPath) {
    setStatus('已取消路由跳转。', true);
    return;
  }
  setStatus(`正在处理前端守卫并跳转 ${targetPath}...`);
  const guardResult = await runInPage(mutatePageVueRuntime, ['clearGuards']);
  const authResult = await runInPage(mutatePageVueRuntime, ['patchAuth']);
  const result = await runInPage(navigateVueRoute, [targetPath]);
  if (result?.url) {
    await chrome.tabs.update(targetTabId, { url: result.url });
  }
  await waitForTabSettled();
  await new Promise((resolve) => setTimeout(resolve, 550));
  await analyze();
  const guardChanged = Number(guardResult?.changed || 0);
  const authChanged = Number(authResult?.changed || 0);
  const method = result?.ok && !result?.url ? result.method : 'URL fallback';
  setStatus(`已跳转 ${targetPath} / ${method} / 清除守卫 ${guardChanged} / 修改鉴权 ${authChanged}`, false);
}
async function waitForTabSettled(timeout = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const tab = await chrome.tabs.get(targetTabId);
      if (tab.status === 'complete') return;
    } catch {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 160));
  }
}

function confirmAction(title, text, onOk) {
  els.confirmTitle.textContent = title;
  els.confirmText.textContent = text;
  const cleanup = () => {
    els.confirmOk.onclick = null;
    els.confirmCancel.onclick = null;
  };
  els.confirmCancel.onclick = () => {
    cleanup();
    els.confirmDialog.close();
  };
  els.confirmOk.onclick = async () => {
    cleanup();
    els.confirmDialog.close();
    await onOk();
  };
  els.confirmDialog.showModal();
}

async function exportJson() {
  const blob = new Blob([JSON.stringify(latest || {}, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  await chrome.downloads.download({
    url,
    filename: `js-extractor/vue-runtime-${Date.now()}.json`,
    saveAs: true
  });
}

function setStatus(msg, error = false) {
  els.status.textContent = msg;
  els.status.style.color = error ? '#ff9f9f' : '#66f2c9';
}

function escapeHtml(str) {
  return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function analyzeVueRuntime() {
  try {
    const roots = findVueRoots();
    const vueInfo = analyzeVueRoots(roots);
    const routerHit = findRouter(roots);
    const router = routerHit?.router;
    const routes = router ? getRoutes(router) : [];
    const guardStats = router ? getGuardStats(router, routes) : {};
    const currentRoute = router ? readRouterCurrent(router) : null;
    const baseInfo = router ? getBaseInfo(router, routes) : null;
    return {
      ok: true,
      url: location.href,
      vue: vueInfo,
      router: router ? {
        detected: true,
        mode: router.mode || router.history?.mode || router.options?.mode || 'unknown',
        source: routerHit?.source || 'runtime',
        hasCurrentRoute: !!router.currentRoute,
        current: currentRoute,
        base: baseInfo
      } : { detected: false },
      routes: routes.map((route) => serializeRoute(route, router, baseInfo)),
      guards: guardStats,
      backup: summarizeBackup(),
      earlyPreinject: summarizeEarlyPreinject(),
      timestamp: Date.now()
    };
  } catch (error) {
    return { ok: false, error: error?.message || String(error), timestamp: Date.now() };
  }

  function findVueRoots() {
    const out = [];
    const seen = new Set();
    const queue = [];
    if (document.body) queue.push(document.body);
    if (document.documentElement) queue.push(document.documentElement);
    const app = document.getElementById('app');
    if (app) queue.unshift(app);

    let scanned = 0;
    while (queue.length && scanned < 2200) {
      const node = queue.shift();
      scanned++;
      if (!node || seen.has(node)) continue;
      seen.add(node);
      if (node.__vue_app__ || node.__vue__ || node._vnode) out.push(node);
      if (node.children) {
        for (const child of node.children) queue.push(child);
      }
    }
    return out;
  }

  function analyzeVueRoots(roots) {
    let type = null, version = null, hasStore = false;
    for (const root of roots) {
      if (root.__vue_app__) {
        type = type || 'vue3';
        version = version || root.__vue_app__.version;
        hasStore = hasStore || !!(root.__vue_app__.config?.globalProperties?.$store || root.__vue_app__._context?.provides?.pinia);
      }
      if (root.__vue__) {
        type = type || 'vue2';
        version = version || root.__vue__.$root?.$options?._base?.version || window.Vue?.version;
        hasStore = hasStore || !!(root.__vue__.$store || root.__vue__.$root?.$store);
      }
    }
    if (!version && window.Vue?.version) version = window.Vue.version;
    return {
      detected: roots.length > 0 || !!window.Vue || !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__,
      roots: roots.length,
      type: type || (window.Vue ? 'global-vue' : null),
      version: version || 'unknown',
      hasStore
    };
  }

  function findRouter(roots) {
    for (const root of roots) {
      const candidates = routerCandidatesFromRoot(root);
      for (const item of candidates) {
        if (isRouterLike(item.router)) {
          return item;
        }
      }
    }
    const globals = [window.$router, window.router, window.__router, window.app?.config?.globalProperties?.$router];
    for (const r of globals) {
      if (isRouterLike(r)) {
        return { router: r, source: 'global' };
      }
    }
    return null;
  }

  function routerCandidatesFromRoot(root) {
    const items = [];
    const app = root.__vue_app__;
    const vue = root.__vue__;
    if (app) {
      items.push({ router: app.config?.globalProperties?.$router, source: 'vue3 globalProperties' });
      items.push({ router: app._instance?.proxy?.$router, source: 'vue3 proxy' });
      items.push({ router: app._instance?.ctx?.$router, source: 'vue3 ctx' });
      const provides = app._context?.provides || app._instance?.provides;
      if (provides) {
        for (const key of Reflect.ownKeys(provides)) {
          const value = provides[key];
          if (isRouterLike(value)) items.push({ router: value, source: `vue3 provide ${String(key)}` });
        }
      }
    }
    if (vue) {
      items.push({ router: vue.$router, source: 'vue2 instance' });
      items.push({ router: vue.$root?.$router, source: 'vue2 root' });
      items.push({ router: vue._routerRoot?._router, source: 'vue2 routerRoot' });
    }
    return items;
  }

  function isRouterLike(obj) {
    return !!obj && typeof obj === 'object' &&
      (typeof obj.push === 'function' || typeof obj.replace === 'function') &&
      (typeof obj.getRoutes === 'function' || Array.isArray(obj.options?.routes) || obj.matcher);
  }

  function getRoutes(router) {
    let routes = [];
    if (typeof router.getRoutes === 'function') {
      routes = router.getRoutes();
    } else if (router.matcher?.getRoutes) {
      routes = router.matcher.getRoutes();
    } else if (Array.isArray(router.options?.routes)) {
      routes = flattenRoutes(router.options.routes);
    } else if (router.history?.current?.matched) {
      routes = router.history.current.matched;
    }
    return Array.from(new Set(routes)).slice(0, 1000);
  }

  function flattenRoutes(routes, out = []) {
    for (const route of routes || []) {
      out.push(route);
      if (Array.isArray(route.children)) flattenRoutes(route.children, out);
    }
    return out;
  }

  function serializeRoute(route, router, baseInfo) {
    const meta = safeClone(route.meta || {});
    const path = route.path || route.regex?.toString?.() || '';
    const name = route.name != null ? String(route.name) : '';
    const hasAuth = routeHasAuth(route);
    const aliases = normalizeAlias(route.alias || route.aliasOf?.path);
    const redirect = typeof route.redirect === 'string' ? route.redirect : route.redirect ? '[function/object]' : '';
    const riskReasons = routeRiskReasons(route, path, name, hasAuth);
    return {
      path,
      name,
      meta,
      hasAuth,
      sensitive: hasAuth || isSensitivePath(path, name),
      riskReasons,
      beforeEnter: !!route.beforeEnter,
      children: Array.isArray(route.children) ? route.children.length : 0,
      aliases,
      redirect,
      depth: path.split('/').filter(Boolean).length,
      fullUrl: buildRoutePreviewUrl(path, router, baseInfo),
      components: Object.keys(route.components || {}).slice(0, 10)
    };
  }

  function normalizeAlias(alias) {
    if (!alias) return [];
    return (Array.isArray(alias) ? alias : [alias]).map((item) => String(item?.path || item)).filter(Boolean).slice(0, 10);
  }

  function routeRiskReasons(route, path, name, hasAuth) {
    const reasons = [];
    if (hasAuth) reasons.push('auth-meta-or-guard');
    if (route.beforeEnter) reasons.push('route-before-enter');
    if (isSensitivePath(path, name)) reasons.push('sensitive-name');
    if (route.redirect) reasons.push('redirect');
    return reasons;
  }

  function routeHasAuth(route) {
    const meta = route.meta || {};
    const keys = Object.keys(meta);
    return !!route.beforeEnter || keys.some((key) => isAuthKey(key) && Boolean(meta[key]));
  }

  function isAuthKey(key) {
    return /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i.test(key);
  }

  function isSensitivePath(path, name) {
    return /(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|secret|token|debug|internal)/i.test(`${path} ${name}`);
  }

  function getGuardStats(router, routes) {
    const stats = {};
    const props = ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks', 'hooks'];
    for (const prop of props) {
      const val = router[prop];
      if (Array.isArray(val) || val instanceof Set) stats[prop] = val.size ?? val.length;
    }
    stats.routeBeforeEnter = routes.filter((r) => !!r.beforeEnter).length;
    return stats;
  }

  function readRouterCurrent(router) {
    const cur = router?.currentRoute?.value || router?.currentRoute || router?.history?.current || null;
    if (!cur || typeof cur !== 'object') return null;
    return {
      path: cur.path || '',
      fullPath: cur.fullPath || '',
      name: cur.name != null ? String(cur.name) : ''
    };
  }

  function getBaseInfo(router, routes) {
    const configured = router?.options?.base || router?.history?.base || '';
    const baseTag = document.querySelector('base[href]')?.getAttribute('href') || '';
    return {
      configured: configured || '',
      baseTag,
      inferredFromLinks: inferBaseFromLinks(routes),
      mode: inferRouterMode(router)
    };
  }

  function inferBaseFromLinks(routes) {
    const paths = routes.map((r) => r?.path).filter((p) => typeof p === 'string' && p.startsWith('/') && p.length > 1).slice(0, 80);
    if (!paths.length) return '';
    const scores = new Map();
    const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 500);
    for (const link of links) {
      let url;
      try { url = new URL(link.getAttribute('href'), location.href); } catch { continue; }
      for (const path of paths) {
        if (!url.pathname.endsWith(path)) continue;
        const base = url.pathname.slice(0, -path.length).replace(/\/+$/, '') || '/';
        scores.set(base, (scores.get(base) || 0) + 1);
      }
    }
    return Array.from(scores.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] || '';
  }

  function inferRouterMode(router) {
    const raw = String(router?.mode || router?.history?.mode || router?.history?.type || '');
    if (/hash/i.test(raw) || /^#\/?/.test(location.hash)) return 'hash';
    return 'history';
  }

  function buildRoutePreviewUrl(path, router, baseInfo) {
    if (!path || !isPreviewablePath(path)) return '';
    try {
      const resolved = router?.resolve?.(path);
      const href = typeof resolved === 'string' ? resolved : resolved?.href;
      if (href) return new URL(href, location.href).href;
    } catch {}
    try {
      const url = new URL(location.href);
      if (baseInfo?.mode === 'hash') {
        url.hash = '#' + path;
        return url.href;
      }
      const base = baseInfo?.configured || baseInfo?.inferredFromLinks || '';
      const cleanBase = base && base !== '/' ? String(base).replace(/\/+$/, '') : '';
      url.pathname = `${cleanBase}${path}`.replace(/\/{2,}/g, '/');
      url.search = '';
      url.hash = '';
      return url.href;
    } catch {
      return '';
    }
  }

  function isPreviewablePath(path) {
    return typeof path === 'string' && path.startsWith('/') && !/[():*+?]/.test(path);
  }

  function safeClone(value) {
    try { return JSON.parse(JSON.stringify(value)); } catch { return String(value); }
  }

  function summarizeBackup() {
    const backup = window.__CSG_VUE_PATCH_BACKUP__;
    if (!backup) return { active: false };
    return {
      active: true,
      guardCollections: backup.guardCollections?.length || 0,
      routeGuards: backup.routeGuards?.length || 0,
      metaEntries: backup.metaEntries?.length || 0,
      routerMethods: backup.routerMethods?.length || 0,
      patchedAt: backup.patchedAt
    };
  }

  function summarizeEarlyPreinject() {
    const early = window.__AEGISSCOPE_VUE_EARLY_GUARD__;
    if (!early) return { active: false };
    return {
      active: !!early.enabled,
      installedAt: early.installedAt,
      routers: early.routers?.length || 0,
      hits: early.hits || 0,
      notes: (early.notes || []).slice(-5)
    };
  }
}

function mutatePageVueRuntime(action) {
  try {
    const analysis = analyzeCurrent();
    if (!analysis.ok || !analysis.router?.detected) {
      return { ok: false, error: '未发现 Vue Router 实例', analysis };
    }

    const ctx = getMutableRouterContext();
    if (!ctx.router) return { ok: false, error: '无法定位可修改的 router 实例', analysis };

    ensureBackup(ctx.router, ctx.routes);
    let changed = 0;
    if (action === 'clearGuards') changed = clearRouteGuards(ctx.router, ctx.routes);
    else if (action === 'patchAuth') changed = patchRouteAuthMeta(ctx.routes);
    else if (action === 'preflight') {
      changed += clearRouteGuards(ctx.router, ctx.routes);
      changed += patchRouteAuthMeta(ctx.routes);
      changed += installRuntimeBypass(ctx.router);
    }
    else if (action === 'restore') changed = restoreRouteRuntime();
    else return { ok: false, error: `未知操作: ${action}`, analysis };

    return {
      ok: true,
      message: `${action} 完成，影响 ${changed} 项`,
      changed,
      analysis: analyzeCurrent()
    };
  } catch (error) {
    return { ok: false, error: error?.message || String(error), analysis: analyzeCurrent() };
  }

  function analyzeCurrent() {
    try {
      const roots = findVueRoots();
      const router = findRouter(roots);
      const routes = router ? getRoutes(router) : [];
      const guards = router ? getGuardStats(router, routes) : {};
      return {
        ok: true,
        url: location.href,
        vue: {
          detected: roots.length > 0 || !!window.Vue || !!window.__VUE_DEVTOOLS_GLOBAL_HOOK__,
          roots: roots.length,
          type: roots.some((r) => r.__vue_app__) ? 'vue3' : roots.some((r) => r.__vue__) ? 'vue2' : window.Vue ? 'global-vue' : null,
          version: roots.find((r) => r.__vue_app__)?.__vue_app__?.version ||
            roots.find((r) => r.__vue__)?.__vue__?.$root?.$options?._base?.version ||
            window.Vue?.version || 'unknown'
        },
        router: router ? {
          detected: true,
          mode: router.mode || router.history?.mode || router.options?.mode || 'unknown',
          source: 'runtime',
          hasCurrentRoute: !!router.currentRoute,
          preflight: !!router.__AEGISSCOPE_VUE_PREFLIGHT__
        } : { detected: false },
        routes: routes.map(serializeRoute),
        guards,
        backup: {
          active: !!window.__CSG_VUE_PATCH_BACKUP__,
          guardCollections: window.__CSG_VUE_PATCH_BACKUP__?.guardCollections?.length || 0,
          routeGuards: window.__CSG_VUE_PATCH_BACKUP__?.routeGuards?.length || 0,
          metaEntries: window.__CSG_VUE_PATCH_BACKUP__?.metaEntries?.length || 0,
          routerMethods: window.__CSG_VUE_PATCH_BACKUP__?.routerMethods?.length || 0,
          patchedAt: window.__CSG_VUE_PATCH_BACKUP__?.patchedAt
        },
        timestamp: Date.now()
      };
    } catch (error) {
      return { ok: false, error: error?.message || String(error), timestamp: Date.now() };
    }
  }

  function getMutableRouterContext() {
    const roots = findVueRoots();
    const router = findRouter(roots);
    const routes = router ? getRoutes(router) : [];
    return { router, routes };
  }

  function findVueRoots() {
    const out = [];
    const queue = [];
    if (document.body) queue.push(document.body);
    const app = document.getElementById('app');
    if (app) queue.unshift(app);
    const seen = new Set();
    let scanned = 0;
    while (queue.length && scanned < 2200) {
      const node = queue.shift();
      scanned++;
      if (!node || seen.has(node)) continue;
      seen.add(node);
      if (node.__vue_app__ || node.__vue__ || node._vnode) out.push(node);
      if (node.children) for (const child of node.children) queue.push(child);
    }
    return out;
  }

  function findRouter(roots) {
    for (const root of roots) {
      const candidates = [];
      const app = root.__vue_app__;
      const vue = root.__vue__;
      if (app) {
        candidates.push(app.config?.globalProperties?.$router, app._instance?.proxy?.$router, app._instance?.ctx?.$router);
        const provides = app._context?.provides || app._instance?.provides;
        if (provides) for (const key of Reflect.ownKeys(provides)) candidates.push(provides[key]);
      }
      if (vue) candidates.push(vue.$router, vue.$root?.$router, vue._routerRoot?._router);
      for (const item of candidates) if (isRouterLike(item)) return item;
    }
    for (const r of [window.$router, window.router, window.__router]) if (isRouterLike(r)) return r;
    return null;
  }

  function isRouterLike(obj) {
    return !!obj && typeof obj === 'object' &&
      (typeof obj.push === 'function' || typeof obj.replace === 'function') &&
      (typeof obj.getRoutes === 'function' || Array.isArray(obj.options?.routes) || obj.matcher);
  }

  function getRoutes(router) {
    if (typeof router.getRoutes === 'function') return router.getRoutes();
    if (router.matcher?.getRoutes) return router.matcher.getRoutes();
    if (Array.isArray(router.options?.routes)) return flattenRoutes(router.options.routes);
    if (router.history?.current?.matched) return router.history.current.matched;
    return [];
  }

  function flattenRoutes(routes, out = []) {
    for (const route of routes || []) {
      out.push(route);
      if (Array.isArray(route.children)) flattenRoutes(route.children, out);
    }
    return out;
  }

  function getGuardStats(router, routes) {
    const stats = {};
    const props = ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks', 'hooks'];
    for (const prop of props) {
      const val = router[prop];
      if (Array.isArray(val) || val instanceof Set) stats[prop] = val.size ?? val.length;
    }
    stats.routeBeforeEnter = routes.filter((r) => !!r.beforeEnter).length;
    return stats;
  }

  function serializeRoute(route) {
    const meta = safeClone(route.meta || {});
    const path = route.path || route.regex?.toString?.() || '';
    const name = route.name != null ? String(route.name) : '';
    const hasAuth = routeHasAuth(route);
    return {
      path,
      name,
      meta,
      hasAuth,
      sensitive: hasAuth || isSensitivePath(path, name),
      beforeEnter: !!route.beforeEnter,
      children: Array.isArray(route.children) ? route.children.length : 0,
      components: Object.keys(route.components || {}).slice(0, 10)
    };
  }

  function routeHasAuth(route) {
    const meta = route.meta || {};
    return !!route.beforeEnter || Object.keys(meta).some((key) => isAuthKey(key) && Boolean(meta[key]));
  }

  function isSensitivePath(path, name) {
    return /(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|secret|token|debug|internal)/i.test(`${path} ${name}`);
  }

  function safeClone(value) {
    try { return JSON.parse(JSON.stringify(value)); } catch { return String(value); }
  }

  function ensureBackup(router, routes) {
    if (window.__CSG_VUE_PATCH_BACKUP__) return;
    const backup = {
      patchedAt: Date.now(),
      guardCollections: [],
      routeGuards: [],
      metaEntries: [],
      routerMethods: []
    };
    const props = ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks', 'hooks'];
    for (const prop of props) {
      const val = router[prop];
      if (Array.isArray(val)) backup.guardCollections.push({ target: router, prop, type: 'array', value: val.slice() });
      else if (val instanceof Set) backup.guardCollections.push({ target: router, prop, type: 'set', value: Array.from(val) });
    }
    for (const route of routes) {
      if (route && Object.prototype.hasOwnProperty.call(route, 'beforeEnter')) {
        backup.routeGuards.push({ route, value: route.beforeEnter });
      }
      if (route?.meta && typeof route.meta === 'object') {
        for (const key of Object.keys(route.meta)) {
          if (isAuthKey(key)) backup.metaEntries.push({ meta: route.meta, key, value: route.meta[key], existed: true });
        }
      }
    }
    window.__CSG_VUE_PATCH_BACKUP__ = backup;
  }

  function clearRouteGuards(router, routes) {
    let changed = 0;
    const props = ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks', 'hooks'];
    for (const prop of props) {
      const val = router[prop];
      if (Array.isArray(val) && val.length) {
        changed += val.length;
        val.length = 0;
      } else if (val instanceof Set && val.size) {
        changed += val.size;
        val.clear();
      }
    }
    for (const route of routes) {
      if (route && route.beforeEnter) {
        route.beforeEnter = undefined;
        changed++;
      }
    }
    return changed;
  }

  function patchRouteAuthMeta(routes) {
    let changed = 0;
    for (const route of routes) {
      if (!route?.meta || typeof route.meta !== 'object') continue;
      for (const key of Object.keys(route.meta)) {
        if (!isAuthKey(key)) continue;
        const next = nextAuthValue(key, route.meta[key]);
        if (route.meta[key] !== next) {
          route.meta[key] = next;
          changed++;
        }
      }
    }
    return changed;
  }

  function installRuntimeBypass(router) {
    const backup = window.__CSG_VUE_PATCH_BACKUP__;
    if (!backup || !router) return 0;
    let changed = 0;
    const guardMethods = ['beforeEach', 'beforeResolve', 'afterEach'];
    for (const prop of guardMethods) {
      if (typeof router[prop] !== 'function' || router[prop].__aegisScopePatched) continue;
      backup.routerMethods.push({ target: router, prop, value: router[prop] });
      const patched = function aegisScopeGuardBypass() {
        return function aegisScopeGuardUnregister() {};
      };
      Object.defineProperty(patched, '__aegisScopePatched', { value: true });
      try {
        router[prop] = patched;
        changed++;
      } catch {}
    }
    try {
      router.__AEGISSCOPE_VUE_PREFLIGHT__ = {
        enabled: true,
        patchedAt: Date.now(),
        methods: guardMethods.filter((name) => router[name]?.__aegisScopePatched)
      };
    } catch {}
    return changed;
  }

  function restoreRouteRuntime() {
    const backup = window.__CSG_VUE_PATCH_BACKUP__;
    if (!backup) return 0;
    let changed = 0;
    for (const item of backup.guardCollections || []) {
      if (item.type === 'array' && Array.isArray(item.target[item.prop])) {
        item.target[item.prop].length = 0;
        item.target[item.prop].push(...item.value);
        changed++;
      } else if (item.type === 'set' && item.target[item.prop] instanceof Set) {
        item.target[item.prop].clear();
        item.value.forEach((x) => item.target[item.prop].add(x));
        changed++;
      }
    }
    for (const item of backup.routeGuards || []) {
      item.route.beforeEnter = item.value;
      changed++;
    }
    for (const item of backup.metaEntries || []) {
      item.meta[item.key] = item.value;
      changed++;
    }
    for (const item of backup.routerMethods || []) {
      try {
        item.target[item.prop] = item.value;
        changed++;
      } catch {}
    }
    try {
      const ctx = getMutableRouterContext();
      if (ctx.router?.__AEGISSCOPE_VUE_PREFLIGHT__) delete ctx.router.__AEGISSCOPE_VUE_PREFLIGHT__;
    } catch {}
    delete window.__CSG_VUE_PATCH_BACKUP__;
    return changed;
  }

  function isAuthKey(key) {
    return /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i.test(key);
  }

  function nextAuthValue(key, value) {
    if (/^(?:permission|permissions|role|roles|authority|access)$/i.test(key)) return Array.isArray(value) ? [] : '';
    if (/^(?:whiteList|noAuth)$/i.test(key)) return true;
    if (typeof value === 'string') return '';
    if (typeof value === 'number') return 0;
    if (Array.isArray(value)) return [];
    if (value && typeof value === 'object') return {};
    return false;
  }
}

async function navigateVueRoute(path) {
  try {
    const router = findRouterForNavigation();
    if (router && typeof router.push === 'function') {
      const beforeHref = location.href;
      const beforeRoute = readRouterPath(router);
      let pushError = '';
      try {
        const ret = router.push(path);
        if (ret && typeof ret.then === 'function') await ret;
      } catch (error) {
        pushError = error?.message || String(error);
      }
      await waitForNavigationEffect(router, beforeHref, beforeRoute, path);
      if (routeChanged(router, beforeHref, beforeRoute, path)) {
        return { ok: true, method: 'router.push', path, href: location.href };
      }
      return {
        ok: false,
        method: 'router.push-no-change',
        error: pushError || 'router.push did not change route',
        url: buildFallbackUrl(path, router),
        path
      };
    }
    return { ok: false, method: 'url-fallback', url: buildFallbackUrl(path, null), path };
  } catch (error) {
    return { ok: false, error: error?.message || String(error), url: buildFallbackUrl(path, null), path };
  }

  function findRouterForNavigation() {
    const roots = findVueRoots();
    for (const root of roots) {
      const app = root.__vue_app__;
      const vue = root.__vue__;
      const candidates = [];
      if (app) {
        candidates.push(app.config?.globalProperties?.$router, app._instance?.proxy?.$router, app._instance?.ctx?.$router);
        const provides = app._context?.provides || app._instance?.provides;
        if (provides) for (const key of Reflect.ownKeys(provides)) candidates.push(provides[key]);
      }
      if (vue) candidates.push(vue.$router, vue.$root?.$router, vue._routerRoot?._router);
      for (const item of candidates) {
        if (item && typeof item.push === 'function') return item;
      }
    }
    for (const item of [window.$router, window.router, window.__router]) {
      if (item && typeof item.push === 'function') return item;
    }
    return null;
  }

  function findVueRoots() {
    const out = [];
    const queue = [];
    if (document.body) queue.push(document.body);
    const app = document.getElementById('app');
    if (app) queue.unshift(app);
    const seen = new Set();
    let scanned = 0;
    while (queue.length && scanned < 2200) {
      const node = queue.shift();
      scanned++;
      if (!node || seen.has(node)) continue;
      seen.add(node);
      if (node.__vue_app__ || node.__vue__ || node._vnode) out.push(node);
      if (node.children) for (const child of node.children) queue.push(child);
    }
    return out;
  }

  function readRouterPath(router) {
    const cur = router?.currentRoute;
    if (!cur) return '';
    const route = cur.value || cur;
    return route.fullPath || route.path || '';
  }

  async function waitForNavigationEffect(router, beforeHref, beforeRoute, targetPath) {
    const start = Date.now();
    while (Date.now() - start < 1200) {
      if (routeChanged(router, beforeHref, beforeRoute, targetPath)) return;
      await new Promise((resolve) => setTimeout(resolve, 80));
    }
  }

  function routeChanged(router, beforeHref, beforeRoute, targetPath) {
    const currentRoute = readRouterPath(router);
    if (currentRoute && normalizePath(currentRoute) === normalizePath(targetPath)) return true;
    if (currentRoute && currentRoute !== beforeRoute && currentRoute.includes(targetPath)) return true;
    if (location.href !== beforeHref && (location.pathname === targetPath || location.hash === `#${targetPath}`)) return true;
    return false;
  }

  function normalizePath(value) {
    return String(value || '').split('?')[0].replace(/\/+$/, '') || '/';
  }

  function buildFallbackUrl(targetPath, router) {
    const resolved = safeResolve(router, targetPath);
    if (resolved) return resolved;
    const url = new URL(location.href);
    const likelyHashMode = url.hash && /^#\/?/.test(url.hash) ||
      /hash/i.test(String(router?.mode || router?.history?.mode || router?.history?.type || ''));
    if (likelyHashMode) {
      url.hash = '#' + targetPath;
      return url.href;
    }
    const base = router?.options?.base || router?.history?.base || '';
    const cleanBase = base && base !== '/' ? String(base).replace(/\/+$/, '') : '';
    url.pathname = `${cleanBase}${targetPath}`.replace(/\/{2,}/g, '/');
    url.search = '';
    url.hash = '';
    return url.href;
  }

  function safeResolve(router, targetPath) {
    try {
      const resolved = router?.resolve?.(targetPath);
      const href = typeof resolved === 'string' ? resolved : resolved?.href;
      if (!href) return '';
      return new URL(href, location.href).href;
    } catch {
      return '';
    }
  }
}
