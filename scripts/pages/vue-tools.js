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
let navigating = false;

async function syncVueTarget(rejectChanged = false) {
  let tab;
  try { tab = await chrome.tabs.get(targetTabId); }
  catch {
    currentTab = null;earlyTarget = null;latest = null;earlyEnabled = false;
    els.origin.textContent = '目标标签页已关闭';
    els.analyze.disabled = true;els.restore.disabled = true;els.refreshTarget.disabled = true;
    updateAuthorizedButtons();renderRoutes();
    throw new Error('目标标签页已关闭，请从目标页面重新打开工具');
  }
  const oldOrigin = currentTab?.url ? new URL(currentTab.url).origin : '';
  const nextOrigin = tab.url ? new URL(tab.url).origin : '';
  const changed = !!oldOrigin && oldOrigin !== nextOrigin;
  currentTab = tab;earlyTarget = getEarlyTarget(tab.url || '');
  els.origin.textContent = tab.url || '目标不可用';
  if (changed) { latest = null;renderRoutes(); }
  await refreshEarlyMode();
  if (!earlyTarget) throw new Error('当前目标不是可操作的 HTTP/HTTPS 页面');
  if (changed && rejectChanged) throw new Error('目标已切换网站，请重新分析后再操作');
  return tab;
}

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
  try { await syncVueTarget(true); } catch (error) { setStatus(error.message, true);return; }
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
      await syncVueTarget(true);
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
  await restoreVueRuntime();
}

async function refreshTargetPage() {
  try {
    await syncVueTarget(true);
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
  if (!earlyTarget) return;
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [earlyTarget.id] });
  if (registered.length) await chrome.scripting.unregisterContentScripts({ ids: [earlyTarget.id] });
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
  try {
  await syncVueTarget();
  setStatus('分析中...');
  latest = await runInPage(analyzeVueRuntime);
  render(latest);
  setStatus(latest?.ok ? '分析完成' : `分析失败: ${latest?.error || 'unknown'}`, !latest?.ok);
  } catch (error) { setStatus(`分析失败: ${error.message}`, true); }
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
  try {
    await syncVueTarget(true);
    await unregisterEarlyContentScript();
    const result = await runInPage(mutatePageVueRuntime, ['restore']);
    if (!result?.ok) throw new Error(result?.error || '页面未返回恢复结果');
    await refreshEarlyMode();
    latest = await runInPage(analyzeVueRuntime);
    render(latest);
    setStatus(`增强模式已关闭，运行时已恢复 ${result.changed} 项。`);
  } catch (error) {
    setStatus(`恢复失败: ${error?.message || String(error)}`, true);
  }
}

async function runInPage(func, args = []) {
  await syncVueTarget(func !== analyzeVueRuntime);
  await chrome.scripting.executeScript({
    target: { tabId: targetTabId }, world: 'MAIN', files: ['scripts/injected/vue-runtime.js']
  });
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
  if (navigating) return;
  if (!isJumpableRoute(path)) {
    setStatus('该路由无法直接跳转。', true);
    return;
  }
  const targetPath = resolveJumpPath(path);
  if (!targetPath) { setStatus('已取消路由跳转。'); return; }
  navigating = true;
  els.routes.querySelectorAll('.jump').forEach((button) => { button.disabled = true; });
  try {
    await syncVueTarget(true);
    setStatus(`正在跳转 ${targetPath}...`);
    await runInPage(mutatePageVueRuntime, ['clearGuards']);
    await runInPage(mutatePageVueRuntime, ['patchAuth']);
    const result = await runInPage(navigateVueRoute, [targetPath]);
    // Do not reload the page after a guard rejection: that reinstalls all guards.
    latest = await runInPage(analyzeVueRuntime);
    render(latest);
    if (!result?.ok) {
      setStatus(`跳转未完成：${result?.error || '页面未返回导航结果'}${result?.current ? ' / 当前 ' + result.current : ''}`, true);
      return;
    }
    const current = latest?.router?.current?.fullPath || latest?.router?.current?.path;
    if (current !== result.current) {
      setStatus(`目标 ${targetPath} 随后被页面重定向至 ${current || '未知路由'}`, true);
      return;
    }
    const method = result.method === 'vue4-runtime' ? 'Vue Router 4 兼容导航' : 'router.push';
    setStatus(`已跳转 ${current} / ${method}`);
  } catch (error) {
    setStatus(`跳转失败：${error?.message || String(error)}`, true);
  } finally {
    navigating = false;
    renderRoutes();
  }
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
    try { await onOk(); } catch (error) { setStatus(error.message || String(error), true); }
  };
  els.confirmDialog.showModal();
}

async function exportJson() {
  const blob = new Blob([JSON.stringify(latest || {}, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  try {
    await chrome.downloads.download({
      url,
      filename: `js-extractor/vue-runtime-${Date.now()}.json`,
      saveAs: true
    });
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }
}

function setStatus(msg, error = false) {
  els.status.textContent = msg;
  els.status.style.color = error ? '#b42318' : '#087443';
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
        mode: window.__AEGISSCOPE_VUE_RUNTIME__.mode(router),
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
    return window.__AEGISSCOPE_VUE_RUNTIME__.findRoots();
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
    return window.__AEGISSCOPE_VUE_RUNTIME__.findRouter(roots);
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

  function flattenRoutes(routes, out = [], parent = '') {
    for (const route of routes || []) {
      const path = route.path?.startsWith('/') ? route.path : `${parent}/${route.path || ''}`.replace(/\/{2,}/g, '/');
      out.push({ ...route, path });
      if (Array.isArray(route.children)) flattenRoutes(route.children, out, path);
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
    const configured = window.__AEGISSCOPE_VUE_RUNTIME__.base(router);
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
    return window.__AEGISSCOPE_VUE_RUNTIME__.mode(router);
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
    if (action === 'restore') {
      // Stop early observers before touching either backup. Both layers preserve
      // the first original value, including when early injection ran first.
      const early = window.__AEGISSCOPE_VUE_EARLY_GUARD__?.restore?.();
      const changed = (early?.restored || 0) + restoreRouteRuntime();
      return { ok: true, message: `运行时已恢复 ${changed} 项`, changed, analysis: analyzeCurrent() };
    }
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
          mode: window.__AEGISSCOPE_VUE_RUNTIME__.mode(router),
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
    return window.__AEGISSCOPE_VUE_RUNTIME__.findRoots();
  }

  function findRouter(roots) {
    return window.__AEGISSCOPE_VUE_RUNTIME__.findRouter(roots)?.router || null;
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
    const backup = window.__CSG_VUE_PATCH_BACKUP__ || {
      patchedAt: Date.now(),
      guardCollections: [],
      routeGuards: [],
      metaEntries: [],
      routerMethods: []
    };
    const early = router.__AEGISSCOPE_EARLY_BACKUP__;
    const props = ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks', 'hooks'];
    for (const prop of props) {
      if (backup.guardCollections.some((entry) => entry.target === router && entry.prop === prop)) continue;
      const val = router[prop];
      const original = early?.collections?.find((entry) => entry.target === router && entry.prop === prop);
      if (Array.isArray(val)) backup.guardCollections.push({ target: router, prop, type: 'array', value: original ? original.value.slice() : val.slice() });
      else if (val instanceof Set) backup.guardCollections.push({ target: router, prop, type: 'set', value: original ? original.value.slice() : Array.from(val) });
    }
    for (const route of routes) {
      if (route && Object.prototype.hasOwnProperty.call(route, 'beforeEnter') &&
          !backup.routeGuards.some((entry) => entry.route === route)) {
        const original = early?.routeGuards?.find((entry) => entry.route === route);
        backup.routeGuards.push({ route, value: original ? original.value : route.beforeEnter });
      }
      if (route?.meta && typeof route.meta === 'object') {
        for (const key of Object.keys(route.meta)) {
          if (!isAuthKey(key) || backup.metaEntries.some((entry) => entry.meta === route.meta && entry.key === key)) continue;
          const original = early?.metaEntries?.find((entry) => entry.meta === route.meta && entry.key === key);
          backup.metaEntries.push({ meta: route.meta, key, value: original ? original.value : route.meta[key], existed: true });
        }
      }
    }
    window.__CSG_VUE_PATCH_BACKUP__ = backup;
  }

  function originalRouterMethod(router, prop) {
    const early = router.__AEGISSCOPE_EARLY_BACKUP__?.methods?.find((entry) => entry.target === router && entry.prop === prop);
    if (early) return early.value;
    const prototype = window.__AEGISSCOPE_VUE_EARLY_GUARD__?.prototypeBackups?.find((entry) =>
      entry.prop === prop && entry.target.isPrototypeOf(router));
    return prototype && router[prop]?.__aegisScopeEarlyPatched ? prototype.value : router[prop];
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
      if (!backup.routerMethods.some((entry) => entry.target === router && entry.prop === prop)) {
        backup.routerMethods.push({ target: router, prop, value: originalRouterMethod(router, prop) });
      }
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
    for (const router of new Set((backup.routerMethods || []).map((entry) => entry.target))) {
      try { delete router.__AEGISSCOPE_VUE_PREFLIGHT__; } catch {}
    }
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
  const api = window.__AEGISSCOPE_VUE_RUNTIME__;
  const router = api?.findRouter()?.router;
  const readPath = () => api.current(router)?.fullPath || api.current(router)?.path || '';
  const failure = (error) => ({ ok: false, error, current: readPath() });
  if (!router) return failure('未发现可用的 Vue Router 实例');
  let timer;
  async function bounded(task, milliseconds) {
    try {
      return await Promise.race([
        task,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('导航等待超时，请检查页面加载情况后重试')), milliseconds); })
      ]);
    } finally { clearTimeout(timer); }
  }
  try {
    let resolved = router.resolve?.(path);
    let target = resolved?.route || resolved;
    // Follow configured redirects using the same query/hash defaults as Router 4.
    const redirects = new Set();
    while (target?.matched?.at(-1)?.redirect) {
      if (redirects.has(target.fullPath) || redirects.size >= 10) return failure('路由重定向形成循环');
      redirects.add(target.fullPath);
      const record = target.matched.at(-1);
      let redirect = typeof record.redirect === 'function' ? record.redirect(target) : record.redirect;
      if (typeof redirect === 'string') {
        redirect = /[?#]/.test(redirect) ? { path: redirect } : { path: redirect, query: target.query, hash: target.hash };
      } else redirect = { query: target.query, hash: target.hash, ...redirect };
      if (!redirect.path && redirect.name) redirect.params = redirect.params || target.params;
      resolved = router.resolve(redirect);
      target = resolved?.route || resolved;
    }
    if (Array.isArray(target?.matched) && !target.matched.length) return failure('目标未匹配到可渲染的路由');
    const targetPath = target?.fullPath || path;
    const matches = () => api.fullPath(readPath()) === api.fullPath(targetPath);
    if (matches()) return { ok: true, method: 'router.push', current: readPath() };
    let navigationError = '', timedOut = false;
    try {
      const result = await bounded(Promise.resolve().then(() => router.push(path)), 5000);
      if (result?.type === 8) return failure('导航已被页面的其他导航取消，请重试');
      if (result instanceof Error || result?.type) navigationError = result.message || `导航被取消 (${result.type})`;
    } catch (error) {
      navigationError = error?.message || String(error);
      timedOut = /等待超时/.test(navigationError);
      if (!timedOut && !error?.type && !/^Navigation/.test(error?.name || '')) return failure(navigationError);
    }
    if (matches()) return { ok: true, method: 'router.push', current: readPath() };
    // Router 3 can use callback-style push with no Promise.
    if (!router.currentRoute?.__v_isRef && !navigationError) {
      await new Promise((resolve) => setTimeout(resolve, 400));
      if (matches()) return { ok: true, method: 'router.push', current: readPath() };
    }
    if (timedOut) return failure(navigationError);
    const history = router.options?.history;
    const ref = router.currentRoute;
    if (!ref?.__v_isRef || ref.__v_isReadonly || !history || typeof history.push !== 'function') {
      return failure(navigationError || '页面未到达目标路由，可能被守卫拦截或重定向');
    }
    if (!target?.matched?.length) return failure('目标未匹配到可渲染的路由');
    if (target.matched.some((record) => record.redirect)) {
      return failure('该路由配置了重定向，请选择最终页面路由');
    }
    // Use Vue Router's normalized route and lazy-component cache. Changing only the
    // address or the ref without resolving components can leave RouterView blank.
    const before = ref.value;
    const components = [];
    await bounded(Promise.all(target.matched.flatMap((record) => Object.entries(record.components || {}).map(async ([name, component]) => {
      if (typeof component !== 'function' || component.displayName || component.props || component.__vccOpts) return;
      const module = await component();
      const loaded = module?.default || module;
      if (!loaded || !['object', 'function'].includes(typeof loaded)) throw new Error('路由组件加载失败');
      components.push({ record, name, loaded, module });
    }))), 8000);
    if (ref.value !== before) return failure('页面在组件加载期间发生了其他导航，请重试');
    for (const { record, name, loaded, module } of components) {
      record.components[name] = loaded;
      if (record.mods) record.mods[name] = module;
    }
    history.push(target.fullPath);
    ref.value = target;
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (!matches()) return failure('页面逻辑再次重定向，未停留在目标路由');
    return { ok: true, method: 'vue4-runtime', current: readPath() };
  } catch (error) {
    return failure(error?.message || String(error));
  }
}
