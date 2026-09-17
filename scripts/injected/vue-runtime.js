// Shared discovery for Vue analysis, navigation and restoration.
(() => {
  const key = '__AEGISSCOPE_VUE_RUNTIME__';
  if (window[key]) return;

  function isRouter(router) {
    return !!router && typeof router.push === 'function' &&
      (typeof router.getRoutes === 'function' || Array.isArray(router.options?.routes) || router.matcher);
  }

  function findRoots() {
    const roots = [], seen = new Set();
    const queue = [document.getElementById('app'), document.documentElement].filter(Boolean);
    for (let i = 0; i < queue.length && seen.size < 5000; i++) {
      const node = queue[i];
      if (!node || seen.has(node)) continue;
      seen.add(node);
      if (node.__vue_app__ || node.__vue__ || node.__vueParentComponent || node._vnode?.component) roots.push(node);
      if (node.children) {
        for (const child of node.children) {
          if (queue.length >= 10000) break;
          queue.push(child);
        }
      }
      if (node.shadowRoot) queue.push(node.shadowRoot);
    }
    return roots;
  }

  function findRouter(roots = findRoots()) {
    const candidates = [];
    const add = (router, source) => { if (isRouter(router)) candidates.push({ router, source }); };
    function fromContext(ctx, source) {
      if (!ctx) return;
      add(ctx.config?.globalProperties?.$router, source);
      if (ctx.provides) {
        for (const name of Reflect.ownKeys(ctx.provides)) add(ctx.provides[name], source + ' provide');
      }
    }
    for (const root of roots) {
      const app = root.__vue_app__, vue = root.__vue__;
      fromContext(app, 'vue3 app');
      fromContext(app?._context, 'vue3 context');
      let component = root.__vueParentComponent || root._vnode?.component || app?._instance;
      for (let depth = 0; component && depth < 20; depth++, component = component.parent) {
        add(component.proxy?.$router, 'vue3 component');
        add(component.ctx?.$router, 'vue3 ctx');
        fromContext(component.appContext, 'vue3 appContext');
      }
      add(vue?.$router, 'vue2 instance');
      add(vue?.$root?.$router, 'vue2 root');
      add(vue?._routerRoot?._router, 'vue2 routerRoot');
    }
    for (const router of [window.$router, window.router, window.__router, window.app?.config?.globalProperties?.$router]) add(router, 'global');
    return candidates[0] || null;
  }

  function current(router) {
    return router?.currentRoute?.value || router?.currentRoute || router?.history?.current || null;
  }

  function mode(router) {
    const raw = router?.mode || router?.options?.mode || router?.history?.mode || router?.history?.type;
    if (raw) return String(raw);
    const history = router?.options?.history;
    if (history) return String(history.base || '').includes('#') ? 'hash' : 'history';
    return /^#\//.test(location.hash) ? 'hash' : 'history';
  }

  function base(router) {
    return router?.options?.history?.base ?? router?.options?.base ?? router?.history?.base ?? '';
  }

  function fullPath(value) {
    const url = new URL(value || '/', 'https://aegisscope.invalid/');
    url.searchParams.sort();
    return (url.pathname.replace(/\/+$/, '') || '/') + url.search + url.hash;
  }

  function routeUrl(path, router) {
    const result = router?.resolve?.(path);
    const href = typeof result === 'string' ? result : result?.href;
    if (href) {
      const url = new URL(href, location.href);
      return url.origin === location.origin && /^https?:$/.test(url.protocol) ? url.href : '';
    }
    if (mode(router) === 'hash') {
      const url = new URL(location.href);
      url.hash = path;
      return url.href;
    }
    const prefix = String(base(router)).replace(/\/+$/, '');
    return new URL(prefix + path, location.origin).href;
  }

  window[key] = { findRoots, findRouter, current, mode, base, fullPath, routeUrl };
})();
