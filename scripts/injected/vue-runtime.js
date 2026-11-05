// Shared discovery for Vue analysis, navigation and restoration.
(() => {
  const key = '__AEGISSCOPE_VUE_RUNTIME__';
  if (window[key]?.revision === 'vue-review-1') return;
  window[key]?.navigation?.cancel?.();
  const ids = new WeakMap();
  let nextId = 0;
  const read = (fn, fallback = null) => { try { return fn() ?? fallback; } catch { return fallback; } };

  function isRouter(router) {
    return read(() => !!router && typeof router.push === 'function' &&
      (typeof router.getRoutes === 'function' || Array.isArray(router.options?.routes) || router.matcher), false);
  }

  function findRoots() {
    const roots = [], seen = new Set();
    const queue = [document.getElementById('app'), document.documentElement].filter(Boolean);
    for (let i = 0; i < queue.length && seen.size < 5000; i++) {
      const node = queue[i];
      if (!node || seen.has(node)) continue;
      seen.add(node);
      if (read(() => node.__vue_app__) || read(() => node.__vue__) || read(() => node.__vueParentComponent) || read(() => node._vnode?.component)) roots.push(node);
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

  function findRouters(roots = findRoots()) {
    const candidates = [];
    const seen = new Set();
    const add = (router, source) => {
      if (!isRouter(router) || seen.has(router)) return;
      seen.add(router);
      if (!ids.has(router)) ids.set(router, `${performance.timeOrigin}:router-${++nextId}`);
      candidates.push({ router, source, id: ids.get(router) });
    };
    function fromContext(ctx, source) {
      if (!ctx) return;
      add(ctx.config?.globalProperties?.$router, source);
      if (ctx.provides) {
        for (const name of Reflect.ownKeys(ctx.provides)) add(ctx.provides[name], source + ' provide');
      }
    }
    for (const root of roots) {
      try {
      const app = read(() => root.__vue_app__), vue = read(() => root.__vue__);
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
      add(vue?.$root?.$options?.router, 'vue2 options');
      add(vue?._router, 'vue2 router');
      } catch { /* A broken app must not hide other apps on this page. */ }
    }
    for (const get of [() => window.$router, () => window.router, () => window.__router, () => window.app?.config?.globalProperties?.$router]) add(read(get), 'global');
    return candidates;
  }

  function findRouter(roots, id = '') {
    const hits = findRouters(roots);
    return (id ? hits.find((hit) => hit.id === id) : hits[0]) || null;
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
      if (url.origin !== location.origin || !/^https?:$/.test(url.protocol)) return '';
      // Hash navigation stays in the current document. Router 3's resolved href
      // can omit index.html or the document's query string; retain both.
      if (mode(router) === 'hash' && url.hash) {
        const currentUrl = new URL(location.href);
        currentUrl.hash = url.hash;
        return currentUrl.href;
      }
      return url.href;
    }
    if (mode(router) === 'hash') {
      const url = new URL(location.href);
      url.hash = path;
      return url.href;
    }
    const prefix = String(base(router)).replace(/\/+$/, '');
    return new URL(prefix + path, location.origin).href;
  }

  window[key] = { version: '2.3.4', revision: 'vue-review-1', findRoots, findRouters, findRouter, current, mode, base, fullPath, routeUrl };
})();
