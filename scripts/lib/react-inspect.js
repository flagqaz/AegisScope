/* Read-only, bounded React observations. Never invoke page callbacks or getters. */
globalThis.AegisReactProbe = async function inspectReact() {
  const inspectedUrl = location.href;
  const wallStarted = performance.now();
  const own = (o, k) => { try { return o && Object.getOwnPropertyDescriptor(o, k)?.value; } catch {} };
  const fiber = o => o && typeof own(o, 'tag') === 'number' &&
    Object.prototype.hasOwnProperty.call(o, 'child') && Object.prototype.hasOwnProperty.call(o, 'return');
  const text = v => typeof v === 'string' ? v.slice(0, 500) : '';
  const warnings = new Set(), evidence = new Set(), versions = new Set(), instances = [], routes = [];
  const roots = [document], fibers = [], seenFibers = new WeakSet(), seenRoots = new WeakSet(), routeKeys = new Set();
  // Each phase owns its active-time budget; yielding must not consume another phase's allowance.
  let active = 0, checkpoint = performance.now(), phaseLimit = 120;
  let incomplete = false;
  const phase = limit => { active = 0; checkpoint = performance.now(); phaseLimit = limit; };
  const limited = message => { incomplete = true; warnings.add(message); };
  let nodes = 0, visited = 0, routeCount = 0;
  const budget = () => { const now=performance.now(); return now-wallStarted<2500 && active+now-checkpoint<phaseLimit; };
  // Timers on the target page can be throttled or replaced. A posted task yields without
  // relying on its setTimeout, and closes both ports after every turn.
  const pause = async () => {
    active += performance.now() - checkpoint;
    await new Promise(resolve => {
      let channel;
      const finish = () => { channel?.port1.close(); channel?.port2.close(); resolve(); };
      try { channel=new MessageChannel(); channel.port1.onmessage=finish; channel.port2.postMessage(null); }
      catch { finish(); }
    });
    checkpoint = performance.now();
  };
  const topCache = new WeakMap();
  const version = v => { if (typeof v === 'string' && /^\d+\.\d+(?:\.\d+)?(?:[-+][\w.-]+)?$/.test(v)) versions.add(v); };
  version(own(own(window, 'React'), 'version'));
  version(own(own(window, 'ReactDOM'), 'version'));
  const label = n => n?.nodeType === 1 ? (n.localName + (n.id ? '#' + n.id.slice(0, 80) : '')) : 'React root';
  function record(value, node, source) {
    if (!fiber(value)) return;
    evidence.add(source);
    let top = value;
    const parents = new Set();
    while (fiber(own(top, 'return')) && parents.size < 80 && !parents.has(top)) {
      if (topCache.has(top)) { top = topCache.get(top); break; }
      parents.add(top); top = own(top, 'return');
    }
    const current = own(own(top, 'stateNode'), 'current');
    if (fiber(current)) top = current;
    for (const parent of parents) topCache.set(parent, top);
    topCache.set(value, top);
    if (!seenRoots.has(top)) {
      seenRoots.add(top);
      if (instances.length < 64) {
        const container = own(own(top, 'stateNode'), 'containerInfo');
        instances.push({ index: instances.length + 1, container: label(container || node), source });
        fibers.push(own(own(top, 'stateNode'), 'current') || top);
      } else limited('挂载实例最多展示 64 个');
    }
  }
  outer: for (let i = 0; i < roots.length; i++) {
    const walker = document.createTreeWalker(roots[i], NodeFilter.SHOW_ELEMENT);
    let n;
    while ((n = walker.nextNode())) {
      if (++nodes > 5000 || !budget()) { limited('DOM 检查达到节点或时间预算；已发现实例仍继续分析路由'); break outer; }
      if (n.shadowRoot) {
        if (roots.length < 64) roots.push(n.shadowRoot); else limited('开放 Shadow DOM 检查达到预算');
      }
      const old = own(n, '_reactRootContainer');
      record(own(own(old, '_internalRoot'), 'current') || own(old, 'current'), n, 'mounted-root');
      try {
        for (const k of Object.getOwnPropertyNames(n).slice(0, 160)) {
          if (!/^__react(?:Fiber|Container|InternalInstance)\$/.test(k)) continue;
          const value = own(n, k);
          record(value, n, 'mounted-fiber');
          // React 15 stack reconciler: require a link back to the observed host node.
          if (!fiber(value) && own(value, '_currentElement') &&
              (own(value, '_hostNode') === n || own(value, '_nativeNode') === n)) {
            evidence.add('mounted-stack');
            if (instances.length < 64 && !seenRoots.has(value)) {
              seenRoots.add(value); instances.push({ index:instances.length + 1, container:label(n), source:'mounted-stack' });
            }
          }
        }
      } catch {}
      if (nodes % 250 === 0) await pause();
    }
  }
  // A hook alone is not evidence. Renderer versions supplement an observed mount only.
  if (evidence.size) {
    const renderers = own(own(window, '__REACT_DEVTOOLS_GLOBAL_HOOK__'), 'renderers');
    try {
      let count = 0;
      for (const renderer of Map.prototype.values.call(renderers)) {
        if (++count > 32) break;
        const name = own(renderer, 'rendererPackageName');
        if (name === 'react-dom') version(own(renderer, 'version'));
      }
    } catch {}
  }
  const links = [], linkKeys = new Set(), jobs = [], seenObjects = new WeakMap();
  const object = o => o !== null && typeof o === 'object';
  const componentName = t => text(own(t, 'displayName')) || text(own(t, 'name'));
  const join = (parent, p) => p.startsWith('/') ? p : p ? parent.replace(/\/$/, '') + '/' + p : parent || '/';
  const initial = { base:'', mode:/^#\//.test(location.hash) ? 'hash' : 'history', modeSource:'地址推测', parent:'' };
  function environment(props, type, inherited) {
    let env = { ...inherited };
    for (const p of [props, own(props,'value'), own(props,'router'), own(own(props,'value'),'router')]) {
      const base = own(p, 'basename');
      if (typeof base === 'string' && (!base || /^\/(?!\/)/.test(base)) && !/[?#\\]/.test(base)) env.base = base;
    }
    const name = componentName(type);
    if (name === 'HashRouter') { env.mode = 'hash'; env.modeSource = '路由组件'; }
    if (name === 'BrowserRouter') { env.mode = 'history'; env.modeSource = '路由组件'; }
    // Match a navigator's observed location, without invoking createHref or any page function.
    const navigator = own(props, 'history') || own(props, 'navigator');
    const routeLocation = own(navigator, 'location') || (navigator && own(props, 'location'));
    const pathname = own(routeLocation, 'pathname');
    if (env.modeSource !== '路由组件' && typeof pathname === 'string' && location.hash) {
      const hashPath = location.hash.slice(1).split(/[?#]/)[0];
      if (pathname === hashPath || pathname === '/' + hashPath) { env.mode='hash'; env.modeSource='路由位置'; }
      else if (pathname === location.pathname) { env.mode='history'; env.modeSource='路由位置'; }
    }
    return env;
  }
  function routeUrl(path, env, staticTarget=false) {
    const patternPath=staticTarget ? path.split(/[?#]/)[0] : path;
    if (!path.startsWith('/') || /[:*?()\\]/.test(patternPath) || path.includes('\\') || path.startsWith('//')) return '';
    const prefix = env.base.replace(/\/$/, '');
    const url = new URL(location.href);
    if (env.mode === 'hash') url.hash = prefix + path;
    else {
      // A route may contain a real URL fragment (e.g. /#login). pathname's setter
      // would encode the separator to %23 and silently navigate to another resource.
      const address=new URL(prefix + path, url.origin);
      return address.origin===url.origin ? address.href : '';
    }
    return url.origin === location.origin ? url.href : '';
  }
  function addRoute(path, env, source) {
    const full=join(env.parent,path), key=env.mode+'|'+env.base+'|'+full;
    if (routeKeys.has(key)) return;
    routeKeys.add(key);
    routes.push({path:full,url:routeUrl(full,env),source,base:env.base,mode:env.mode,modeSource:env.modeSource});
  }
  function addLink(path, env, source, literal = false) {
    if (typeof path !== 'string' || !path || path.length > 2000) return;
    try {
      const address = literal ? new URL(path,location.href).href : routeUrl(join(env.parent,path),env,true);
      if (!address) return;
      const u=new URL(address);
      if (!/^https?:$/.test(u.protocol) || u.origin!==location.origin || linkKeys.has(u.href)) return;
      linkKeys.add(u.href);links.push({path:u.pathname+u.search+u.hash,url:u.href,source});
    } catch {}
  }
  function destination(value) {
    if(typeof value==='string')return value;
    if(!object(value))return '';
    const path=own(value,'pathname'),search=own(value,'search'),hash=own(value,'hash');
    if([path,search,hash].some(v=>v!==undefined && typeof v!=='string'))return '';
    if(search && !search.startsWith('?') || hash && !hash.startsWith('#'))return '';
    return (path || '')+(search || '')+(hash || '');
  }
  function enqueue(value, kind, env, depth=0, type=null) {
    if (!object(value)) return;
    if (depth > 20 || jobs.length >= 16000) { limited('路由对象读取达到深度或数量预算'); return; }
    jobs.push({value,kind,env,depth,type});
  }
  const routeProps = (props,type) => typeof type!=='string' &&
    (componentName(type)==='Route' || ['component','Component','element','render'].some(k=>own(props,k)!==undefined) || own(props,'index')===true);
  const queue = fibers.map(f => ({f,env:initial}));
  phase(240);
  while (queue.length) {
    if (visited >= 6000 || !budget()) { limited('Fiber 检查达到节点或时间预算；已发现配置仍继续读取'); break; }
    const {f,env}=queue.pop();
    if (!fiber(f) || seenFibers.has(f)) continue;
    visited++; seenFibers.add(f);
    const props=own(f,'memoizedProps'), type=own(f,'type'), next=environment(props,type,env);
    enqueue(props,'props',next,0,type);
    const instance=own(f,'stateNode');
    if (own(instance,'props')!==props) enqueue(own(instance,'props'),'props',next,0,type);
    // Context dependencies retain the value actually consumed by this Fiber.
    let dependency=own(own(f,'dependencies'),'firstContext');
    const dependencies=new Set();
    while(object(dependency) && !dependencies.has(dependency) && dependencies.size<32) {
      dependencies.add(dependency);enqueue(own(dependency,'memoizedValue'),'props',next);
      dependency=own(dependency,'next');
    }
    if (dependency && dependencies.size===32) limited('Context 依赖读取达到数量预算');
    const child=own(f,'child'), sibling=own(f,'sibling');
    if (sibling) queue.push({f:sibling,env});
    const parentPath=own(props,'path');
    const childEnv=routeProps(props,type) && typeof parentPath==='string' ? {...next,parent:join(next.parent,parentPath)} : next;
    if (child) queue.push({f:child,env:childEnv});
    if (visited % 200===0) await pause();
  }
  phase(240);
  for(let cursor=0;cursor<jobs.length;cursor++) {
    if(routeCount>=12000 || !budget()) { limited('路由配置读取达到数量或时间预算'); break; }
    const {value,kind,env,depth,type}=jobs[cursor];
    const key=kind+'|'+env.base+'|'+env.mode+'|'+env.parent+'|'+componentName(type);
    let contexts=seenObjects.get(value);
    if(contexts?.has(key))continue;
    if(!contexts){contexts=new Set();seenObjects.set(value,contexts);}contexts.add(key);
    routeCount++;
    if(Array.isArray(value)) {
      if(value.length>500)limited('单个路由列表最多读取 500 项');
      for(let i=0;i<Math.min(value.length,500);i++)enqueue(own(value,String(i)),kind,env,depth+1,type);
    } else if(kind==='config') {
      const p=own(value,'path'), paths=Array.isArray(p)?p:[p];
      for(let i=0;i<Math.min(paths.length,100);i++) {
        const path=own(paths,String(i));
        if(typeof path!=='string' && path!=null)continue;
        if(typeof path==='string' || own(value,'index')===true)addRoute(text(path),env,'运行时路由配置');
        const next={...env,parent:join(env.parent,text(path))};
        enqueue(own(value,'children'),'config',next,depth+1);
        enqueue(own(value,'childRoutes'),'config',next,depth+1);
        if(own(value,'getChildRoutes') || own(value,'lazy'))warnings.add('存在懒加载路由，未调用加载函数；未加载子路由可能不可见');
      }
    } else if(kind==='element') {
      const marker=own(value,'$$typeof');
      if(marker===Symbol.for('react.element') || marker===Symbol.for('react.transitional.element'))
        enqueue(own(value,'props'),'props',env,depth+1,own(value,'type'));
    } else {
      let next=environment(value,type,env);
      for(const k of ['routes','routeConfig'])enqueue(own(value,k),'config',next,depth+1);
      for(const k of ['router','value','routeRelatedConfig'])enqueue(own(value,k),'props',next,depth+1);
      const name=componentName(type), path=own(value,'path');
      const isRoute=routeProps(value,type);
      if(isRoute && (typeof path==='string' || Array.isArray(path) || own(value,'index')===true)) {
        const paths=Array.isArray(path)?path:[path];
        for(let i=0;i<Math.min(paths.length,100);i++) {
          const p=own(paths,String(i)); if(p!=null && typeof p!=='string')continue;
          addRoute(text(p),next,'JSX 路由配置');
          enqueue(own(value,'children'),'element',{...next,parent:join(next.parent,text(p))},depth+1);
        }
      } else enqueue(own(value,'children'),'element',next,depth+1);
      const target=destination(own(value,'to'));
      if(name==='Link' || name==='NavLink')addLink(target,next,'React 链接（非路由配置）');
      else if(type && typeof type!=='string' && /^\/(?!\/)|^#/.test(target)) {
        // Minified Redirect/Navigate components cannot be identified by their names.
        // Keep their explicit static destination as a candidate, not a confirmed route.
        addLink(target,next,'React 跳转目标（非路由配置）');
        const from=own(value,'from');
        if(typeof from==='string' && from.startsWith('/'))addLink(from,next,'React 跳转来源（非路由配置）');
      }
      if(type==='a')addLink(own(value,'href'),next,'React 链接（非路由配置）',true);
      if(own(value,'eventKey')!==undefined || own(value,'rule')!==undefined) {
        const p=own(value,'rule') || own(value,'eventKey');
        if(typeof p==='string' && p.startsWith('/'))addLink(p,next,'菜单地址（非路由配置）');
      }
    }
    if(routeCount%200===0)await pause();
  }
  for (const a of Array.from(document.querySelectorAll('a[href]')).slice(0, 500)) {
    try {
      const u = new URL(a.getAttribute('href'), location.href);
      addLink(u.href,initial,'页面链接（非路由配置）',true);
    } catch {}
  }
  warnings.add('仅检查当前主页面和开放 Shadow DOM；关闭的 Shadow DOM、未加载路由和其他框架内页面可能不可见');
  if (!routes.length) warnings.add('未发现可读取的路由配置，不代表站点没有路由');
  return { detected:evidence.size > 0 || versions.size > 0, mounted:instances.length > 0,
    versions:[...versions], instances, routes, links, evidence:[...evidence], coverage:[...warnings],
    incomplete, url:inspectedUrl, documentEpoch:performance.timeOrigin, checkedNodes:Math.min(nodes,5000), checkedFibers:Math.min(visited,6000), checkedRouteObjects:routeCount };
};
