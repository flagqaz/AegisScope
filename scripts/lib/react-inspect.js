/* Bounded observations stay read-only. Only an explicit navigation command may call a router. */
globalThis.AegisReactProbe = async function inspectReact(command = null) {
  const inspectedUrl = location.href;
  const wallStarted = performance.now();
  const own = (o, k) => { try { return o && Object.getOwnPropertyDescriptor(o, k)?.value; } catch {} };
  function pattern(path) {
    const fields=[], segments=[];
    if(typeof path!=='string' || path.length>2000 || !path.startsWith('/') || path.startsWith('//'))return {fields,unsupported:true};
    for(const segment of path.split('/').slice(1)) {
      const match=/^:([\w]+)(?:\((\\d\+|\[0-9\]\+)\))?([?*+]?)$/.exec(segment);
      let field;
      if(match)field={name:match[1],optional:match[3]==='?'||match[3]==='*',multiple:match[3]==='*'||match[3]==='+',numeric:!!match[2]};
      else if(segment==='*')field={name:'*',optional:true,multiple:true};
      else if(/^[\w-]+\?$/.test(segment))field={name:segment.slice(0,-1),optional:true,literal:segment.slice(0,-1)};
      else if(/[:*?()\\]/.test(segment))return {fields:[],segments:[],manual:true};
      if(field){field.key='p'+fields.length;fields.push(field);segments.push(field);}else segments.push(segment);
    }
    return {fields,segments};
  }
  function resolve(route, values, sourceUrl) {
    const spec=pattern(route.path), source=new URL(sourceUrl);
    if(!/^https?:$/.test(source.protocol) || spec.unsupported)throw Error('不支持的路由地址。');
    let path;
    if(spec.manual) {
      path=own(values,'manual');
      if(typeof path!=='string' || !path.startsWith('/') || path.startsWith('//') || /[?#\\\x00-\x20]/.test(path))throw Error('请填写以 / 开头的具体路径，不包含查询串或锚点。');
      if(path.split('/').some(s=>{try{return ['.','..'].includes(decodeURIComponent(s));}catch{return true;}}))throw Error('路径包含无效片段。');
    } else {
      path='/'+spec.segments.map(segment=>{
        if(typeof segment==='string')return segment;
        let value=own(values,segment.key);
        if(segment.literal)return value===true?segment.literal:null;
        if(value===undefined || value===''){if(segment.optional)return null;throw Error('请填写参数 '+segment.name+'。');}
        if(typeof value!=='string' || value.length>1500 || /[\x00-\x1f\x7f]/.test(value))throw Error('参数 '+segment.name+' 无效。');
        const parts=segment.multiple?value.split('/'):[value];
        if(parts.some(p=>!p || p==='.' || p==='..' || segment.numeric&&!/^\d+$/.test(p)))throw Error('参数 '+segment.name+' 格式不正确。');
        return parts.map(p=>encodeURIComponent(p).replace(/[!'()*]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase())).join('/');
      }).filter(s=>s!==null).join('/');
    }
    const query=own(values,'query') || '', fragment=own(values,'fragment') || '';
    if(typeof query!=='string' || typeof fragment!=='string' || query.length+fragment.length>2000)throw Error('查询参数或锚点过长。');
    if(query)path+='?'+new URLSearchParams(query.replace(/^\?/, '')).toString();
    if(fragment)path+='#'+encodeURIComponent(fragment.replace(/^#/,''));
    const base=typeof route.base==='string'?route.base:'';
    if(base && (!base.startsWith('/') || base.startsWith('//') || /[?#\\]/.test(base)))throw Error('基础路径无效。');
    const prefix=base.replace(/\/$/,'');
    const url=route.mode==='hash'?new URL(source.href):new URL(prefix+path,source.origin);
    if(route.mode==='hash')url.hash=prefix+path;
    if(url.origin!==source.origin)throw Error('仅支持当前站点地址。');
    return {path,url:url.href};
  }
  if(command?.action==='parameters')return pattern(command.path);
  if(command?.action==='resolve') {
    try{return resolve(command.route,command.values,command.sourceUrl);}catch(e){return {error:e.message};}
  }
  function view() {
    const walker=document.createTreeWalker(document.body || document.documentElement,NodeFilter.SHOW_TEXT);
    let node, count=0, length=0, hash=2166136261;
    while ((node=walker.nextNode()) && ++count<=800 && length<16000) {
      if (/^(SCRIPT|STYLE|NOSCRIPT)$/.test(node.parentElement?.tagName || '')) continue;
      const value=(node.nodeValue || '').slice(0,Math.min(1000,16000-length));
      length+=value.length;
      for(let i=0;i<value.length;i++) hash=Math.imul(hash^value.charCodeAt(i),16777619);
    }
    return {url:location.href,documentEpoch:performance.timeOrigin,signature:(hash>>>0)+':'+length};
  }
  if(command?.action==='observe') return view();
  const navigating = command?.action === 'navigate';
  const validCommand = () => !navigating || (location.href === command.expectedUrl &&
    Date.now() < command.deadline && (!command.documentEpoch || command.documentEpoch === performance.timeOrigin));
  if (!validCommand()) return { navigation:{state:'stale',message:'目标页面已变化或导航请求已过期，请重新分析。'} };
  const routeNavigators = new Map();
  const dataNavigators = new WeakSet();
  const navigatorIds = new WeakMap();
  let nextNavigatorId = 0;
  function navigatorId(navigator) {
    if(!navigator)return 0;
    if(!navigatorIds.has(navigator))navigatorIds.set(navigator,++nextNavigatorId);
    return navigatorIds.get(navigator);
  }
  const fiber = o => o && typeof own(o, 'tag') === 'number' &&
    Object.prototype.hasOwnProperty.call(o, 'child') && Object.prototype.hasOwnProperty.call(o, 'return');
  const text = v => typeof v === 'string' ? v.slice(0, 500) : '';
  const warnings = new Set(), evidence = new Set(), versions = new Set(), instances = [], routes = [];
  const roots = [document], fibers = [], stacks=[], seenFibers = new WeakSet(), seenRoots = new WeakSet(), routeKeys = new Set();
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
            let top=value;const parents=new Set();
            while(own(top,'_hostParent') && !parents.has(top) && parents.size<80){parents.add(top);top=own(top,'_hostParent');}
            if (instances.length < 64 && !seenRoots.has(top)) {
              seenRoots.add(top); stacks.push(top);instances.push({ index:instances.length + 1, container:label(n), source:'mounted-stack' });
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
  const links = [], linkKeys = new Set(), linkByUrl=new Map(), jobs = [], seenObjects = new WeakMap();
  const object = o => o !== null && typeof o === 'object';
  const componentName = t => text(own(t, 'displayName')) || text(own(t, 'name'));
  const join = (parent, p) => p.startsWith('/') ? p : p ? parent.replace(/\/$/, '') + '/' + p : parent || '/';
  const initial = { base:'', mode:/^#\//.test(location.hash) ? 'hash' : 'history', modeSource:'地址推测', parent:'' };
  function environment(props, type, inherited) {
    let env = { ...inherited };
    for(const context of [props,own(props,'value')]) {
      const router=own(context,'router'), navigator=own(context,'navigator');
      if(navigator && typeof navigator==='object' && router && ['navigate','subscribe','createHref'].every(k=>typeof own(router,k)==='function'))
        dataNavigators.add(navigator);
    }
    for (const p of [props, own(props,'value'), own(props,'router'), own(own(props,'value'),'router')]) {
      const base = own(p, 'basename');
      if (typeof base === 'string' && (!base || /^\/(?!\/)/.test(base)) && !/[?#\\]/.test(base)) env.base = base;
    }
    const name = componentName(type);
    if (name === 'HashRouter') { env.mode = 'hash'; env.modeSource = '路由组件'; }
    if (name === 'BrowserRouter') { env.mode = 'history'; env.modeSource = '路由组件'; }
    // Match a navigator's observed location, without invoking createHref or any page function.
    const navigator = own(props, 'history') || own(props, 'navigator') ||
      own(own(props,'value'),'navigator') || own(own(props,'value'),'history');
    if (navigator && ['push','replace','createHref'].every(k => typeof own(navigator,k) === 'function'))
      env.navigator = navigator;
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
  function labelText(value) {
    const queue=[value],seen=new WeakSet();let output='',count=0;
    while(queue.length && count++<32 && output.length<200) {
      const item=queue.pop();
      if(typeof item==='string' || typeof item==='number'){output+=String(item);continue;}
      if(!object(item) || seen.has(item))continue;seen.add(item);
      if(Array.isArray(item))for(let i=Math.min(item.length,16)-1;i>=0;i--)queue.push(own(item,String(i)));
      else if(own(item,'$$typeof')===Symbol.for('react.element') || own(item,'$$typeof')===Symbol.for('react.transitional.element'))queue.push(own(own(item,'props'),'children'));
    }
    return output.replace(/\s+/g,' ').trim().slice(0,200);
  }
  function routeLabels(value) {
    const meta=own(value,'meta'),handle=own(value,'handle');
    const name=labelText(own(value,'name'));
    const caption=labelText(own(meta,'title')) || labelText(own(handle,'title')) || labelText(own(value,'title')) || labelText(own(value,'label'));
    const title=caption || name;
    const description=labelText(own(value,'description')) || labelText(own(meta,'description')) || labelText(own(handle,'description'));
    const fields={};
    for(const key of ['title','name','description','icon','hidden','hideInMenu','requiresAuth','authority','roles']) {
      const v=own(meta,key) ?? own(handle,key) ?? own(value,key);
      if(typeof v==='string')fields[key]=v.slice(0,200);
      else if(typeof v==='boolean' || typeof v==='number' && Number.isFinite(v))fields[key]=v;
      else if(Array.isArray(v))fields[key]=Array.from({length:Math.min(v.length,12)},(_,i)=>own(v,String(i))).filter(x=>['string','number','boolean'].includes(typeof x)).map(x=>typeof x==='string'?x.slice(0,100):x);
    }
    return {name,title,description,meta:fields,titleSource:caption?'路由配置':name?'路由名称':''};
  }
  function mergeLabels(target,details) {
    if(target.titleSource==='路由名称' && details.titleSource==='路由配置'){target.title=details.title;target.titleSource=details.titleSource;}
    for(const key of ['name','title','description','titleSource'])if(!target[key] && details[key])target[key]=details[key];
    target.meta={...details.meta,...target.meta};
  }
  const routeByKey=new Map();
  function addRoute(path, env, source, value) {
    const full=join(env.parent,path), key=env.mode+'|'+env.base+'|'+full;
    if (env.navigator) {
      if (!routeNavigators.has(key)) routeNavigators.set(key,new Set());
      routeNavigators.get(key).add(env.navigator);
    }
    const labels=routeLabels(value);
    if (routeKeys.has(key)) {mergeLabels(routeByKey.get(key),labels);return;}
    routeKeys.add(key);
    const spec=pattern(full);
    const route={path:full,url:routeUrl(full,env),dynamic:!spec.unsupported && (!!spec.manual || spec.fields.length>0),source,base:env.base,mode:env.mode,modeSource:env.modeSource,...labels};
    routeByKey.set(key,route);routes.push(route);
  }
  function addLink(path, env, source, literal = false, title = '') {
    if (typeof path !== 'string' || !path || path.length > 2000) return;
    try {
      const address = literal ? new URL(path,location.href).href : routeUrl(join(env.parent,path),env,true);
      if (!address) return;
      const u=new URL(address);
      if (!/^https?:$/.test(u.protocol) || u.origin!==location.origin) return;
      const label=labelText(title);
      if(linkKeys.has(u.href)){const previous=linkByUrl.get(u.href);if(!previous.title && label){previous.title=label;previous.titleSource='菜单/链接文字';}return;}
      const link={path:u.pathname+u.search+u.hash,url:u.href,source,title:label,titleSource:label?'菜单/链接文字':''};
      linkKeys.add(u.href);linkByUrl.set(u.href,link);links.push(link);
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
  const configShape = value => object(value) && (typeof own(value,'path')==='string' || own(value,'index')===true || own(value,'path')==null) &&
    ['component','Component','element','render','getComponent','lazy','children','childRoutes','routes'].some(k=>own(value,k)!==undefined);
  // Inspect committed hook state, memo/ref values and effect dependencies, without
  // evaluating closures or traversing pending update queues / stale alternate trees.
  function stateSources(f,env) {
    enqueue(own(f,'memoizedState'),'carrier',env);
    const effects=own(f,'updateQueue');
    enqueue(own(effects,'lastEffect'),'carrier',env);
    enqueue(own(effects,'firstEffect'),'carrier',env);
    for(const field of ['dependencies','dependencies_old','dependencies_new','contextDependencies']) {
      const deps=own(f,field);let dependency=own(deps,'firstContext') || own(deps,'first');
      const seen=new Set();
      while(object(dependency) && !seen.has(dependency) && seen.size<64) {
        seen.add(dependency);enqueue(own(dependency,'memoizedValue'),'props',env);
        dependency=own(dependency,'next');
      }
      if(dependency && seen.size===64)limited('Context 依赖读取达到数量预算');
    }
  }
  const legacyQueue=stacks.map(f=>({f,env:initial})), seenStacks=new WeakSet();
  phase(240);
  for(let cursor=0;cursor<legacyQueue.length && cursor<3000;cursor++) {
    const {f,env}=legacyQueue[cursor];if(!object(f) || seenStacks.has(f))continue;
    seenStacks.add(f);
    const element=own(f,'_currentElement'),props=own(element,'props') || own(own(f,'_instance'),'props');
    const next=environment(props,own(element,'type'),env);
    enqueue(props,'props',next,0,own(element,'type'));
    enqueue(own(own(f,'_instance'),'state'),'carrier',next);
    for(const key of ['_renderedComponent','_renderedNode'])if(own(f,key))legacyQueue.push({f:own(f,key),env:next});
    for(const key of ['_renderedChildren','_renderedChildrenArray']) {
      const children=own(f,key);if(object(children))for(const k of Object.keys(children).slice(0,500))legacyQueue.push({f:own(children,k),env:next});
    }
    if(cursor%200===0)await pause();
    if(!budget()){limited('旧版 React 实例读取达到时间预算');break;}
  }
  if(legacyQueue.length>3000)limited('旧版 React 实例读取达到数量预算');
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
    stateSources(f,next);
    enqueue(own(instance,'state'),'carrier',next);
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
    const key=kind+'|'+env.base+'|'+env.mode+'|'+env.parent+'|'+componentName(type)+'|'+navigatorId(env.navigator);
    let contexts=seenObjects.get(value);
    if(contexts?.has(key))continue;
    if(!contexts){contexts=new Set();seenObjects.set(value,contexts);}contexts.add(key);
    routeCount++;
    if(kind==='carrier') {
      if(Array.isArray(value)) {
        const size=Math.min(value.length,500);
        for(let i=0;i<size;i++) {
          const entry=own(value,String(i));
          enqueue(entry,configShape(entry)?'config':'carrier',env,depth+1);
        }
        if(value.length>500)limited('状态数组读取达到数量预算');
      }else {
        const marker=own(value,'$$typeof');
        if(marker===Symbol.for('react.element') || marker===Symbol.for('react.transitional.element'))enqueue(value,'element',env,depth+1);
        else {
          const next=environment(value,null,env);
          for(const k of ['routes','routeConfig'])enqueue(own(value,k),'config',next,depth+1);
          for(const k of ['memoizedState','baseState','next','deps','current','value','props','children','routeRelatedConfig','router'])enqueue(own(value,k),'carrier',next,k==='next'?depth:depth+1);
        }
      }
    } else if(Array.isArray(value)) {
      if(value.length>500)limited('单个路由列表最多读取 500 项');
      for(let i=0;i<Math.min(value.length,500);i++)enqueue(own(value,String(i)),kind,env,depth+1,type);
    } else if(kind==='config') {
      const p=own(value,'path'), paths=Array.isArray(p)?p:[p];
      for(let i=0;i<Math.min(paths.length,100);i++) {
        const path=own(paths,String(i));
        if(typeof path!=='string' && path!=null)continue;
        if(typeof path==='string' || own(value,'index')===true)addRoute(text(path),env,'运行时路由配置',value);
        const next={...env,parent:join(env.parent,text(path))};
        enqueue(own(value,'children'),'config',next,depth+1);
        enqueue(own(value,'childRoutes'),'config',next,depth+1);
        enqueue(own(value,'routes'),'config',next,depth+1);
        enqueue(own(value,'indexRoute'),'config',next,depth+1);
        if(own(value,'getChildRoutes') || own(value,'lazy'))warnings.add('存在懒加载路由，未调用加载函数；未加载子路由可能不可见');
      }
    } else if(kind==='element') {
      const marker=own(value,'$$typeof');
      if(marker===Symbol.for('react.element') || marker===Symbol.for('react.transitional.element'))
        enqueue(own(value,'props'),'props',env,depth+1,own(value,'type'));
    } else {
      let next=environment(value,type,env);
      for(const k of ['routes','routeConfig'])enqueue(own(value,k),'config',next,depth+1);
      if(configShape(own(value,'route')))enqueue(own(value,'route'),'config',next,depth+1);
      for(const k of ['router','value','routeRelatedConfig'])enqueue(own(value,k),'props',next,depth+1);
      // Wrappers often keep JSX/config under an explicit slot rather than children.
      for(const k of ['content','outlet','routeElement'])enqueue(own(value,k),'element',next,depth+1);
      const name=componentName(type), path=own(value,'path');
      const isRoute=routeProps(value,type);
      if(isRoute && (typeof path==='string' || Array.isArray(path) || own(value,'index')===true)) {
        const paths=Array.isArray(path)?path:[path];
        for(let i=0;i<Math.min(paths.length,100);i++) {
          const p=own(paths,String(i)); if(p!=null && typeof p!=='string')continue;
          addRoute(text(p),next,'JSX 路由配置',value);
          enqueue(own(value,'children'),'element',{...next,parent:join(next.parent,text(p))},depth+1);
        }
      } else enqueue(own(value,'children'),'element',next,depth+1);
      const target=destination(own(value,'to'));
      if(name==='Link' || name==='NavLink')addLink(target,next,'React 链接（非路由配置）',false,own(value,'title') || own(value,'children'));
      else if(type && typeof type!=='string' && /^\/(?!\/)|^#/.test(target)) {
        // Minified Redirect/Navigate components cannot be identified by their names.
        // Keep their explicit static destination as a candidate, not a confirmed route.
        addLink(target,next,'React 跳转目标（非路由配置）');
        const from=own(value,'from');
        if(typeof from==='string' && from.startsWith('/'))addLink(from,next,'React 跳转来源（非路由配置）');
      }
      if(type==='a')addLink(own(value,'href'),next,'React 链接（非路由配置）',true,own(value,'aria-label') || own(value,'title') || own(value,'children'));
      if(own(value,'eventKey')!==undefined || own(value,'rule')!==undefined) {
        const p=own(value,'rule') || own(value,'eventKey');
        if(typeof p==='string' && p.startsWith('/'))addLink(p,next,'菜单地址（非路由配置）',false,own(value,'title') || own(value,'label') || own(value,'children'));
      }
    }
    if(routeCount%200===0)await pause();
  }
  for (const a of roots.flatMap(root=>Array.from(root.querySelectorAll('a[href]')).slice(0,500)).slice(0,500)) {
    try {
      const u = new URL(a.getAttribute('href'), location.href);
      addLink(u.href,initial,'页面链接（非路由配置）',true,a.getAttribute('aria-label') || a.getAttribute('title') || a.textContent?.slice(0,200));
    } catch {}
  }
  warnings.add('仅检查当前主页面和开放 Shadow DOM；关闭的 Shadow DOM、未加载路由和其他框架内页面可能不可见');
  if (!routes.length) warnings.add('未发现可读取的路由配置，不代表站点没有路由');
  for(const route of routes) {
    const link=linkByUrl.get(route.url);
    if((!route.title || route.titleSource==='路由名称') && link?.title){route.title=link.title;route.titleSource=link.titleSource;}
    const candidates=routeNavigators.get(route.mode+'|'+route.base+'|'+route.path);
    route.navigation=candidates?.size===1?'router':candidates?.size>1?'ambiguous':'address';
  }
  if(navigating) {
    const fail=(state,message)=>({navigation:{state,message}});
    if(!validCommand())return fail('stale','目标页面已变化或导航请求已过期，请重新分析。');
    const requested=command.route;
    const route=routes.find(r=>r.path===requested?.path && r.base===requested?.base &&
      r.mode===requested?.mode && r.url===(requested?.templateUrl ?? requested?.url));
    if(!route)return fail('unavailable','当前页面未找到这条路由，请重新分析，或使用“地址打开”。');
    let targetPath=route.path, targetUrl=route.url;
    if(route.dynamic) {
      try{const resolved=resolve(route,requested.parameters,inspectedUrl);targetPath=resolved.path;targetUrl=resolved.url;}
      catch(e){return fail('invalid',e.message);}
      if(targetUrl!==requested.url)return fail('invalid','参数生成的地址不一致，请重新填参。');
    }
    if(!targetUrl)return fail('invalid','缺少有效跳转地址。');
    if(route.navigation!=='router')return fail('unavailable',route.navigation==='ambiguous'?
      '这条路由关联了多个路由器，无法确定导航对象；请使用“地址打开”。':
      '当前页面未暴露可调用的路由器，请使用“地址打开”。');
    const [navigator]=routeNavigators.get(route.mode+'|'+route.base+'|'+route.path);
    // history v4 applies basename itself; newer navigators expect a prefixed path.
    // Resolve through the selected router's own createHref before invoking push once.
    let destination;
    try {
      for(const path of new Set([targetPath,route.base.replace(/\/$/,'')+targetPath])) {
        const parsed=new URL(path,location.origin);
        if(parsed.origin!==location.origin)continue;
        const candidate={pathname:parsed.pathname,search:parsed.search,hash:parsed.hash};
        const href=own(navigator,'createHref').call(navigator,candidate);
        if(typeof href==='string' && new URL(href,location.href).href===targetUrl) {destination=candidate;break;}
      }
      if(!destination)return fail('unavailable','路由器生成的地址与采集地址不一致，请重新分析或使用“地址打开”。');
      if(!validCommand())return fail('stale','目标页面已变化或导航请求已过期，请重新分析。');
      const before=view();
      // RouterProvider's navigator delegates to router.navigate, which applies its
      // basename. Its createHref only formats URLs, so do not pass the prefix twice.
      if(dataNavigators.has(navigator)) {
        const parsed=new URL(targetPath,location.origin);
        destination={pathname:parsed.pathname,search:parsed.search,hash:parsed.hash};
      }
      await own(navigator,'push').call(navigator,destination);
      return {navigation:{state:'requested',method:'router.push',before,target:targetUrl}};
    } catch(error) {
      return fail('error','路由器未完成导航：'+(typeof error?.message==='string'?error.message.slice(0,300):'页面路由器调用失败'));
    }
  }
  return { detected:evidence.size > 0 || versions.size > 0, mounted:instances.length > 0,
    versions:[...versions], instances, routes, links, evidence:[...evidence], coverage:[...warnings],
    incomplete, url:inspectedUrl, documentEpoch:performance.timeOrigin, checkedNodes:Math.min(nodes,5000), checkedFibers:Math.min(visited,6000), checkedRouteObjects:routeCount };
};
