const targetTabId = Number(new URLSearchParams(location.search).get('tabId'));
const el = id => document.getElementById(id);
let latest = null, busy = false, generation = 0, navigating = false;
let cancelPending = null;
const ANALYSIS_TIMEOUT_MS = 12000;
const status = message => { el('status').textContent = message; };
let lastNavigation=null;
const displayAddress=address=>{try{const url=new URL(address);return url.pathname+url.search+url.hash;}catch{return address || '未知';}};
const loginAddress=address=>{try{const url=new URL(address),path=url.hash?url.hash.slice(1).split('?')[0]:url.pathname;return /(?:^|\/)(?:login|signin|sign-in)(?:\/|$)/i.test(path);}catch{return false;}};
function navigationStatus(record,message,currentUrl,phase) {
  if(record!==lastNavigation || record.snapshot!==latest)return;
  record.currentUrl=currentUrl || record.currentUrl;record.phase=phase;
  latest.navigationResult={targetUrl:record.target,currentUrl:record.currentUrl,method:record.method,title:record.title || '',phase,message,updatedAt:new Date().toISOString()};
  el('navigationResult').hidden=false;
  el('navigationResult').textContent=[record.title?'页面：'+record.title:'', '目标：'+record.target,'当前：'+(record.currentUrl || '等待页面响应'),'方式：'+record.method,'结果：'+message].filter(Boolean).join('\n');
  status(message);
}
let parameterSession=null, previewGeneration=0;
const parameterDrafts=new Map();
function closeParameters() {parameterSession=null;previewGeneration++;el('routeParams').close();}
async function editParameters(item,addressOnly=false) {
  if(!latest || busy || navigating)return;
  const snapshot=latest, token=generation;
  const spec=await AegisReactProbe({action:'parameters',path:item.path});
  if(latest!==snapshot || token!==generation)return;
  if(spec.unsupported){status('不支持的路由模式。');return;}
  const key=new URL(snapshot.url).origin+'|'+item.mode+'|'+item.base+'|'+item.path;
  const saved=parameterDrafts.get(key) || {};
  const fields=spec.manual?[{key:'manual',name:'具体路径',optional:false}]:spec.fields;
  el('paramsFields').replaceChildren(...fields.map(field=>{
    const label=document.createElement('label');label.className='react-param-field';
    label.textContent=field.name+(field.literal?'（勾选保留此段）':field.optional?'（可选）':'（必填）')+(field.multiple?'，多级路径用 / 分隔':field.numeric?'，仅数字':'');
    const input=document.createElement('input');input.dataset.parameter=field.key;
    input.type=field.literal?'checkbox':'text';input.maxLength=1500;
    if(field.literal)input.checked=saved[field.key]===true;else input.value=saved[field.key] || '';
    input.autocomplete='off';label.append(input);return label;
  }));
  el('paramsQuery').value=saved.query || '';el('paramsFragment').value=saved.fragment || '';
  el('paramsPattern').textContent=item.path;
  el('paramsHint').textContent=spec.manual?'此路径包含复杂模式，请填写具体路径；是否匹配由网站路由器判断。':'填写实际参数值，插件会进行 URL 编码。留空的可选参数将省略。';
  parameterSession={item,addressOnly,snapshot,token,key};
  el('routeParams').showModal();await previewParameters();
}
function parameterValues() {
  const values={query:el('paramsQuery').value,fragment:el('paramsFragment').value};
  for(const input of el('paramsFields').querySelectorAll('input'))values[input.dataset.parameter]=input.type==='checkbox'?input.checked:input.value;
  return values;
}
async function previewParameters() {
  const session=parameterSession, token=++previewGeneration;if(!session)return;
  const result=await AegisReactProbe({action:'resolve',route:session.item,values:parameterValues(),sourceUrl:session.snapshot.url});
  if(session!==parameterSession || token!==previewGeneration)return;
  el('paramsPreview').textContent=result.url || '—';el('paramsError').textContent=result.error || '';
  el('paramsSubmit').disabled=!!result.error;
  return result;
}
el('paramsForm').addEventListener('input',previewParameters);
el('paramsCancel').addEventListener('click',closeParameters);
el('routeParams').addEventListener('cancel',()=>{parameterSession=null;previewGeneration++;});
el('paramsForm').addEventListener('submit',async event=>{
  event.preventDefault();const session=parameterSession;if(!session)return;
  const values=parameterValues(), result=await previewParameters();
  if(!result || result.error || session!==parameterSession)return;
  if(session.snapshot!==latest || session.token!==generation){closeParameters();status('分析结果已变化，请重新选择路由。');return;}
  parameterDrafts.set(session.key,values);if(parameterDrafts.size>100)parameterDrafts.delete(parameterDrafts.keys().next().value);
  closeParameters();await openRoute({...session.item,templateUrl:session.item.url,parameters:values,url:result.url},session.addressOnly);
});
function list(id, items) {
  el(id).replaceChildren(...items.map(text => { const li=document.createElement('li'); li.textContent=text; return li; }));
}
function clear() {
  lastNavigation=null;el('navigationResult').hidden=true;el('navigationResult').textContent='';
  latest=null; el('export').disabled=true; el('detected').textContent='待分析';
  el('versions').textContent='—'; el('instances').textContent='0'; el('count').textContent='0';
  el('routeMeta').textContent='可发现的路由配置';
  list('mounts',[]); list('coverage',[]); el('routes').replaceChildren();
}
function sameOrigin(address, source) {
  try { const a=new URL(address), b=new URL(source); return /^https?:$/.test(a.protocol) && a.origin===b.origin; }
  catch { return false; }
}
function retainSnapshot(address) {
  if(!latest)return;
  latest.snapshot.currentUrl=address;
  latest.snapshot.stale=true;
  el('origin').textContent=address;
  list('coverage',[...latest.coverage,'页面已变化：路由、实例和版本为上次采集结果；点击“分析实例”可更新。']);
  if(!navigating) {
    if(lastNavigation && lastNavigation.snapshot===latest) {
      if(address!==lastNavigation.target)navigationStatus(lastNavigation,
        loginAddress(address)?'页面随后返回登录页，未保持在目标路由。':'页面随后离开目标地址；当前 '+displayAddress(address),address,'changed');
      else if(lastNavigation.currentUrl!==address)navigationStatus(lastNavigation,'页面当前已到达 '+displayAddress(address)+'；路由列表已保留。',address,'unconfirmed');
    }else status('已保留上次采集的路由，可继续打开；点击“分析实例”可更新结果。');
  }
}
function renderRoutes() {
  const keyword=el('search').value.trim().toLowerCase();
  const items=[...(latest?.routes || []), ...(latest?.links || [])].filter(x=>[x.path,x.source,x.title,x.name,x.description,JSON.stringify(x.meta || {})].join(' ').toLowerCase().includes(keyword));
  el('routes').replaceChildren(...items.map(item=>{
    const row=document.createElement('div'); row.className='react-row route';
    const content=document.createElement('div'), name=document.createElement('strong'), title=document.createElement('small'), detail=document.createElement('small');
    name.className='path'; title.className='meta react-route-title'; detail.className='meta';
    title.textContent=[item.title || item.name || '未提供路由名称',item.name && item.name!==item.title?item.name:'',item.description || '',item.titleSource==='菜单/链接文字'?'来自菜单/链接':''].filter(Boolean).join(' · ');
    name.textContent=item.path; detail.textContent=item.source+(item.url?' · '+item.url:item.dynamic?' · 可填写参数后打开':' · 无可用地址'); content.append(name,title);
    const fields=Object.fromEntries(Object.entries(item.meta || {}).filter(([key])=>!['title','name','description'].includes(key)));
    if(Object.keys(fields).length){const meta=document.createElement('small');meta.className='meta';meta.textContent=JSON.stringify(fields);content.append(meta);}
    content.append(detail);
    const actions=document.createElement('div'); actions.className='react-route-actions';
    const button=document.createElement('button'); button.textContent=item.dynamic?'填参跳转':'打开'; button.disabled=(!item.url && !item.dynamic) || busy || navigating;
    button.addEventListener('click',()=>item.dynamic?editParameters(item):openRoute(item)); actions.append(button);
    if(item.navigation==='router') {
      const addressButton=document.createElement('button'); addressButton.textContent='地址打开';
      addressButton.title='按地址加载页面；同一页面内的地址也会重新加载';
      addressButton.disabled=(!item.url && !item.dynamic) || busy || navigating;
      addressButton.addEventListener('click',()=>item.dynamic?editParameters(item,true):openRoute(item,true)); actions.append(addressButton);
    }
    row.append(content,actions); return row;
  }));
  if(!items.length) { const empty=document.createElement('p'); empty.className='empty'; empty.textContent='没有可展示的路由或链接。'; el('routes').append(empty); }
}
async function analyze() {
  if(busy || navigating)return;
  const token=++generation; busy=true; clear(); el('analyze').disabled=true; status('正在分析 React…');
  let timer, expired=false;
  const active=()=>{if(expired || token!==generation)throw Error('分析任务已失效。');};
  try {
    if(!Number.isInteger(targetTabId)||targetTabId<=0)throw Error('缺少有效目标标签页，请从插件重新打开工具。');
    const deadline=new Promise((_,reject)=>{
      cancelPending=()=>{expired=true;reject(Error('分析任务已失效。'));};
      timer=setTimeout(()=>{expired=true;reject(Error('分析超时（12 秒）。目标页可能被暂停、冻结或未响应；请切回目标页检查后重新分析。'));},ANALYSIS_TIMEOUT_MS);
    });
    const request=async()=>{
      const tab=await chrome.tabs.get(targetTabId);active();
      if(!/^https?:/.test(tab.url || ''))throw Error('此页面不支持运行时分析。');
      el('origin').textContent=tab.url;
      const [entry]=await chrome.scripting.executeScript({target:{tabId:targetTabId},world:'MAIN',func:AegisReactProbe});active();
      const data=entry?.result, current=await chrome.tabs.get(targetTabId);active();
      if(!data || data.url!==current.url)throw Error('目标页面已变化，请重新分析。');
      return data;
    };
    const data=await Promise.race([request(),deadline]);active();
    latest=data;
    latest.snapshot={sourceUrl:data.url,currentUrl:data.url,capturedAt:new Date().toISOString(),stale:false};
    el('detected').textContent=data.detected?'已识别':'未发现';
    el('versions').textContent=data.versions.join(' / ') || '未暴露';
    el('instances').textContent=String(data.instances.length); el('count').textContent=String(data.routes.length);
    el('routeMeta').textContent=data.links.length ? `另有 ${data.links.length} 条链接 / 跳转地址` : '可发现的路由配置';
    list('mounts',data.instances.map(x=>`${x.index}. ${x.container} · ${x.source}`)); list('coverage',data.coverage);
    el('export').disabled=false;
    status(data.incomplete?'分析未覆盖全部内容：已达到采集预算，请结合采集范围查看结果。':data.detected?'分析完成，请结合采集范围查看结果。':'未发现明确 React 运行时证据；未挂载或不可访问的实例仍可能未被采集。');
  } catch(e) { if(token===generation){clear();status(e.message || String(e));} }
  finally {clearTimeout(timer);if(token===generation){cancelPending=null;busy=false;el('analyze').disabled=false;renderRoutes();}}
}
async function openRoute(item, addressOnly=false) {
  if(!latest || busy || navigating)return;
  const snapshot=latest, token=generation;
  const address=typeof item==='string'?item:item.url;
  const active=()=>snapshot===latest && token===generation;
  let timer, expired=false, record;
  navigating=true;el('analyze').disabled=true;renderRoutes();
  try {
    const deadline=Date.now()+ANALYSIS_TIMEOUT_MS;
    const check=()=>{if(!active() || expired)throw Error('导航任务已失效。');};
    const request=async()=>{
      const tab=await chrome.tabs.get(targetTabId), url=new URL(address);check();
      if(!sameOrigin(tab.pendingUrl || tab.url,snapshot.url)) {
        invalidate('目标页面已切换到其他站点，请重新分析。'); return;
      }
      if(!sameOrigin(url.href,snapshot.url))throw Error('地址无效，请重新分析。');
      record={snapshot,target:url.href,currentUrl:tab.url,title:typeof item==='object'?item.title || item.name:'',method:addressOnly || typeof item==='string' || item.navigation!=='router'?'地址导航':'router.push'};
      lastNavigation=record;
      navigationStatus(record,'正在跳转 '+displayAddress(url.href)+'，控制台保持打开…',tab.url,'requested');
      let result;
      if(addressOnly || typeof item==='string' || item.navigation!=='router') {
        await chrome.tabs.update(targetTabId,{url:url.href});check();
        // Hash-only tabs.update does not reload the document. The explicit address
        // entry provides a real page load when the application's view is out of sync.
        if(addressOnly && tab.url?.split('#')[0]===url.href.split('#')[0]) {
          const current=await chrome.tabs.get(targetTabId);check();
          if(current.url===url.href)await chrome.tabs.reload(targetTabId);
        }
        check();result={target:url.href,before:{documentEpoch:null,signature:null}};
      }else {
        const [entry]=await chrome.scripting.executeScript({target:{tabId:targetTabId},world:'MAIN',func:AegisReactProbe,
          args:[{action:'navigate',route:item,expectedUrl:tab.url,documentEpoch:snapshot.snapshot.stale?null:snapshot.documentEpoch,deadline}]});check();
        result=entry?.result?.navigation;
        if(result?.state!=='requested')throw Error(result?.message || '未收到导航结果，请重新分析。');
      }
      let observed;
      // Keep the console active, observe delayed redirects, and continue marking
      // subsequent tab URL changes after this bounded observation window ends.
      for(let i=0;i<8;i++) {
        await new Promise(resolve=>setTimeout(resolve,400));check();
        try {
          const [view]=await chrome.scripting.executeScript({target:{tabId:targetTabId},world:'MAIN',func:AegisReactProbe,args:[{action:'observe'}]});check();
          observed=view?.result;
        }catch(error) {
          check();const current=await chrome.tabs.get(targetTabId);check();
          observed={url:current.pendingUrl || current.url,unconfirmed:true};
        }
        if(!observed || !sameOrigin(observed.url,snapshot.url))break;
      }
      if(!observed)throw Error('导航已请求，但未能读取页面状态；请检查目标页面。');
      const target=displayAddress(result.target);
      if(observed.url!==result.target)navigationStatus(record,loginAddress(observed.url)?
        '跳转未完成：页面已返回登录页；目标 '+target:
        '尚未到达目标地址，页面可能仍在加载，或已阻止、重定向导航；当前 '+displayAddress(observed.url),observed.url,'changed');
      else if(observed.unconfirmed)navigationStatus(record,'地址已到达 '+target+'，页面内容暂无法确认。',observed.url,'unconfirmed');
      else if(result.before.documentEpoch && observed.documentEpoch!==result.before.documentEpoch)navigationStatus(record,'已跳转 '+target+' / 页面重新加载；路由列表已保留。',observed.url,'arrived');
      else if(result.before.signature && observed.signature!==result.before.signature)navigationStatus(record,'已跳转 '+target+' / 观察到页面内容更新；路由列表已保留。',observed.url,'arrived');
      else if(record.method==='地址导航')navigationStatus(record,'已跳转 '+target+' / 地址导航；路由列表已保留。',observed.url,'arrived');
      else navigationStatus(record,'地址已到达 '+target+'，但尚未观察到正文变化；可使用“地址打开”重新加载。',observed.url,'unconfirmed');
    };
    await Promise.race([request(),new Promise((_,reject)=>{timer=setTimeout(()=>{
      expired=true;reject(Error('导航等待超时，尚未确认页面切换；请检查目标页后再试。'));
    },ANALYSIS_TIMEOUT_MS);})]);
  }catch(e){if(active()){if(record)navigationStatus(record,e.message || String(e),record.currentUrl,'error');else status(e.message || String(e));}}
  finally {clearTimeout(timer);if(active()){navigating=false;el('analyze').disabled=false;renderRoutes();}}
}
el('vue').addEventListener('click',()=>{location.href=chrome.runtime.getURL('pages/vue-tools.html?tabId='+targetTabId);});
el('analyze').addEventListener('click',analyze); el('search').addEventListener('input',renderRoutes);
el('export').addEventListener('click',async()=>{
  if(!latest || busy)return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(latest,null,2)],{type:'application/json'}));
  try{await chrome.downloads.download({url,filename:'AegisScope/react-analysis.json',saveAs:true});}catch(e){status(e.message);}finally{setTimeout(()=>URL.revokeObjectURL(url),1500);}
});
function invalidate(message) {
  closeParameters();parameterDrafts.clear();
  generation++;cancelPending?.();cancelPending=null;busy=false;navigating=false;
  clear();el('analyze').disabled=false;renderRoutes();status(message);
}
chrome.tabs.onRemoved.addListener(id=>{if(id===targetTabId)invalidate('目标页面已关闭。');});
chrome.tabs.onUpdated.addListener((id,change,tab)=>{
  if(id!==targetTabId || !(change.status==='loading'||change.url))return;
  const address=change.url || tab?.pendingUrl || tab?.url;
  if(address)el('origin').textContent=address;
  if(!busy && latest && sameOrigin(address,latest.url))retainSnapshot(address);
  else invalidate('目标页面已变化，请重新分析。');
});
analyze();
