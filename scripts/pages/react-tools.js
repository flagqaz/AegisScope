const targetTabId = Number(new URLSearchParams(location.search).get('tabId'));
const el = id => document.getElementById(id);
let latest = null, busy = false, generation = 0;
let cancelPending = null;
const ANALYSIS_TIMEOUT_MS = 12000;
const status = message => { el('status').textContent = message; };
function list(id, items) {
  el(id).replaceChildren(...items.map(text => { const li=document.createElement('li'); li.textContent=text; return li; }));
}
function clear() {
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
  status('已保留上次采集的路由，可继续打开；点击“分析实例”可更新结果。');
}
function renderRoutes() {
  const keyword=el('search').value.trim().toLowerCase();
  const items=[...(latest?.routes || []), ...(latest?.links || [])].filter(x=>(x.path+' '+x.source).toLowerCase().includes(keyword));
  el('routes').replaceChildren(...items.map(item=>{
    const row=document.createElement('div'); row.className='react-row route';
    const content=document.createElement('div'), name=document.createElement('strong'), detail=document.createElement('small');
    name.className='path'; detail.className='meta';
    name.textContent=item.path; detail.textContent=item.source+(item.url?' · '+item.url:' · 需要具体参数'); content.append(name,detail);
    const button=document.createElement('button'); button.textContent='打开'; button.disabled=!item.url || busy;
    button.addEventListener('click',()=>openRoute(item.url)); row.append(content,button); return row;
  }));
  if(!items.length) { const empty=document.createElement('p'); empty.className='empty'; empty.textContent='没有可展示的路由或链接。'; el('routes').append(empty); }
}
async function analyze() {
  if(busy)return;
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
async function openRoute(address) {
  if(!latest || busy)return;
  const snapshot=latest, token=generation;
  try {
    const tab=await chrome.tabs.get(targetTabId), url=new URL(address);
    if(snapshot!==latest || token!==generation || busy)return;
    if(!sameOrigin(tab.pendingUrl || tab.url,snapshot.url)) {
      invalidate('目标页面已切换到其他站点，请重新分析。'); return;
    }
    if(!sameOrigin(url.href,snapshot.url))throw Error('地址无效，请重新分析。');
    await chrome.tabs.update(targetTabId,{url:url.href,active:true});
    if(snapshot===latest && token===generation && !latest.snapshot.stale)
      status('已请求打开地址，路由列表保留；实际页面和访问权限由网站处理。');
  }catch(e){if(snapshot===latest && token===generation)status(e.message || String(e));}
}
el('vue').addEventListener('click',()=>{location.href=chrome.runtime.getURL('pages/vue-tools.html?tabId='+targetTabId);});
el('analyze').addEventListener('click',analyze); el('search').addEventListener('input',renderRoutes);
el('export').addEventListener('click',async()=>{
  if(!latest || busy)return;
  const url=URL.createObjectURL(new Blob([JSON.stringify(latest,null,2)],{type:'application/json'}));
  try{await chrome.downloads.download({url,filename:'AegisScope/react-analysis.json',saveAs:true});}catch(e){status(e.message);}finally{setTimeout(()=>URL.revokeObjectURL(url),1500);}
});
function invalidate(message) {
  generation++;cancelPending?.();cancelPending=null;busy=false;
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
