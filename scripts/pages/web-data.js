// Executed in the target document's isolated world.
function inspectPage(action, options) {
  if (location.origin !== options.origin) throw new Error('目标站点已变化，请重新打开采集窗口');
  function selector(el) {
    const parts = [];
    while (el && el !== document.documentElement) {
      if (el.id && document.querySelectorAll('#' + CSS.escape(el.id)).length === 1) {
        parts.unshift('#' + CSS.escape(el.id));
        break;
      }
      const siblings = Array.from(el.parentElement.children).filter(n => n.localName === el.localName);
      parts.unshift(el.localName + ':nth-of-type(' + (siblings.indexOf(el) + 1) + ')');
      el = el.parentElement;
    }
    return parts.join(' > ');
  }
  const visible = el => el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden';
  const pagerSelector = '.el-pagination,.ant-pagination,.pagination,.pager,.v-pagination,.MuiPagination-root,[aria-label*="pagination" i],[aria-label*="分页"]';
  function paginationOnly(el) {
    if (el.matches(pagerSelector)) return true;
    const pager = el.querySelector(pagerSelector);
    if (pager && el.textContent.trim() === pager.textContent.trim()) return true;
    const text = el.textContent.trim();
    return text.length < 180 && /^共\s*[\d,]+\s*条/.test(text) &&
      /\d+\s*条\s*\/\s*页/.test(text) && !!el.querySelector('input,select,button,[role="button"]');
  }
  function dataRow(el) {
    return visible(el) && el.textContent.trim() && !/^(SCRIPT|STYLE|BUTTON|OPTION)$/.test(el.tagName) &&
      !(el.localName === 'tr' && Array.from(el.cells).every(cell => cell.localName === 'th')) &&
      !paginationOnly(el);
  }
  if (action === 'find') {
    const candidates = [];
    for (const parent of document.querySelectorAll('tbody,ul,ol,main,section,div,dl,[role="rowgroup"]')) {
      if (parent.closest('nav,body > footer,[role="navigation"],[role="contentinfo"],[role="tablist"],[role="menu"]')) continue;
      if (parent.children.length < (parent.localName === 'tbody' ? 1 : 2) || !visible(parent) || parent.closest(pagerSelector) || paginationOnly(parent)) continue;
      const groups = new Map();
      for (const child of parent.children) {
        if (!dataRow(child)) continue;
        const key = child.localName;
        if (!groups.has(key)) groups.set(key,[]);
        groups.get(key).push(child);
      }
      for (const [tag,items] of groups) {
        const count=items.length;
        if (count < (tag === 'tr' ? 1 : 3)) continue;
        const sample=items.slice(0,5);
        const repeats=sample.filter(el=>el.firstElementChild && el.firstElementChild.localName===sample[0].firstElementChild?.localName && el.childElementCount>=2).length/sample.length;
        const score = (tag === 'tr' ? 1000 : 0) + repeats*80 + Math.min(count,100) + Math.min(parent.clientWidth * parent.clientHeight / 20000,50);
        candidates.push({parent,tag,count,score,first:items[0]});
      }
    }
    const selected=[];
    const recordContainers=new Set();
    for(const area of candidates.sort((a,b)=>b.score-a.score)){
      // One record's internal layout is rarely a separate dataset.
      let ancestor=area.parent;
      while(ancestor && !recordContainers.has(ancestor)) ancestor=ancestor.parentElement;
      if(ancestor && area.tag!=='tr') continue;
      selected.push(area);
      for(const child of area.parent.children) if(child.localName===area.tag) recordContainers.add(child);
      if(selected.length===12) break;
    }
    return selected.map(({parent,tag,count,first})=>{
      const kind=tag==='tr'?'表格':'列表';
      const sample=first.innerText.trim().replace(/\s+/g,' ');
      const title=parent.getAttribute('aria-label') || parent.closest('table')?.caption?.innerText || sample;
      return {path:selector(parent),tag,label:kind+' · '+count+' 行 · '+(title.length>22?title.slice(0,22)+'…':title)};
    });
  }
  const controlSelector='button,a,[role="button"]';
  function identity(el){
    const label=(el.getAttribute('aria-label') || el.title || el.textContent).trim();
    if(label) return [el.localName,'label',label];
    const icon=el.querySelector('i,svg,use,span');
    return [el.localName,'icon',el.getAttribute('rel'),el.className?.toString(),
      icon?.getAttribute('class'),el.querySelector('use')?.getAttribute('href') || el.querySelector('use')?.getAttribute('xlink:href'),
      el.querySelector('svg path')?.getAttribute('d')];
  }
  if (action === 'pick') {
    return new Promise(resolve => {
      function finish(value) {
        clearTimeout(timer);
        document.removeEventListener('click',click,true);
        document.removeEventListener('keydown',key,true);
        resolve(value);
      }
      function key(e) { if(e.key === 'Escape') finish(null); }
      function click(e) {
        e.preventDefault(); e.stopImmediatePropagation();
        const el = e.target.closest(controlSelector) || e.target;
        const scope=el.closest(pagerSelector+',nav,ul,ol') || el.parentElement;
        finish({path:selector(el),scope:selector(scope),signature:JSON.stringify(identity(el)),tag:el.localName});
      }
      const timer=setTimeout(()=>finish(null),30000);
      document.addEventListener('click',click,true);
      document.addEventListener('keydown',key,true);
    });
  }
  const region = document.querySelector(options.area.path);
  if (!region) throw new Error('页面上暂未找到所选区域');
  if (action === 'next') {
    const picked=options.next;
    const scope=document.querySelector(picked.scope);
    if(!scope) return 'missing';
    const matches=Array.from(scope.querySelectorAll(CSS.escape(picked.tag))).filter(el=>
      visible(el) && JSON.stringify(identity(el))===picked.signature);
    // An unlabeled pair of identical arrows cannot be distinguished by position alone.
    if(matches.length!==1) return matches.length?'ambiguous':'missing';
    const el=matches[0];
    if(el.closest(':disabled,[aria-disabled="true"],.disabled,.is-disabled') || getComputedStyle(el).pointerEvents==='none') return 'disabled';
    el.click();
    return 'clicked';
  }
  if (action === 'scroll' || action === 'scrollState') {
    let el=region;
    while(el && !(el.scrollHeight>el.clientHeight && /auto|scroll/.test(getComputedStyle(el).overflowY))) el=el.parentElement;
    el ||= document.scrollingElement;
    const top=el.scrollTop;
    if(action==='scroll') el.scrollTop=top+Math.max(1,Math.floor(el.clientHeight * 0.8));
    const windowed=region!==el && region.getBoundingClientRect().height <= el.clientHeight*3;
    return {top, remaining:Math.max(0,el.scrollHeight-el.clientHeight-top),windowed};
  }
  if(!globalThis.aegisDataOutlineListener){
    globalThis.aegisDataOutlineListener=true;
    chrome.runtime.onConnect.addListener(port=>{
      if(port.name!=='aegis-web-data-outline') return;
      const sheet=new CSSStyleSheet();
      document.adoptedStyleSheets=[...document.adoptedStyleSheets,sheet];
      const frame=document.createElement('aegis-data-outline');
      frame.setAttribute('aria-hidden','true');
      frame.style.cssText='all:initial;position:fixed;display:none;pointer-events:none;box-sizing:border-box;border:3px solid #eb493a;z-index:2147483647';
      document.documentElement.append(frame);
      let parent, pending=0;
      function draw(){
        pending=0;
        if(!parent?.isConnected){frame.style.display='none';return;}
        let {left,top,right,bottom}=parent.getBoundingClientRect();
        left=Math.max(0,left); top=Math.max(0,top);
        right=Math.min(document.documentElement.clientWidth,right);
        bottom=Math.min(document.documentElement.clientHeight,bottom);
        for(let el=parent.parentElement;el;el=el.parentElement){
          const style=getComputedStyle(el);
          if(style.overflowX==='visible' && style.overflowY==='visible') continue;
          const rect=el.getBoundingClientRect();
          const x=rect.left+el.clientLeft,y=rect.top+el.clientTop;
          if(style.overflowX!=='visible'){left=Math.max(left,x);right=Math.min(right,x+el.clientWidth);}
          if(style.overflowY!=='visible'){top=Math.max(top,y);bottom=Math.min(bottom,y+el.clientHeight);}
        }
        Object.assign(frame.style,{display:right>left && bottom>top?'block':'none',left:left+'px',top:top+'px',width:Math.max(0,right-left)+'px',height:Math.max(0,bottom-top)+'px'});
      }
      function schedule(){if(!pending) pending=requestAnimationFrame(draw);}
      const resize=new ResizeObserver(schedule);
      window.addEventListener('scroll',schedule,true);
      window.addEventListener('resize',schedule);
      port.onMessage.addListener(area=>{
        if(!frame.isConnected) document.documentElement.append(frame);
        parent=document.querySelector(area.path);
        resize.disconnect();
        for(let el=parent;el;el=el.parentElement) resize.observe(el);
        schedule();
        const excluded=Array.from(parent?.children || [],(el,i)=>el.localName===area.tag && !dataRow(el)?':nth-child('+(i+1)+')':null).filter(Boolean);
        const row=area.path+' > '+CSS.escape(area.tag)+(excluded.length?':not('+excluded.join(',')+')':'');
        const cells=area.tag==='tr' ? row+' > td' : row;
        sheet.replaceSync(cells+'{box-shadow:inset 0 0 0 100vmax #ffd84d33!important}');
      });
      port.onDisconnect.addListener(()=>{
        resize.disconnect();window.removeEventListener('scroll',schedule,true);window.removeEventListener('resize',schedule);
        cancelAnimationFrame(pending);frame.remove();
        document.adoptedStyleSheets=document.adoptedStyleSheets.filter(s=>s!==sheet);
      });
    });
  }
  const result=[];
  // Only the path inside each record identifies a field; optional siblings may disappear.
  function fieldPath(node,row){
    const path=[];
    while(node && node!==row){
      const semantic=node.getAttribute('itemprop') || node.getAttribute('data-field');
      const classes=Array.from(node.classList).filter(name=>! /^(?:active|selected|disabled|hidden|is-|has-)/i.test(name)).sort();
      path.unshift(semantic || [node.localName,...classes].join('.'));
      node=node.parentElement;
    }
    return path.join(' / ') || '文本';
  }
  function cardField(owner,row,value){
    // Reuse explicit field identities even if a theme inserts a wrapper on some rows.
    const marked=owner.closest('[data-field],[itemprop]');
    const declared=marked && row.contains(marked) && (marked.getAttribute('data-field') || marked.getAttribute('itemprop'));
    if(declared) return [declared,value];
    const definition=owner.closest('dd');
    const term=definition?.previousElementSibling;
    if(term?.localName==='dt' && row.contains(term) && term.innerText.trim()) return [term.innerText.trim(),value];
    const inline=/^([\p{L}][\p{L}\p{N} _-]{0,23})[：:]\s*(\S[\s\S]*)$/u.exec(value);
    if(inline && !inline[2].startsWith('//')) return [inline[1].trim(),inline[2]];
    const path=fieldPath(owner,row);
    const semanticOwner=owner.closest('a,h1,h2,h3,h4,h5,h6,strong,b');
    if(path.includes('.') || (semanticOwner && row.contains(semanticOwner))) return [path,value];
    if(/^(?:[¥￥$€£]\s*[+-]?\d[\d,]*(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?\s*(?:元|USD|CNY|EUR))$/i.test(value)) return ['金额文本',value];
    if(/^\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?$/.test(value)) return ['日期文本',value];
    return ['未标注文本（原序）',value];
  }
  const table=region.closest('table');
  const firstRow=table?.rows[0];
  const headings=Array.from(table?.tHead?.rows || []).at(-1) ||
    (firstRow?.cells.length && Array.from(firstRow.cells).every(c=>c.tagName==='TH') ? firstRow : null);
  const headers=headings?.cells;
  for(const row of region.children) {
    if(row.localName !== options.area.tag || !dataRow(row)) continue;
    const values=Object.create(null);
    const cells=row.localName === 'tr' ? Array.from(row.cells) : Array.from(row.children);
    const usedFields=new Set();
    (cells.length && row.localName==='tr' ? cells : [row]).forEach((cell,index)=>{
      const base=headers?.[index]?.innerText.trim() || (row.localName==='tr'?'列 '+(index+1):'文本');
      let field=base,occurrence=1;
      while(usedFields.has(field) || Object.hasOwn(values,field)) field=base+' ('+(++occurrence)+')';
      usedFields.add(field);
      if(row.localName==='tr') values[field]=cell.innerText.trim();
      else {
        const walker=document.createTreeWalker(cell,NodeFilter.SHOW_TEXT);
        let textNode;
        while((textNode=walker.nextNode())) {
          const value=textNode.textContent.trim(), owner=textNode.parentElement;
          if(value && !owner.closest('script,style,template') && visible(owner)){
            const term=owner.closest('dt');
            if(term?.nextElementSibling?.localName==='dd' && visible(term.nextElementSibling) && term.nextElementSibling.innerText.trim()) continue;
            const [key,text]=cardField(owner,row,value);
            values[key]=values[key] ? values[key]+'\n'+text : text;
          }
        }
      }
      for(const [sel,attr,label] of [['a[href]','href','链接'],['img[src],img[srcset]','src','图片']]) {
        const nodes=[...(cell.matches(sel)?[cell]:[]),...cell.querySelectorAll(sel)].filter(visible);
        nodes.forEach((node,i)=>{
          const key=row.localName==='tr' ? field+' '+label+(i?' '+(i+1):'') : fieldPath(node,row)+' '+label;
          const value=node.currentSrc || node[attr];
          values[key]=values[key] ? values[key]+'\n'+value : value;
        });
      }
    });
    if(Object.keys(values).length) result.push(Object.entries(values));
  }
  return result;
}

const $=id=>document.getElementById(id);
const tabId=Number(new URLSearchParams(location.search).get('tabId'));
let origin='', areas=[], next=null, rows=[], seen=new Set(), columns=[], hidden=new Set(), names=new Map();
let running=false, busy=false, batches=0, stopping=false;
let lastAdded=0,elapsedMs=0,startedAt=0;
const widths=new Map();
let finishWait=null;
function wait(ms){
  return new Promise(resolve=>{
    const done=()=>{clearTimeout(timer);finishWait=null;resolve();};
    const timer=setTimeout(done,ms);
    finishWait=done;
  });
}
let outline=null,outlineDocument='';
function clearOutline(){outline?.disconnect();outline=null;}
window.addEventListener('pagehide',clearOutline);
async function page(action, extra={}) {
  const args={origin,area:areas[$('area').selectedIndex] || null,next,...extra};
  const [response]=await chrome.scripting.executeScript({target:{tabId},func:inspectPage,args:[action,args]});
  if (response?.result==null && action!=='pick') throw new Error('目标页无法读取或页面已变化');
  if(action==='read'){
    if(!outline || outlineDocument!==response.documentId){
      clearOutline();
      outlineDocument=response.documentId;
      const port=chrome.tabs.connect(tabId,{documentId:outlineDocument,name:'aegis-web-data-outline'});
      outline=port;
      port.onDisconnect.addListener(()=>{if(outline===port) outline=null;});
    }
    outline.postMessage(args.area);
  }
  return response?.result;
}
function status(message){$('status').textContent=message;}
function controls(){
  for(const id of ['area','refresh','pick','mode','delay','timeout']) $(id).disabled=busy || running;
  $('pick').disabled ||= $('mode').value==='scroll' || !areas.length;
  $('pageInterval').disabled=busy || running || $('mode').value==='scroll';
  $('start').disabled=busy || running || !areas.length || ($('mode').value==='next' && !next);
  $('stop').disabled=!running;
  for(const id of ['copy','xlsx','csv']) $(id).disabled=!rows.length || !columns.some(k=>!hidden.has(k));
}
function clear(){
  rows=[];seen.clear();columns=[];hidden.clear();names.clear();widths.clear();batches=0;lastAdded=0;elapsedMs=0;
}
function columnLabel(key){
  const parts=key.split(' / ');
  const suffix=key.match(/ (链接|图片)$/)?.[0] || '';
  for(const part of parts.reverse()){
    const [tag,...classes]=part.replace(/ (链接|图片)$/,'').split('.');
    if(!/^(?:div|span|a|p|section|strong|b|i|img|time|pre|h[1-6]|li)$/.test(tag)) return part;
    const name=classes.filter(c=>!/^((?:margin|padding)-|(?:el|ant)-|common-tag$|ellipsis$|ellipse-text$|flex$)/i.test(c)).at(-1);
    if(name) return name+suffix;
    if(tag==='time') return '时间'+suffix;
    if(tag==='pre') return '预格式文本'+suffix;
    if(/^h[1-6]$/.test(tag)) return '标题'+suffix;
  }
  return suffix.trim() || '文本';
}
function append(batch){
  let added=0;
  for(const entries of batch){
    const row=Object.assign(Object.create(null),Object.fromEntries(entries));
    const key=JSON.stringify([...entries].sort(([a],[b])=>a.localeCompare(b)));
    if(seen.has(key)) continue;
    seen.add(key);rows.push(row);added++;
    for(const [key] of entries) if(!columns.includes(key)){
      columns.push(key);
      const base=areas[$('area').selectedIndex]?.tag==='tr'?key:columnLabel(key);
      let label=base, suffix=1;
      while([...names.values()].includes(label)) label=base+' ('+(++suffix)+')';
      names.set(key,label);
    }
  }
  if(added){batches++;lastAdded=added;}
  return added;
}
function render(){
  const keys=columns.filter(k=>!hidden.has(k));
  const head=document.querySelector('thead'), body=document.querySelector('tbody');
  head.replaceChildren();body.replaceChildren();
  const tr=head.insertRow();
  for(const k of keys){
    const th=document.createElement('th'),input=document.createElement('input'),btn=document.createElement('button');
    input.value=names.get(k)||k; input.title='修改列名';input.onchange=()=>names.set(k,input.value.trim()||k);
    btn.textContent='×';btn.title='隐藏此列';btn.onclick=()=>{hidden.add(k);render();};
    const grip=document.createElement('button');
    grip.className='resize';grip.textContent='↔';grip.title='拖动调整列宽，或用左右方向键微调';
    input.style.width=(widths.get(k)||130)+'px';
    const resize=w=>{const width=Math.min(800,Math.max(64,w));widths.set(k,width);input.style.width=width+'px';};
    grip.onpointerdown=e=>{
      const left=e.clientX,initial=parseFloat(input.style.width);
      grip.setPointerCapture(e.pointerId);
      grip.onpointermove=ev=>resize(initial+ev.clientX-left);
      grip.onlostpointercapture=()=>{grip.onpointermove=null;};
    };
    grip.onkeydown=e=>{
      if(['ArrowLeft','ArrowRight'].includes(e.key)){e.preventDefault();resize(parseFloat(input.style.width)+(e.key==='ArrowRight'?12:-12));}
    };
    th.append(input,btn,grip);tr.append(th);
  }
  for(const row of rows.slice(0,1000)){
    const tr=body.insertRow();
    for(const k of keys){
      const preview=document.createElement('div');
      preview.className='cell-preview';
      preview.textContent=row[k]||'';
      preview.title=preview.textContent;
      tr.insertCell().append(preview);
    }
  }
  const seconds=Math.floor((elapsedMs+(startedAt?performance.now()-startedAt:0))/1000);
  $('stats').textContent='共 '+rows.length+' 行 · '+keys.length+' 列 · '+batches+' 批 · 最近新增 '+lastAdded+' 行 · 耗时 '+seconds+' 秒'+(rows.length>1000?' · 预览前 1000 行':'');
  controls();
}
async function loadArea(){
  const batch=await page('read',{highlight:true});
  clear();next=null;append(batch);render();status('已读取当前区域。');
}
async function refresh(){
  const found=await page('find');
  areas=found;$('area').replaceChildren(...found.map((a,i)=>new Option(a.label,String(i))));
  if(found.length) await loadArea(); else {clearOutline();clear();next=null;render();status('当前页面未找到可提取的表格或重复列表。');}
}
async function crawl(){
  const min=Number($('delay').value)*1000,max=Number($('timeout').value)*1000;
  const interval=$('mode').value==='next'?$('pageInterval').valueAsNumber*1000:0;
  if(!Number.isFinite(interval)||interval<0) throw new Error('翻页间隔请填写大于或等于 0 的秒数。');
  let nextClickAt=performance.now()+interval;
  if(!Number.isFinite(min)||!Number.isFinite(max)||min<200||max<min) throw new Error('最短等待至少 0.2 秒，最长等待应大于或等于最短等待。');
  running=true;stopping=false;startedAt=performance.now();controls();
  try {
    // A page requested before Stop may have finished loading in the meantime.
    if(append(await page('read'))) render();
    while(!stopping){
      status('采集中，已收集 '+rows.length+' 行…');
      const scrolling=$('mode').value==='scroll';
      let before;
      if(scrolling) before=await page('scroll');
      else {
        while(!stopping && performance.now()<nextClickAt){
          const remaining=nextClickAt-performance.now();
          status('距下次翻页约 '+Math.ceil(remaining/1000)+' 秒，已收集 '+rows.length+' 行。');
          await wait(Math.min(1000,Math.max(1,remaining)));
        }
        if(stopping) break;
        const deadline=Date.now()+max;
        do {
          before=await page('next');
          if(before==='clicked') nextClickAt=performance.now()+interval;
          if(before==='clicked' || stopping) break;
          const remaining=deadline-Date.now();
          if(remaining<=0) break;
          status('等待分页栏更新…');
          await wait(Math.min(500,remaining));
        }while(!stopping);
      }
      if(stopping) break;
      if(!scrolling && before!=='clicked'){
        status(before==='disabled'?'下一页按钮持续禁用，已停止翻页。':'无法唯一定位所选下一页按钮，请重新选取。已保留采集结果。');
        return;
      }
      const until=Date.now()+max;let added=0,canAdvance=false;
      do {
        await wait(Math.min(min,Math.max(0,until-Date.now())));
        if(stopping) break;
        const tab=await chrome.tabs.get(tabId);
        if(new URL(tab.url).origin!==origin) throw new Error('目标站点已变化，已保留采集结果。');
        if(tab.status!=='loading'){
          try{
            const batch=await page('read');
            if(stopping) break;
            added=append(batch);
            if(scrolling && !added){
              const pos=await page('scrollState');
              canAdvance=!pos.windowed && pos.remaining>1 && (pos.top>before.top || pos.remaining>before.remaining);
              // A background tab may dispatch scroll/render well after scrollTop changes.
              // Give a windowed list its full read interval before moving its viewport again.
              if(canAdvance) break;
            }
          }catch(err){if(Date.now()>=until)throw err;}
        }
        if(added){render();break;}
      }while(Date.now()<until);
      if(!added && !canAdvance && !stopping){status('等待结束，未发现新行。已有数据可继续导出。');return;}
    }
    status('已停止采集。');
  }finally{elapsedMs+=performance.now()-startedAt;startedAt=0;running=false;render();}
}
function delimited(matrix,delimiter){
  return matrix.map(row=>row.map(value=>{
    // Keep spreadsheet programs from executing formulas copied from the page.
    const text=/^[\s]*[=+@-]/.test(value) ? "'"+value : value;
    if(/[\r\n"]/.test(text)||text.includes(delimiter)) return '"'+text.replaceAll('"','""')+'"';
    return text;
  }).join(delimiter)).join('\r\n');
}
function workbook(matrix){
  const xml=value=>String(value).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]/g,'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
  const main='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const rel='http://schemas.openxmlformats.org/officeDocument/2006/relationships';
  const links=(type,target)=>'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="'+rel+'/'+type+'" Target="'+target+'"/></Relationships>';
  const items={
    '[Content_Types].xml':'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
    '_rels/.rels':links('officeDocument','xl/workbook.xml'),
    'xl/workbook.xml':'<workbook xmlns="'+main+'" xmlns:r="'+rel+'"><sheets><sheet name="网页数据" sheetId="1" r:id="rId1"/></sheets></workbook>',
    'xl/_rels/workbook.xml.rels':links('worksheet','worksheets/sheet1.xml'),
    'xl/worksheets/sheet1.xml':'<worksheet xmlns="'+main+'"><sheetData>'+matrix.map(row=>'<row>'+row.map(v=>'<c t="inlineStr"><is><t xml:space="preserve">'+xml(v)+'</t></is></c>').join('')+'</row>').join('')+'</sheetData></worksheet>'
  };
  return createZip(Object.entries(items).map(([name,content])=>({name,data:new TextEncoder().encode(content)})),
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
}
async function output(format){
  const keys=columns.filter(k=>!hidden.has(k));
  const matrix=[keys.map(k=>names.get(k)||k),...rows.map(row=>keys.map(k=>row[k]||''))];
  if(format==='copy'){await navigator.clipboard.writeText(delimited(matrix,'\t'));status('已复制 '+rows.length+' 行。');return;}
  const blob=format==='csv'?new Blob(['\ufeff',delimited(matrix,',')],{type:'text/csv;charset=utf-8'}):workbook(matrix);
  const url=URL.createObjectURL(blob);
  try{await chrome.downloads.download({url,filename:new URL(origin).hostname+'-网页数据.'+format,saveAs:true});}
  finally{setTimeout(()=>URL.revokeObjectURL(url),60000);}
}
async function perform(fn){
  if(busy)return;
  busy=true;controls();
  try{await fn();}catch(err){status(err.message||String(err));}finally{busy=false;controls();}
}
$('refresh').onclick=()=>perform(refresh);
$('area').onchange=()=>perform(loadArea);
$('mode').onchange=controls;
$('pick').onclick=()=>perform(async()=>{
  const self=await chrome.tabs.getCurrent();
  status('请在原页面点击下一页按钮，按 Esc 取消。');
  await chrome.tabs.update(tabId,{active:true});
  try{next=await page('pick');status(next?'已选取下一页按钮。':'已取消选取。');}
  finally{if(self?.id)await chrome.tabs.update(self.id,{active:true});}
});
$('start').onclick=()=>perform(crawl);
$('stop').onclick=()=>{stopping=true;finishWait?.();status('正在停止…');};
$('reset').onclick=()=>{names.clear();hidden.clear();widths.clear();render();};
for(const format of ['xlsx','csv','copy']) $(format).onclick=()=>output(format).catch(err=>status(err.message));
perform(async()=>{
  const tab=await chrome.tabs.get(tabId);
  if(!/^https?:\/\//i.test(tab.url))throw new Error('请在 HTTP 或 HTTPS 网页上打开此工具。');
  origin=new URL(tab.url).origin;$('source').textContent=tab.url;await refresh();
});
