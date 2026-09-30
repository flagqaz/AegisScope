// Tab-scoped charset overrides. Rules themselves are the durable session state.
// Design reference: Chrome-Charset (MIT); see docs/third-party/Chrome-Charset-LICENSE.txt.
(() => {
  const FIRST = 340000, LAST = 349999;
  // UA exceptions use priority 99. They must not suppress an explicit charset choice.
  const PRIORITY = 100;
  const MIME_TYPES = ['text/html', 'application/xhtml+xml', 'text/plain', 'text/xml', 'application/xml'];
  let pending = Promise.resolve();
  let headerConditionsSupported = null;
  const EXACT_SUFFIX = '(?:#.*)?$';
  function serialize(work) {
    const result = pending.then(work);
    pending = result.catch(() => {});
    return result;
  }
  const owned = (rule) => rule.id >= FIRST && rule.id <= LAST;
  const forTab = (rule, tabId) => owned(rule) && rule.condition.tabIds?.includes(tabId);
  function originOf(url) {
    try { const u = new URL(url); return /^https?:$/.test(u.protocol) ? u.origin : ''; } catch { return ''; }
  }
  function documentUrl(url) {
    try { const u = new URL(url);u.hash = '';return u.href; } catch { return ''; }
  }
  function exactPattern(url) {
    return '^' + documentUrl(url).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + EXACT_SUFFIX;
  }
  function exactRuleUrl(rule) {
    const pattern = rule?.condition.regexFilter || '';
    return pattern.slice(1, pattern.endsWith(EXACT_SUFFIX) ? -EXACT_SUFFIX.length : -1).replace(/\\([.*+?^${}()|[\]\\])/g, '$1');
  }
  function setting(rules, tabId) {
    const group = rules.filter((rule) => forTab(rule, tabId));
    const modern = group.find((item) => item.condition.responseHeaders);
    const rule = modern || group.find((item) => item.condition.resourceTypes?.includes('main_frame'));
    const pageUrl = modern ? '' : exactRuleUrl(rule);
    const value = rule?.action.responseHeaders?.find((item) => item.header === 'content-type')?.value || '';
    return {
      encoding: /charset=([^;]+)/i.exec(value)?.[1] || '',
      origin: modern ? rule.condition.urlFilter.slice(1, -1) : originOf(pageUrl),
      pageUrl,
      mode: rule ? modern ? 'site' : 'page' : '',
      includeFrames: group.some((item) => item.condition.resourceTypes?.includes('sub_frame')),
      ruleCount: group.length
    };
  }
  async function inspect(tabId) {
    const tab = await chrome.tabs.get(tabId);
    const origin = originOf(tab.url);
    if (!origin) return { url: tab.url || '', origin: '', supported: false, reason: '仅支持 HTTP/HTTPS 网页；浏览器内置页和本地文件无法修改响应编码。' };
    try {
      const [entry] = await chrome.scripting.executeScript({
        target: { tabId },
        func: () => ({ encoding: document.characterSet, contentType: document.contentType, url: location.href })
      });
      const page = entry?.result;
      if (!page || originOf(page.url) !== origin) throw new Error('页面已切换，请重新读取');
      const mime = String(page.contentType || '').split(';')[0].toLowerCase();
      return { ...page, origin, contentType: mime, supported: MIME_TYPES.includes(mime), reason: MIME_TYPES.includes(mime) ? '' : '当前内容不是可修改编码的 HTML、纯文本或 XML 页面。' };
    } catch (error) {
      return { url: tab.url, origin, supported: false, reason: `无法读取页面：${error.message}` };
    }
  }
  async function getState(tabId) {
    await pending;
    const [page, rules] = await Promise.all([inspect(tabId), chrome.declarativeNetRequest.getSessionRules()]);
    const config = setting(rules, tabId);
    return { ok: true, page, ...config, enabled: !!config.encoding && config.origin === page.origin &&
      (config.mode !== 'page' || config.pageUrl === documentUrl(page.url)) };
  }
  async function remove(tabId) {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const ids = rules.filter((rule) => forTab(rule, tabId)).map((rule) => rule.id);
    if (ids.length) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids });
    return ids.length;
  }
  function setEncoding(tabId, encoding, includeFrames = false, expectedUrl) {
    return serialize(async () => {
      if (!Number.isInteger(tabId) || tabId < 0) throw new Error('目标标签页无效');
      if (!globalThis.AEGISSCOPE_CHARSETS.some(([value]) => value === encoding)) throw new Error('不支持的编码');
      const page = await inspect(tabId);
      if (!page.supported) throw new Error(page.reason);
      if (expectedUrl && expectedUrl !== page.url) throw new Error('目标页面已变化，请重新读取编码后应用');
      const rules = await chrome.declarativeNetRequest.getSessionRules();
      const removed = rules.filter((rule) => forTab(rule, tabId)).map((rule) => rule.id);
      const used = new Set(rules.filter((rule) => !removed.includes(rule.id)).map((rule) => rule.id));
      let next = FIRST;
      const allocate = () => {
        while (used.has(next) && next <= LAST) next++;
        if (next > LAST) throw new Error('编码规则数量已达上限，请先恢复其他标签页的默认编码');
        used.add(next);return next++;
      };
      const condition = { tabIds: [tabId], urlFilter: `|${page.origin}/`, resourceTypes: includeFrames ? ['main_frame', 'sub_frame'] : ['main_frame'] };
      const action = (mime) => ({ type: 'modifyHeaders', responseHeaders: [{ header: 'content-type', operation: 'set', value: `${mime}; charset=${encoding}` }] });
      const addRules = MIME_TYPES.map((mime) => ({
        id: allocate(), priority: PRIORITY, action: action(mime),
        condition: { ...condition, responseHeaders: [{ header: 'content-type', values: [mime, `${mime};*`, `${mime} ;*`] }] }
      }));
      // If the current document was sniffed without Content-Type, limit the fallback
      // to its exact URL. Never turn another untyped response into HTML by accident.
      addRules.push({
        id: allocate(), priority: PRIORITY, action: action(page.contentType),
        condition: { tabIds: [tabId], resourceTypes: ['main_frame'],
          regexFilter: exactPattern(page.url), isUrlFilterCaseSensitive: true,
          excludedResponseHeaders: [{ header: 'content-type' }] }
      });
      const current = await chrome.tabs.get(tabId);
      if (current.url !== page.url) throw new Error('目标页面已变化，请重新读取编码后应用');
      if (headerConditionsSupported !== false) {
        try {
          await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: removed, addRules });
          headerConditionsSupported = true;
        } catch (error) {
          // Only unsupported schema fields trigger fallback. Quota/permission errors
          // must remain errors, and an atomic failed update preserves existing rules.
          const message = error.message || String(error);
          if (!/responseHeaders|excludedResponseHeaders/i.test(message) ||
              !/Unexpected property|Unknown|not supported|unsupported|Invalid.*condition/i.test(message)) throw error;
          headerConditionsSupported = false;
        }
      }
      if (headerConditionsSupported === false) {
        const legacy = [{ url: page.url, contentType: page.contentType, resourceType: 'main_frame' }];
        if (includeFrames) {
          const frames = await chrome.scripting.executeScript({
            target: { tabId, allFrames: true },
            func: () => ({ url: location.href, contentType: document.contentType })
          }).catch(() => []);
          for (const frame of frames) {
            const data = frame.result;
            if (frame.frameId === 0 || originOf(data?.url) !== page.origin || !MIME_TYPES.includes(data?.contentType)) continue;
            if (!legacy.some((item) => item.resourceType === 'sub_frame' && documentUrl(item.url) === documentUrl(data.url))) {
              legacy.push({ ...data, resourceType: 'sub_frame' });
            }
          }
        }
        const tab = await chrome.tabs.get(tabId);
        if (tab.url !== page.url) throw new Error('目标页面已变化，请重新读取编码后应用');
        // Old engines cannot match response MIME. Pin each previously inspected
        // document URL (including query) and retain its detected MIME, never a site-wide HTML rule.
        const fallback = legacy.map((doc) => ({
          id: allocate(), priority: PRIORITY, action: action(doc.contentType),
          condition: { tabIds: [tabId], resourceTypes: [doc.resourceType],
            regexFilter: exactPattern(doc.url), isUrlFilterCaseSensitive: true }
        }));
        await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: removed, addRules: fallback });
      }
      try { await chrome.tabs.reload(tabId, { bypassCache: true }); }
      catch (error) { return { ok: true, encoding, warning: `编码已设置，刷新失败：${error.message}。请手动刷新。` }; }
      return { ok: true, encoding, reloading: true };
    });
  }
  function reset(tabId) {
    return serialize(async () => {
      await remove(tabId);
      try { await chrome.tabs.reload(tabId, { bypassCache: true }); }
      catch (error) { return { ok: true, warning: `已恢复默认规则，刷新失败：${error.message}。请手动刷新。` }; }
      return { ok: true, reloading: true };
    });
  }
  chrome.tabs.onRemoved.addListener((tabId) => { serialize(() => remove(tabId)).catch(() => {}); });
  chrome.tabs.onUpdated.addListener((tabId, change) => {
    if (!change.url) return;
    serialize(async () => {
      const config = setting(await chrome.declarativeNetRequest.getSessionRules(), tabId);
      // Read the latest URL inside the queue, not a stale navigation event.
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (config.encoding && (config.origin !== originOf(tab?.url) ||
          (config.mode === 'page' && config.pageUrl !== documentUrl(tab?.url)))) await remove(tabId);
    }).catch(() => {});
  });
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!['GET_CHARSET_STATE', 'SET_CHARSET', 'RESET_CHARSET'].includes(message?.type)) return;
    const work = message.type === 'GET_CHARSET_STATE' ? getState(message.tabId) :
      message.type === 'SET_CHARSET' ? setEncoding(message.tabId, message.encoding, !!message.includeFrames, message.expectedUrl) : reset(message.tabId);
    work.then(sendResponse, (error) => sendResponse({ ok: false, error: error.message }));
    return true;
  });
  globalThis.AegisCharset = { getState, setEncoding, reset };
})();
