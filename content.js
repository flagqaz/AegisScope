(function collectScripts() {
  const items = [];
  const inline = [];

  for (const el of document.querySelectorAll('script')) {
    const src = el.src || el.getAttribute('src');
    if (src) {
      items.push({ url: src, async: el.async, defer: el.defer, type: el.type || 'text/javascript' });
    } else if (el.textContent && el.textContent.trim().length) {
      const content = el.textContent;
      inline.push({
        hash: hashString(content),
        length: content.length,
        content: content.length > 200000 ? content.slice(0, 200000) + '\n/* ...truncated */' : content
      });
    }
  }

  chrome.runtime.sendMessage({
    type: 'CONTENT_SCRIPTS_FOUND',
    items,
    inline
  });

  function hashString(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (h * 31 + str.charCodeAt(i)) | 0;
    }
    return (h >>> 0).toString(16);
  }
})();
