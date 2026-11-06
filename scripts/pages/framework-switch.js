document.getElementById('reactTools')?.addEventListener('click', () => {
  const id = new URLSearchParams(location.search).get('tabId') || '';
  location.href = chrome.runtime.getURL('pages/framework-tools.html?tabId=' + encodeURIComponent(id));
});
