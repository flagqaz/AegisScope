// Passive source analysis only. No network access or execution of page code.
const window = self;
let sniffRunSeq = 0;
importScripts('../../rules/sniff-rules.js');
let ruleCoverage = [];
try { importScripts('../../rules/sniff-rules-webtech.js'); }
catch { ruleCoverage = ['扩展规则加载失败，仅完成基础规则分析']; }
importScripts('sniff-engine.js');
self.onmessage = async ({ data }) => {
  const { id, signals } = data;
  const run = ++sniffRunSeq;
  let sent = 0;
  try {
    const detected = await analyzeSniffSignalsCooperatively(signals, run, partial => {
      if (partial.length > sent) {
        self.postMessage({ id, type: 'progress', detected: partial.slice(sent) });
        sent = partial.length;
      }
    });
    self.postMessage({ id, type: 'done', detected, coverage: ruleCoverage });
  } catch (error) {
    self.postMessage({ id, type: 'error', error: String(error?.message || error) });
  }
};
