// Isolated static analysis. Terminating this worker cancels even a running regexp.
importScripts('../../rules/rules.js', 'analyzer.js');
self.onmessage = ({ data }) => {
  try {
    const result = self.JS_EXTRACTOR_ANALYZER.analyzeSource(data.source, data.meta);
    reviewStaticEvidence(result, data.source);
    self.postMessage({ result });
  } catch (error) {
    self.postMessage({ error: error?.message || String(error) });
  }
};

function reviewStaticEvidence(result, source) {
  const firebaseKeys = new Set(result.findings.filter(f => f.ruleId === 'firebase-config-exposure').map(f => f.captured));
  for (const f of result.findings) {
    const note = (reason, severity = 'info', name) => {
      f.confidence = 'suspected'; f.severity = severity;
      f.evidence = reason;
      if (name) f.ruleName = name;
      f.description = reason;
      f.exploit = '';
      f.recommendation = '结合实际权限和业务用途核验，不应仅凭此静态线索判定漏洞。';
    };
    if (f.ruleId === 'aws-access-key-id') {
      if (!/^(?:AKIA|ASIA)/.test(f.match)) {
        note('匹配的是 IAM 实体标识符，不是访问密钥。', 'info', 'AWS IAM 标识符');
      } else {
        f.severity = 'high'; f.confidence = 'likely';
        f.description = '检测到 AWS 访问密钥 ID 格式；仅有 ID 不能用于认证，尚未验证有效性或配套凭据。';
        f.exploit = '';
      }
    }
    if (f.ruleId === 'firebase-config-exposure') {
      note('Firebase Web 配置通常用于公开客户端；数据权限由 Security Rules 等机制决定，配置出现本身不证明泄露。', 'info', 'Firebase 公开客户端配置');
    }
    if (f.ruleId === 'gcp-api-key') {
      if (firebaseKeys.has(f.match)) note('该 Key 同时出现在 Firebase 公开客户端配置中，未验证 API 限制或数据访问权限。', 'info', 'Firebase 客户端 API Key');
      else { f.confidence = 'likely'; f.evidence = '符合 Google API Key 格式；是否有效及是否缺少使用限制均未验证。'; }
    }
    if (f.ruleId === 'pem-private-key') {
      const endMarker = f.match.replace('BEGIN', 'END');
      const end = source.indexOf(endMarker, f.offset + f.match.length);
      const body = end < 0 ? '' : source.slice(f.offset + f.match.length, end).trim();
      if (end < 0 || end - f.offset > 8192 || !/^[A-Za-z0-9+/=\s]{80,}$/.test(body)) {
        note('PEM 头尾类型不匹配或内容格式不完整，尚不能确认是私钥。', 'medium');
      } else {
        f.match = source.slice(f.offset, end + endMarker.length); f.captured = f.match;
        f.context.match = f.match; f.context.after = source.slice(end + endMarker.length, end + endMarker.length + 800);
        f.evidence = 'PEM 头尾类型匹配且包含 base64 数据；密钥结构、有效性及实际使用情况未验证。';
        f.confidence = 'likely';
        f.description = '检测到私钥格式的数据块，需要核验其实际用途并评估是否轮换。';
        f.exploit = '';
      }
    }
    if (f.ruleId === 'supabase-service-role-key') {
      try {
        const payload = JSON.parse(b64urlToStr(String(f.captured).split('.')[1]));
        if (payload.role === 'anon') note('JWT 声明为 anon 公开客户端角色，不是 service_role 管理密钥。', 'info', 'Supabase anon 客户端密钥');
        else if (payload.role !== 'service_role') note('变量名类似 service_role，但 JWT 未声明 service_role；需要核验实际用途。', 'medium');
        else f.evidence = 'JWT 声明 role=service_role；签名和服务端接受情况未验证。';
      } catch { note('JWT 载荷无法解析，不能确认其为 service_role 密钥。', 'medium'); }
    }
    // Preserve potential evidence; explicit example placeholders lower confidence rather than disappear.
    if (f.category === 'secret' && /(?:EXAMPLE|YOUR[_-](?:API[_-]?)?KEY|REPLACE[_-]ME)/i.test(String(f.captured))) {
      note('命中内容含明确示例/占位标记，保留线索但不作为高置信泄露。', 'low');
    }
  }
  result.stats.bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  result.stats.byConfidence = { confirmed: 0, likely: 0, suspected: 0 };
  for (const f of result.findings) {
    result.stats.bySeverity[f.severity]++;
    result.stats.byConfidence[f.confidence]++;
  }
}
