// 安全扫描规则库 — 以"可利用漏洞"为目标
//
// 每条规则:
//   id, name, category, severity, regex
//   confidence: 'confirmed' | 'likely' | 'suspected'  默认信心
//   description, exploit, recommendation
//   validate?(ctx) -> null | { confidence?, severity?, evidence?, drop?: true }
//     - drop:true 表示该匹配是误报，丢弃
//     - 返回 null 视为通过，使用默认 confidence/severity
//   contextRequire?: RegExp     ±contextWindow 字符内必须出现
//   contextDeny?:    RegExp     ±contextWindow 字符内出现则丢弃
//   contextWindow?:  number     默认 240
//
// 过滤策略：默认仅展示 confirmed + likely；suspected 需用户开启开关
//
// 不进入 findings 的「页面元信息」类规则放在 META_RULES，
// 仅用于「加密栈/信息暴露」面板展示。

// ---------- 工具函数 ----------

function b64urlToStr(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try {
    const bin = atob(s);
    try { return decodeURIComponent(escape(bin)); } catch { return bin; }
  } catch { return null; }
}

function luhnOk(num) {
  const d = String(num).replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function shannonEntropy(str) {
  if (!str) return 0;
  const f = {};
  for (const c of str) f[c] = (f[c] || 0) + 1;
  let h = 0; const L = str.length;
  for (const k in f) { const p = f[k] / L; h -= p * Math.log2(p); }
  return h;
}

const PLACEHOLDER_LITERALS = new Set([
  'your-api-key', 'your_api_key', 'xxxxxxxx', 'changeme', 'placeholder',
  'example', 'test', 'demo', 'todo', 'replace-me', 'null', 'undefined',
  'password', 'string', '<your-key-here>', 'secret', 'apikey', 'token',
  '00000000000000000000', '11111111111111111111'
]);

function isPlaceholder(v) {
  const s = String(v || '').trim().toLowerCase();
  if (PLACEHOLDER_LITERALS.has(s)) return true;
  if (/^(.)\1+$/.test(s)) return true;            // aaaa, 111111
  if (/^x+$/i.test(s)) return true;                // xxxxxxxx
  if (/^<[^>]+>$/.test(s)) return true;            // <your-key>
  if (/^(?:abcdef|123456|qwerty)/i.test(s) && s.length < 16) return true;
  return false;
}

function isDocumentationDomain(host) {
  const h = String(host || '').toLowerCase();
  return /^(?:example|test|invalid|localhost)(?:\.|$)/.test(h) ||
    /\.(?:example|test|invalid)$/.test(h) ||
    /^(?:example\.com|example\.org|example\.net|test\.com)$/.test(h);
}

function isReservedIp(ip) {
  const parts = String(ip || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b, c, d] = parts;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && b === 18) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  return false;
}

function isLikelyInternationalPhone(v) {
  const raw = String(v || '').trim();
  if (!/^\+/.test(raw)) return false;
  const d = raw.replace(/\D/g, '');
  if (d.length < 8 || d.length > 15) return false;
  if (/^(.)\1+$/.test(d)) return false;
  if (/^(?:0123456789|1234567890|9876543210|0987654321)/.test(d)) return false;
  return true;
}

// 在 ±window 范围内是否含某个加密上下文
function inCryptoContext(source, offset, len) {
  const w = 300;
  const lo = Math.max(0, offset - w);
  const hi = Math.min(source.length, offset + len + w);
  const ctx = source.slice(lo, hi);
  return /(?:CryptoJS\.(?:AES|DES|TripleDES|RC4)\s*\.\s*(?:encrypt|decrypt)|crypto\.(?:createCipher(?:iv)?|createDecipher(?:iv)?)|crypto\.subtle\.(?:encrypt|decrypt|importKey)|JSEncrypt|forge\.cipher|sm[234]\.(?:encrypt|decrypt|do(?:En|De)crypt))/i.test(ctx);
}

// 在 ±window 范围内是否含明确的"安全敏感"用法
function inSecuritySensitiveContext(source, offset, len) {
  const w = 200;
  const lo = Math.max(0, offset - w);
  const hi = Math.min(source.length, offset + len + w);
  const ctx = source.slice(lo, hi);
  return /(?:password|passwd|pwd|secret|token|sign(?:ature)?|hmac|salt|nonce|api[_-]?key|access[_-]?key|csrf|auth)/i.test(ctx);
}

// ---------- 规则定义 ----------

const RULES = [

  // ============ Cloud / SaaS 凭证 (强格式 → confirmed) ============
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g,
    description: 'AWS 访问密钥 ID 格式精确匹配，泄漏可直接用于 AWS 控制平面调用。',
    exploit: '`aws sts get-caller-identity --no-sign-request=false` 立即验证账户/权限；若同时泄漏 SecretKey 即可完全控制账号绑定的资源。',
    recommendation: '在 IAM 控制台 deactivate 该 Key，审计 CloudTrail，启用 SCP 限制前端来源。',
    validate(ctx) {
      // ASIA 通常为 STS 临时凭证；如未在同一 source 内出现 SessionToken 则降级
      if (ctx.match.startsWith('ASIA') &&
          !/(?:x-amz-security-token|sessionToken|session_token)/i.test(ctx.source.slice(
            Math.max(0, ctx.offset - 500), Math.min(ctx.source.length, ctx.offset + 500)))) {
        return { confidence: 'likely', evidence: 'STS 临时凭证但未见配套 SessionToken' };
      }
      return null;
    }
  },

  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret_access_key|SecretAccessKey)["'\s:=]+["']?([A-Za-z0-9\/+=]{40})["']?/g,
    description: '与 AWS Access Key 配套的密钥本体，泄漏后等同于完整凭证。',
    exploit: '配合 Access Key ID 即可直接 sign API 请求，aws-cli/SDK 任意调用。',
    recommendation: '立即吊销并轮换；前端绝不可硬编码，使用后端代理或 Cognito 临时凭证。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 4.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'aliyun-accesskey-id',
    name: '阿里云 AccessKey ID',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bLTAI(?:5t|4G|4F)[A-Za-z0-9]{12,20}\b/g,
    description: '阿里云 AccessKey ID（LTAI 前缀含子类型）。',
    exploit: '使用 aliyun-cli `aliyun sts GetCallerIdentity` 验证；若搭配 Secret 可直接控制 ECS/OSS/RAM。',
    recommendation: 'RAM 控制台禁用 Key，迁至 STS 临时凭证。'
  },

  {
    id: 'tencent-secret-id',
    name: '腾讯云 SecretId',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bAKID[A-Za-z0-9]{32,40}\b/g,
    description: '腾讯云 API SecretId。',
    exploit: '搭配 SecretKey 可调用 TencentCloud API（CVM/COS/CAM）。',
    recommendation: 'CAM 控制台禁用 Key。'
  },

  {
    id: 'gcp-api-key',
    name: 'Google API Key',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    description: 'Google/Firebase API Key（39 字符精确格式）。',
    exploit: '调用未限制 referer 的 Google Maps/YouTube/Translate API 产生费用，或访问绑定的 Firebase 数据。',
    recommendation: '在 GCP 控制台为 Key 配置 HTTP referer / IP / API 白名单。'
  },

  {
    id: 'gcp-oauth-token',
    name: 'Google OAuth Access Token',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /\bya29\.[0-9A-Za-z_-]{30,}\b/g,
    description: 'Google OAuth 2.0 访问令牌。',
    exploit: '直接 `Authorization: Bearer ya29.xxx` 调用 Google APIs，访问授权范围内的资源。',
    recommendation: '吊销 token 并审计 OAuth 授权应用。'
  },

  {
    id: 'azure-storage-conn',
    name: 'Azure Storage 连接字符串',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+\/=]{86,90}(?:;EndpointSuffix=[\w.]+)?/g,
    description: 'Azure 存储账户完整连接串。',
    exploit: '使用 Azure Storage Explorer 直接登录，读写所有容器/blob/queue/table。',
    recommendation: '轮换 Account Key，改用 SAS 短期令牌。'
  },

  {
    id: 'stripe-secret-key',
    name: 'Stripe Secret Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{24,99}\b/g,
    description: 'Stripe 生产环境私钥。',
    exploit: '调用 Stripe API 创建/退款/导出客户付款数据；rk_live 受限但仍可读取部分资源。',
    recommendation: 'Dashboard 立即 roll key；前端只能使用 pk_ 公钥。',
    validate(ctx) {
      if (ctx.match.startsWith('sk_test_') || ctx.match.startsWith('rk_test_'))
        return { severity: 'medium', confidence: 'likely', evidence: '测试环境 Key' };
      return null;
    }
  },

  {
    id: 'sendgrid-api-key',
    name: 'SendGrid API Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,
    description: 'SendGrid API Key（前缀 SG. + 两段固定长度）。',
    exploit: '直接调用 SendGrid 发送任意邮件、读取邮件统计。',
    recommendation: 'Dashboard 删除该 Key 并轮换。'
  },

  {
    id: 'github-token',
    name: 'GitHub Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,255}\b/g,
    description: 'GitHub PAT / OAuth / Refresh / App Token。',
    exploit: '`curl -H "Authorization: token ghp_xxx" https://api.github.com/user` 验证身份；可读写授权范围内的仓库与 Actions Secret。',
    recommendation: 'Settings > Developer settings 立即吊销。'
  },

  {
    id: 'gitlab-pat',
    name: 'GitLab Personal Access Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    description: 'GitLab PAT。',
    exploit: '调用 GitLab API 读写仓库、CI 变量。',
    recommendation: '吊销并启用 IP 限制。'
  },

  {
    id: 'slack-token',
    name: 'Slack Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bxox[abprs]-(?:\d+-){2,}[A-Za-z0-9]{24,40}\b/g,
    description: 'Slack Bot/User/App/Refresh Token。',
    exploit: '调用 chat.postMessage、users.list 等 API；xoxp 用户 token 可代为发消息。',
    recommendation: 'Slack App 控制台 revoke token。'
  },

  {
    id: 'slack-webhook',
    name: 'Slack Incoming Webhook',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/g,
    description: 'Slack 入站 Webhook URL。',
    exploit: 'POST JSON 到该 URL 即可向绑定频道发送任意消息（钓鱼/告警污染）。',
    recommendation: 'Slack App 删除该 Webhook 并替换。'
  },

  {
    id: 'discord-webhook',
    name: 'Discord Webhook',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[\w-]{60,}/g,
    description: 'Discord Webhook URL。',
    exploit: 'POST 即可发消息/上传文件到目标频道。',
    recommendation: '服务器设置删除该 Webhook。'
  },

  {
    id: 'wechat-work-webhook',
    name: '企业微信 Webhook',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /https:\/\/qyapi\.weixin\.qq\.com\/cgi-bin\/webhook\/send\?key=[A-Za-z0-9-]{25,80}/g,
    description: '企业微信机器人 Webhook URL。',
    exploit: 'POST JSON 到该 URL 可向绑定群发送消息，可能造成钓鱼、告警污染或信息投递滥用。',
    recommendation: '删除或轮换 Webhook key，并限制机器人使用范围。'
  },

  {
    id: 'dingtalk-robot-webhook',
    name: '钉钉机器人 Webhook',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /https:\/\/oapi\.dingtalk\.com\/robot\/send\?access_token=[a-f0-9]{50,90}/g,
    description: '钉钉机器人 Webhook access_token。',
    exploit: '可向钉钉群发送任意消息，若未配置签名/关键词限制风险更高。',
    recommendation: '在钉钉机器人配置中重置 access_token，并开启加签和关键词限制。'
  },

  {
    id: 'feishu-bot-webhook',
    name: '飞书机器人 Webhook',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /https:\/\/open\.feishu\.cn\/open-apis\/bot\/v2\/hook\/[A-Za-z0-9-]{25,90}/g,
    description: '飞书机器人 Webhook URL。',
    exploit: '可向飞书群发送任意消息，造成钓鱼、社工或告警污染。',
    recommendation: '在飞书机器人配置中重置 Webhook，并开启签名校验。'
  },

  {
    id: 'npm-token',
    name: 'npm Access Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    description: 'npm 发布令牌。',
    exploit: '`npm whoami --registry ...` 验证；可发布恶意包到所属 scope（供应链攻击）。',
    recommendation: 'npmjs.com 立即 revoke。'
  },

  {
    id: 'mailgun-key',
    name: 'Mailgun API Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bkey-[a-f0-9]{32}\b/g,
    description: 'Mailgun API Key（key- + 32 hex）。',
    exploit: '直接调用 Mailgun 发邮件 API。',
    recommendation: 'Dashboard 轮换 Key。'
  },

  {
    id: 'openai-api-key',
    name: 'OpenAI API Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/g,
    description: 'OpenAI API Key 或项目 Key，泄露后可直接调用模型接口产生费用和数据风险。',
    exploit: '使用 Authorization: Bearer <key> 调用 OpenAI API 验证权限。',
    recommendation: '立即在 OpenAI 控制台撤销并轮换 Key，前端只调用后端代理。'
  },

  {
    id: 'anthropic-api-key',
    name: 'Anthropic API Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    description: 'Anthropic API Key，泄露后可直接调用 Claude API。',
    exploit: '携带 x-api-key 请求 Anthropic API 即可验证。',
    recommendation: '立即 revoke 并改为服务端保存。'
  },

  {
    id: 'huggingface-token',
    name: 'HuggingFace Access Token',
    category: 'secret', severity: 'high', confidence: 'confirmed',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    description: 'HuggingFace 访问令牌，可能拥有模型、数据集或推理 API 权限。',
    exploit: '调用 HuggingFace API /whoami-v2 验证令牌权限。',
    recommendation: '在 HuggingFace Settings > Access Tokens 中撤销并重建。'
  },

  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g,
    description: 'Telegram Bot Token，泄露后可控制机器人发送消息、读取更新。',
    exploit: '访问 https://api.telegram.org/bot<TOKEN>/getMe 验证机器人身份。',
    recommendation: '通过 BotFather revoke 并重新生成 Token。'
  },

  {
    id: 'discord-bot-token',
    name: 'Discord Bot/User Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\b(?:mfa\.[A-Za-z0-9_-]{80,}|[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b/g,
    description: 'Discord Bot 或用户 Token，泄露后可控制账号或机器人。',
    exploit: '使用 Authorization 头访问 Discord API 验证身份。',
    recommendation: '在 Discord Developer Portal 轮换 Bot Token；用户 Token 泄露需重置密码。'
  },

  {
    id: 'supabase-service-role-key',
    name: 'Supabase Service Role Key',
    category: 'secret', severity: 'critical', confidence: 'likely',
    regex: /(?:supabase(?:ServiceRole|_SERVICE_ROLE)?|service[_-]?role(?:[_-]?key)?|SUPABASE_SERVICE_ROLE_KEY)["'\s:=]+["']?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["']?/gi,
    description: 'Supabase service_role JWT 具备绕过 RLS 的高权限，不应出现在前端。',
    exploit: '携带 apikey/Authorization Bearer 调用 Supabase REST API，可绕过行级安全策略。',
    recommendation: '仅在后端环境变量中保存 service_role，前端只能使用 anon key。'
  },

  {
    id: 'firebase-config-exposure',
    name: 'Firebase 配置暴露',
    category: 'secret', severity: 'medium', confidence: 'likely',
    regex: /apiKey\s*:\s*["'](AIza[0-9A-Za-z_-]{35})["'][\s\S]{0,600}authDomain\s*:\s*["'][^"']+firebaseapp\.com["']/g,
    description: 'Firebase Web 配置暴露。apiKey 本身不等同私钥，但常用于定位项目并测试未授权数据库/存储规则。',
    exploit: '结合 projectId/authDomain 测试 Firestore、Realtime Database、Storage Rules 是否允许未授权读写。',
    recommendation: '确认 Firebase Security Rules 严格限制读写，并为 API Key 配置来源限制。'
  },

  {
    id: 'oauth-client-secret',
    name: 'OAuth Client Secret',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /(?:client[_-]?secret|oauth[_-]?secret|OIDC_CLIENT_SECRET|GOOGLE_CLIENT_SECRET)["'\s:=]+["']?([A-Za-z0-9_\-./+=]{20,160})["']?/gi,
    description: 'OAuth/OIDC Client Secret 硬编码，可能被用于伪造客户端换取授权码或 Token。',
    exploit: '结合 client_id、redirect_uri、授权码流程尝试换取 access_token。',
    recommendation: 'Client Secret 仅存后端；公开客户端使用 PKCE，不在前端保存 secret。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'jwt-session-signing-secret',
    name: 'JWT/Session 签名密钥',
    category: 'secret', severity: 'critical', confidence: 'likely',
    regex: /(?:jwt[_-]?secret|secretOrKey|signing[_-]?key|session[_-]?secret|cookie[_-]?secret|csrf[_-]?secret)["'\s:=]+["']?([^"'\s,;}{]{16,160})["']?/gi,
    description: 'JWT、Session、Cookie 或 CSRF 签名密钥硬编码，泄露后可能伪造身份或绕过校验。',
    exploit: '若后端使用该密钥签名，攻击者可离线签发 JWT、伪造 Session Cookie 或 CSRF Token。',
    recommendation: '立即轮换签名密钥并使旧 Token/Session 失效；密钥仅存服务端密钥管理系统。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (/^(?:true|false|null|undefined)$/i.test(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
      return null;
    }
  },

  {
    id: 'hardcoded-symmetric-crypto-key',
    name: '硬编码对称加密密钥',
    category: 'crypto-vuln', severity: 'critical', confidence: 'likely',
    regex: /(?:aes|des|3des|sm4|crypto|encrypt|decrypt|cipher)[_-]?(?:key|secret)["'\s:=]+["']?([A-Za-z0-9+/_=.-]{16,128})["']?/gi,
    description: 'AES/DES/3DES/SM4 等对称加密密钥硬编码。前端一旦泄露密钥，加密只能提供混淆效果。',
    exploit: '结合识别到的算法、模式、IV/nonce，可离线解密前端加密请求或伪造密文。',
    recommendation: '密钥不得写入前端；使用服务端密钥管理和 HTTPS，必要时改用短期会话密钥。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
      return null;
    }
  },

  {
    id: 'hardcoded-signature-key',
    name: '硬编码签名/HMAC 密钥',
    category: 'secret', severity: 'critical', confidence: 'likely',
    regex: /(?:hmac|sign|signature|mac|sha256|sha1|md5)[_-]?(?:key|secret|salt)["'\s:=]+["']?([A-Za-z0-9+/_=.-]{16,160})["']?/gi,
    description: '签名、HMAC、摘要盐值或验签密钥硬编码，可能导致请求签名可伪造。',
    exploit: '攻击者可重算 sign/signature 参数，篡改金额、用户 ID、订单号等关键参数。',
    recommendation: '签名密钥只放服务端；前端仅提交原始参数，由服务端签名或验签。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.8) return { drop: true };
      return null;
    }
  },

  {
    id: 'wechat-alipay-app-secret',
    name: '微信/支付宝 AppSecret 或商户密钥',
    category: 'secret', severity: 'critical', confidence: 'likely',
    regex: /(?:app[_-]?secret|wechat[_-]?secret|wx[_-]?secret|alipay[_-]?private[_-]?key|mch[_-]?key|pay[_-]?secret)["'\s:=]+["']?([A-Za-z0-9_\-+=/]{24,160})["']?/gi,
    description: '微信、支付宝或支付商户相关密钥硬编码，可能影响支付签名、退款或回调验签。',
    exploit: '结合商户号/appid 对支付请求、退款请求或回调签名进行伪造测试。',
    recommendation: '密钥必须保存在服务端，立即轮换并审计支付/退款日志。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'wechat-app-id',
    name: '微信/企业微信 AppID',
    category: 'exposure', severity: 'low', confidence: 'likely',
    regex: /\b(?:wx[a-z0-9]{15,18}|ww[a-z0-9]{15,18})\b/g,
    description: '微信小程序、公众号或企业微信 AppID 暴露。AppID 通常不是密钥，但可辅助枚举应用和接口。',
    exploit: '结合 AppSecret、回调地址、开放平台配置可用于进一步攻击面定位。',
    recommendation: '确认仅暴露允许公开的 AppID；AppSecret、商户密钥、回调签名密钥不得进入前端。'
  },

  {
    id: 'huawei-oss-config-secret',
    name: '华为云 OBS/OSS 配置凭证',
    category: 'secret', severity: 'critical', confidence: 'likely',
    regex: /huawei\.oss\.(?:ak|sk|bucket\.name|endpoint|local\.path)["'\s:=]+["']?([A-Za-z0-9_.-]{8,160})["']?/gi,
    description: '华为云对象存储相关 AK/SK、bucket 或 endpoint 配置。',
    exploit: '若同时存在 AK/SK，可直接访问对象存储资源；bucket/endpoint 可辅助枚举公开资产。',
    recommendation: 'AK/SK 只允许存放在服务端密钥管理中，前端使用临时授权或后端代理。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (/bucket|endpoint|local/i.test(ctx.match)) return { severity: 'medium', confidence: 'likely', evidence: '对象存储 bucket/endpoint 配置暴露' };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'docker-token-assignment',
    name: 'Docker/Registry Token 或密码',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /docker[_-]?(?:token|password|key|hub[_-]?password)["'\s:=]+["']?([A-Za-z0-9._~+\/=-]{16,180})["']?/gi,
    description: 'Docker Hub 或私有镜像仓库相关 token/password。',
    exploit: '可用于拉取/推送镜像，造成供应链污染或私有镜像泄露。',
    recommendation: '撤销并重建 Docker/Registry Token，CI/CD 中使用最小权限短期凭证。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'npm-auth-token-assignment',
    name: 'npm Auth Token Assignment',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /npm[_-]?(?:token|auth[_-]?token|api[_-]?key|password)["'\s:=]+["']?([A-Za-z0-9._~+\/=-]{16,180})["']?/gi,
    description: 'npm registry/publish token appears in a variable, object field, or config style assignment.',
    exploit: 'Reuse the token against npm registry APIs to test package publish/read permissions.',
    recommendation: 'Revoke the token in npm account settings and move registry credentials to CI/server-side secrets.',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'firebase-secret-assignment',
    name: 'Firebase Secret / Server Key',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /firebase[_-]?(?:secret|token|server[_-]?key|messaging[_-]?key|api[_-]?key)["'\s:=]+["']?([A-Za-z0-9._~+\/=-]{20,220})["']?/gi,
    description: 'Firebase API/server credential style assignment.',
    exploit: 'Depending on project rules and key type, this may allow Firebase API usage or message sending tests.',
    recommendation: 'Restrict Firebase keys by domain/API scope and keep server keys outside frontend bundles.',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'github-secret-assignment',
    name: 'GitHub Token/Secret Assignment',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /github[_-]?(?:token|pat|secret|client[_-]?secret|api[_-]?key)["'\s:=]+["']?([A-Za-z0-9_._~+\/=-]{18,255})["']?/gi,
    description: 'GitHub-related token or OAuth client secret appears in assignment form.',
    exploit: 'Validate with GitHub API endpoints only when authorized; leaked tokens may expose repositories, Actions, or org data.',
    recommendation: 'Revoke the token/client secret and rotate any app secrets that were shipped to frontend code.',
    validate(ctx) {
      const v = ctx.captured;
      if (isPlaceholder(v)) return { drop: true };
      if (/^(?:ghp|gho|ghu|ghs|ghr|github_pat)_/i.test(v)) {
        return { severity: 'critical', confidence: 'confirmed', evidence: 'GitHub token prefix found in assignment' };
      }
      if (shannonEntropy(v) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'google-secret-assignment',
    name: 'Google/Firebase Credential Assignment',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /(?:google|gcp|firebase)[_-]?(?:api[_-]?key|client[_-]?secret|oauth[_-]?secret|server[_-]?key)["'\s:=]+["']?([A-Za-z0-9._~+\/=-]{20,220})["']?/gi,
    description: 'Google Cloud, Maps, OAuth, or Firebase credential style assignment.',
    exploit: 'Check API restrictions and allowed referrers for the leaked credential.',
    recommendation: 'Rotate the credential and enforce API/referrer/IP restrictions in Google Cloud Console.',
    validate(ctx) {
      const v = ctx.captured;
      if (isPlaceholder(v)) return { drop: true };
      if (/^AIza[0-9A-Za-z_-]{35}$/.test(v)) return { confidence: 'confirmed', severity: 'high' };
      if (shannonEntropy(v) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'aws-credential-assignment',
    name: 'AWS Credential Assignment',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key|secretkey|session[_-]?token|api[_-]?key|key)["'\s:=]+["']?([A-Za-z0-9\/+=._-]{16,220})["']?/gi,
    description: 'AWS key, secret, or session token style assignment beyond strict AWS key formats.',
    exploit: 'When paired with other AWS credential parts, this may be validated with STS get-caller-identity.',
    recommendation: 'Rotate exposed AWS credentials and replace frontend secrets with scoped temporary credentials or backend proxying.',
    validate(ctx) {
      const v = ctx.captured;
      if (isPlaceholder(v)) return { drop: true };
      if (/^(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}$/.test(v)) {
        return { severity: 'critical', confidence: 'confirmed', evidence: 'AWS access key id format found in assignment' };
      }
      if (shannonEntropy(v) < 3.2) return { drop: true };
      return null;
    }
  },

  {
    id: 'mailgun-assignment',
    name: 'Mailgun Credential Assignment',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /mailgun[_-]?(?:api[_-]?key|secret[_-]?api[_-]?key|private[_-]?key|key)["'\s:=]+["']?([A-Za-z0-9._~+\/=-]{16,160})["']?/gi,
    description: 'Mailgun API credential appears in assignment form.',
    exploit: 'A valid Mailgun key may allow sending mail or reading domain/event data.',
    recommendation: 'Rotate the Mailgun key and keep email provider credentials on the server side.',
    validate(ctx) {
      const v = ctx.captured;
      if (isPlaceholder(v)) return { drop: true };
      if (/^key-[a-f0-9]{32}$/i.test(v)) return { severity: 'critical', confidence: 'confirmed' };
      if (shannonEntropy(v) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'sentry-dsn',
    name: 'Sentry DSN',
    category: 'secret', severity: 'low', confidence: 'confirmed',
    regex: /https:\/\/[A-Fa-f0-9]{16,64}@o\d+\.ingest\.sentry\.io\/\d+/g,
    description: 'Sentry DSN 暴露通常不是高危凭证，但可能被用于污染错误日志或枚举项目。',
    exploit: '向 DSN 发送伪造事件，观察是否污染告警和错误统计。',
    recommendation: '确认 DSN 允许公开暴露的风险可接受，并配置速率限制、来源过滤和告警降噪。'
  },

  {
    id: 'twilio-account-sid',
    name: 'Twilio Account SID',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /\bAC[a-f0-9]{32}\b/g,
    description: 'Twilio Account SID（仅 SID 不足以调用 API）。',
    exploit: '需配合 Auth Token；若同源出现 Auth Token 则可发短信/拨电话。',
    recommendation: '若同源含 Auth Token 应立即轮换。',
    validate(ctx) {
      const w = 800;
      const seg = ctx.source.slice(Math.max(0, ctx.offset - w), Math.min(ctx.source.length, ctx.offset + w));
      if (/(?:auth[_-]?token|TWILIO_AUTH_TOKEN)["'\s:=]+["']?[a-f0-9]{32}/i.test(seg)) {
        return { severity: 'critical', confidence: 'confirmed', evidence: '同源出现 AuthToken，构成完整凭证' };
      }
      return null;
    }
  },

  // ============ 私钥 / 证书 (需 BEGIN+END 配对 → confirmed) ============
  {
    id: 'notion-integration-token',
    name: 'Notion Integration Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bsecret_[A-Za-z0-9]{43}\b/g,
    description: 'Notion 内部集成 Token，泄露后可访问已授权 workspace 页面和数据库。',
    exploit: '携带 `Authorization: Bearer secret_xxx` 调用 Notion API 可读取/写入授权资源。',
    recommendation: '立即在 Notion integrations 中 rotate/revoke，并检查授权页面范围。'
  },

  {
    id: 'linear-api-key',
    name: 'Linear API Key',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\blin_api_[A-Za-z0-9]{32,}\b/g,
    description: 'Linear API Key，可访问组织 issue、团队和项目数据。',
    exploit: '携带 `Authorization: <key>` 调用 Linear GraphQL API。',
    recommendation: '立即撤销并重新生成 Linear API Key。'
  },

  {
    id: 'shopify-access-token',
    name: 'Shopify Access Token',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\bshp(?:at|ss|ca|ua)_[a-fA-F0-9]{32}\b/g,
    description: 'Shopify Admin/Storefront/Custom App Token，可能访问店铺订单、客户或商品数据。',
    exploit: '携带 `X-Shopify-Access-Token` 调用对应店铺 Admin API。',
    recommendation: '在 Shopify 后台撤销应用 Token，并排查订单/客户数据访问日志。'
  },

  {
    id: 'cloudflare-token-or-key',
    name: 'Cloudflare Token / API Key',
    category: 'secret', severity: 'critical', confidence: 'likely',
    regex: /(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CF_TOKEN|cloudflare[_-]?(?:api[_-]?)?(?:token|key))["'\s:=]+["']?([A-Za-z0-9_-]{30,120})["']?/gi,
    description: 'Cloudflare API Token 或 Global API Key 形式凭证。',
    exploit: '可调用 Cloudflare API 修改 DNS、Worker、Zone 配置或读取账号资源。',
    recommendation: 'Cloudflare Dashboard 立即撤销 Token，并为新 Token 设置最小权限和资源范围。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.2) return { drop: true };
      return null;
    }
  },

  {
    id: 'vercel-token',
    name: 'Vercel Token',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /(?:VERCEL_TOKEN|vercel[_-]?token)["'\s:=]+["']?([A-Za-z0-9_-]{24,120})["']?/gi,
    description: 'Vercel API Token，可能访问项目、部署、环境变量。',
    exploit: '使用 `Authorization: Bearer <token>` 调用 Vercel API 读取项目或触发部署。',
    recommendation: 'Vercel Account Settings 中撤销 Token，检查项目环境变量访问记录。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.1) return { drop: true };
      return null;
    }
  },

  {
    id: 'netlify-token',
    name: 'Netlify Access Token',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /(?:NETLIFY_AUTH_TOKEN|NETLIFY_TOKEN|netlify[_-]?(?:auth[_-]?)?token)["'\s:=]+["']?([A-Za-z0-9_-]{32,120})["']?/gi,
    description: 'Netlify Personal Access Token，可能访问站点、部署、构建环境变量。',
    exploit: '携带 Bearer Token 调用 Netlify API。',
    recommendation: 'Netlify User Settings 中撤销 Token，并检查站点 deploy hook 和环境变量。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.1) return { drop: true };
      return null;
    }
  },

  {
    id: 'bearer-auth-token',
    name: 'Bearer 认证 Token',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /["']Bearer\s+([A-Za-z0-9._~+\/=-]{20,500})["']/g,
    description: '硬编码 Bearer Token，可能是 OAuth/JWT/API 访问令牌。',
    exploit: '直接放入 `Authorization: Bearer <token>` 请求头复用。',
    recommendation: 'Bearer Token 不应写入前端源码；使用后端代理或短期会话下发。',
    validate(ctx) {
      const token = ctx.captured;
      if (isPlaceholder(token)) return { drop: true };
      if (/^eyJ[A-Za-z0-9_-]+\./.test(token)) return { severity: 'critical', confidence: 'confirmed', evidence: 'Bearer 中包含 JWT 结构' };
      if (shannonEntropy(token) < 3.2) return { drop: true };
      return null;
    }
  },

  {
    id: 'api-key-header',
    name: 'API Key 请求头',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /["'](?:x-api-key|api-key|apikey|x-auth-token|authorization)["']\s*:\s*["']([A-Za-z0-9._~+\/=-]{16,180})["']/gi,
    description: '常见认证请求头中硬编码 API Key / Token。',
    exploit: '复用对应 Header 即可尝试访问后端 API。',
    recommendation: '认证 Header 值应由后端签发或运行时短期下发，不应出现在打包产物中。',
    validate(ctx) {
      const v = ctx.captured;
      if (/^(?:Bearer|Basic)\s+/i.test(v)) return { drop: true };
      if (isPlaceholder(v)) return { drop: true };
      if (shannonEntropy(v) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'authorization-token-header',
    name: 'Authorization Token Header',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /(?:["']?authorization["']?)\s*:\s*["'](?:Token\s+)?([A-Za-z0-9._~+\/=-]{20,500})["']/gi,
    description: 'Authorization header contains a hardcoded token value other than standard Bearer/Basic forms.',
    exploit: 'Replay the Authorization header against matching API endpoints when testing is authorized.',
    recommendation: 'Generate Authorization tokens at runtime on the server side or use short-lived session-bound tokens.',
    validate(ctx) {
      const v = ctx.captured;
      if (/(?:["']?authorization["']?)\s*:\s*["'](?:Bearer|Basic)\s+/i.test(ctx.match)) return { drop: true };
      if (isPlaceholder(v)) return { drop: true };
      if (shannonEntropy(v) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'session-cookie-token',
    name: 'Session/Cookie Token',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /(?:sessionid|session_id|connect\.sid|JSESSIONID|PHPSESSID|remember[_-]?token|csrf[_-]?token|xsrf[_-]?token)["'\s:=]+["']?([A-Za-z0-9._~+\/=-]{20,200})["']?/gi,
    description: '会话、CSRF/XSRF 或记住登录 Token 硬编码。',
    exploit: '可能用于复用会话、绕过 CSRF 或模拟用户状态。',
    recommendation: '会话类 Token 必须由服务端按用户动态签发，禁止写入静态前端代码。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 3.0) return { drop: true };
      return null;
    }
  },

  {
    id: 'hardcoded-password-assignment',
    name: '硬编码密码/口令字段',
    category: 'hardcode', severity: 'high', confidence: 'likely',
    regex: /["']?(?:password|passwd|pwd|passphrase|loginPass|defaultPassword)["']?\s*[:=]\s*["']([^"'\s]{6,128})["']/gi,
    description: '源码中出现密码/口令字段字面量赋值。',
    exploit: '可用于尝试默认账号、测试环境后台或接口 Basic/OAuth 流程。',
    recommendation: '移除硬编码密码，改为服务端配置或密钥管理系统；若是真实口令立即轮换。',
    validate(ctx) {
      const v = ctx.captured;
      if (isPlaceholder(v) || /^[*•]+$/.test(v)) return { drop: true };
      if (/^(?:123456|12345678|password|qwerty|admin123|root123|test123|demo123)$/i.test(v)) {
        return { severity: 'critical', confidence: 'confirmed', evidence: '常见弱口令硬编码' };
      }
      if (shannonEntropy(v) < 2.3) return { confidence: 'suspected' };
      return null;
    }
  },

  {
    id: 'pem-private-key',
    name: 'PEM 私钥块',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/g,
    description: '完整 PEM 格式私钥（要求 BEGIN/END 配对且中间是有效 base64 块）。',
    exploit: '直接用 openssl/ssh 加载即可签名/解密；TLS 私钥泄漏意味着可中间人解密历史流量。',
    recommendation: '立即从代码中移除并轮换证书；扫描 git 历史。',
    validate(ctx) {
      const after = ctx.source.slice(ctx.offset, Math.min(ctx.source.length, ctx.offset + 8192));
      const endRe = /-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----/;
      const m = endRe.exec(after);
      if (!m) return { drop: true };
      const body = after.slice(ctx.match.length, m.index);
      // 必须有连续 base64 行
      if (!/[A-Za-z0-9+\/=\s]{80,}/.test(body)) return { drop: true };
      return { evidence: '已校验 BEGIN/END 配对与 base64 内容' };
    }
  },

  // ============ 数据库连接 (含明文凭证 → confirmed) ============
  {
    id: 'db-conn-string',
    name: '数据库连接串（含明文密码）',
    category: 'secret', severity: 'critical', confidence: 'confirmed',
    regex: /\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqp|mssql):\/\/([^:\s"'<>]+):([^@\s"'<>]{4,})@([A-Za-z0-9.\-]+(?::\d+)?)(?:\/[\w.-]*)?/g,
    description: 'URL 形式数据库连接串，含用户名+密码+主机。',
    exploit: '直接 `mongo "mongodb+srv://..."` / `psql "postgres://..."` 连接对应库。',
    recommendation: '改用后端代理；密码不应出现在前端任何位置。',
    validate(ctx) {
      const pwd = ctx.match.match(/:\/\/[^:]+:([^@]+)@/)?.[1];
      if (!pwd || isPlaceholder(pwd)) return { drop: true };
      return null;
    }
  },

  // ============ JWT (实际解析) ============
  {
    id: 'jwt-token',
    name: 'JWT Token',
    category: 'secret', severity: 'medium', confidence: 'likely',
    regex: /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
    description: 'JWT；进一步校验 alg、敏感载荷、过期时间。',
    exploit: '若 alg=none 可任意伪造；payload 含敏感字段说明信息泄漏；缺 exp 则为永久 token。',
    recommendation: '强制 HS256/RS256；设置 exp；payload 不应放敏感数据。',
    validate(ctx) {
      const parts = ctx.match.split('.');
      const head = b64urlToStr(parts[0]);
      const body = b64urlToStr(parts[1]);
      let header, payload;
      try { header = JSON.parse(head); payload = JSON.parse(body); }
      catch { return { drop: true }; }

      const evidences = [];
      let severity = 'low', confidence = 'likely';

      if (header.alg && String(header.alg).toLowerCase() === 'none') {
        evidences.push('alg=none — 可任意伪造');
        severity = 'critical'; confidence = 'confirmed';
      }
      const sensitiveKeys = ['password', 'pwd', 'pass', 'secret', 'private_key', 'privatekey',
        'apikey', 'api_key', 'access_key', 'ssn', 'creditcard', 'card_number'];
      for (const k of Object.keys(payload || {})) {
        if (sensitiveKeys.includes(String(k).toLowerCase())) {
          evidences.push('payload 含敏感字段: ' + k);
          if (severity === 'low') severity = 'high';
          confidence = 'confirmed';
        }
      }
      if (payload && typeof payload.exp !== 'number') {
        evidences.push('无 exp — 永不过期');
        if (severity === 'low') severity = 'medium';
        confidence = 'confirmed';
      }
      if (!evidences.length) return { drop: true }; // 普通正常 JWT 不报
      return { severity, confidence, evidence: evidences.join('；') + ` | alg=${header.alg}` };
    }
  },

  // ============ 加解密漏洞 (需上下文) ============
  {
    id: 'aes-ecb-mode',
    name: 'AES ECB 模式',
    category: 'crypto-vuln', severity: 'high', confidence: 'confirmed',
    regex: /\b(?:mode\s*[:=]\s*CryptoJS\.mode\.ECB|"aes-(?:128|192|256)-ecb"|'aes-(?:128|192|256)-ecb')\b/g,
    description: 'AES ECB 模式相同明文块产生相同密文块，泄漏明文模式（如著名的"企鹅图"）。',
    exploit: '对相同 16 字节块加密结果完全一致，攻击者可通过频率分析、字典攻击恢复明文结构。',
    recommendation: '改用 GCM（AEAD，自带认证）或 CBC + 随机 IV + HMAC。'
  },

  {
    id: 'hardcoded-aes-key',
    name: '硬编码 AES 密钥',
    category: 'crypto-vuln', severity: 'critical', confidence: 'likely',
    regex: /(?:key|KEY|secretKey|aesKey|encryptKey|cryptoKey)\s*[:=]\s*(?:CryptoJS\.enc\.\w+\.parse\(\s*)?["']([A-Za-z0-9+\/=_\-]{16,64})["']/g,
    description: '位于加密调用上下文中的对称密钥字面量。',
    exploit: '直接复制密钥即可解密所有由前端加密的请求/响应；前端"加密"完全失效。',
    recommendation: '密钥不应硬编码在前端；改为后端下发的会话密钥（如登录后返回）+ HTTPS。',
    validate(ctx) {
      if (isPlaceholder(ctx.captured)) return { drop: true };
      if (shannonEntropy(ctx.captured) < 2.5) return { drop: true };
      if (!inCryptoContext(ctx.source, ctx.offset, ctx.match.length)) return { drop: true };
      return { evidence: 'key 位于实际加密调用 ±300 字符内' };
    }
  },

  {
    id: 'hardcoded-iv',
    name: '硬编码 IV / Nonce',
    category: 'crypto-vuln', severity: 'high', confidence: 'likely',
    regex: /\b(?:iv|IV|nonce)\s*[:=]\s*(?:CryptoJS\.enc\.\w+\.parse\(\s*)?["']([0-9a-fA-F]{16,64}|[A-Za-z0-9+\/=_\-]{12,32})["']/g,
    description: '加密 IV/Nonce 看起来是固定的字面量。',
    exploit: 'CBC 固定 IV → 同明文同密文，可重放；GCM/CTR 固定 IV+key → 灾难性，可异或还原密钥流恢复任意明文。',
    recommendation: 'IV 必须使用 crypto.getRandomValues 随机生成，与密文一起传输（拼接或独立字段）。',
    validate(ctx) {
      // 全 0 / 全相同字符的 IV 是确凿漏洞，优先于 placeholder 判断
      const isAllSame = /^(.)\1+$/.test(ctx.captured);
      if (!inCryptoContext(ctx.source, ctx.offset, ctx.match.length)) return { drop: true };
      if (isAllSame) {
        return { confidence: 'confirmed', evidence: `${/^0+$/.test(ctx.captured) ? '全 0' : '全相同字符'} IV，加密上下文中确定可利用` };
      }
      if (isPlaceholder(ctx.captured)) return { drop: true };
      return null;
    }
  },

  {
    id: 'weak-md5-security',
    name: 'MD5 用于安全场景',
    category: 'crypto-vuln', severity: 'high', confidence: 'likely',
    regex: /\b(?:CryptoJS\.MD5|md5)\s*\(\s*([^)]{1,200})\)/g,
    description: 'MD5 抗碰撞已破，禁止用于密码哈希、签名、消息认证。',
    exploit: '彩虹表/碰撞攻击可在分钟级恢复弱口令；签名场景可被构造碰撞绕过。',
    recommendation: '密码用 bcrypt/argon2/scrypt；消息认证用 HMAC-SHA256；文件校验可继续用 MD5/CRC（仅完整性）。',
    validate(ctx) {
      const arg = ctx.captured || '';
      if (!/(?:password|passwd|pwd|secret|token|sign|signature|key|salt|auth|hmac)/i.test(arg)) {
        // 仅当参数中含安全敏感词时才报；否则可能是文件校验等合法用途
        return { drop: true };
      }
      return { evidence: '参数含 password/token/secret 等安全敏感关键字' };
    }
  },

  {
    id: 'weak-sha1-security',
    name: 'SHA-1 用于安全场景',
    category: 'crypto-vuln', severity: 'medium', confidence: 'likely',
    regex: /\b(?:CryptoJS\.SHA1|sha1)\s*\(\s*([^)]{1,200})\)/g,
    description: 'SHA-1 已被构造碰撞（SHAttered），不应用于签名/证书/HMAC 之外的新系统。',
    exploit: '可构造两份不同内容产生相同 SHA-1，绕过基于哈希的完整性校验。',
    recommendation: '替换为 SHA-256 或 SHA-3。',
    validate(ctx) {
      const arg = ctx.captured || '';
      if (!/(?:password|passwd|pwd|secret|token|sign|signature|key|salt|auth)/i.test(arg)) {
        return { drop: true };
      }
      return null;
    }
  },

  {
    id: 'weak-cipher-des-rc4',
    name: '使用 DES / 3DES / RC4',
    category: 'crypto-vuln', severity: 'high', confidence: 'confirmed',
    regex: /\b(?:CryptoJS\.(?:DES|TripleDES|RC4|Rabbit)\.(?:encrypt|decrypt)|"des-ede3?-(?:cbc|ecb)"|'des-ede3?-(?:cbc|ecb)')\b/g,
    description: 'DES/3DES/RC4 均已淘汰：DES 56 位密钥可暴破，RC4 流密码已被多种攻击攻破。',
    exploit: '弱算法可在合理时间被破解；RC4 在 TLS 中曾被实际攻击。',
    recommendation: '统一替换为 AES-256-GCM。'
  },

  {
    id: 'rsa-pkcs1-v1_5',
    name: 'RSA PKCS#1 v1.5 / NoPadding',
    category: 'crypto-vuln', severity: 'medium', confidence: 'likely',
    regex: /(?:setOptions\s*\(\s*\{\s*encryptionScheme\s*:\s*["']pkcs1["']|RSA(?:[-_])?(?:PKCS1Padding|NoPadding))/g,
    description: 'PKCS#1 v1.5 易受 Bleichenbacher padding oracle；NoPadding 不安全。',
    exploit: '若服务端能区分填充错误，可在百万级请求内恢复明文/会话密钥。',
    recommendation: '加密用 RSA-OAEP，签名用 RSA-PSS。'
  },

  {
    id: 'math-random-as-crypto',
    name: 'Math.random 用作密码学随机',
    category: 'crypto-vuln', severity: 'high', confidence: 'confirmed',
    regex: /\b(?:key|iv|IV|nonce|salt|token|secret|sessionId|csrf)\s*=\s*(?:[^=;\n]{0,80}?)Math\.random\s*\(/gi,
    description: 'Math.random 是非密码学伪随机数生成器，输出可预测。',
    exploit: 'V8 的 Math.random 使用 xorshift128+，已有论文展示通过几个连续输出恢复内部状态、预测后续输出。',
    recommendation: '使用 crypto.getRandomValues(new Uint8Array(n)) 或 crypto.randomUUID()。'
  },

  {
    id: 'eval-on-decrypted',
    name: 'eval 解密后内容（动态执行）',
    category: 'crypto-vuln', severity: 'critical', confidence: 'confirmed',
    regex: /\beval\s*\(\s*(?:[A-Za-z_$][\w$]*\.)?(?:decrypt|atob|JSON\.parse\s*\(\s*atob)/g,
    description: '将解密/解码结果直接送入 eval，等同于服务端→前端 RCE 通道。',
    exploit: '攻击者控制密文/Base64 输入即可注入任意 JS 代码。',
    recommendation: '禁止 eval；解密后用 JSON.parse 处理结构化数据，或显式校验白名单。'
  },

  // ============ 硬编码漏洞 ============
  {
    id: 'hardcoded-admin-credentials',
    name: '硬编码管理员凭证',
    category: 'hardcode', severity: 'critical', confidence: 'likely',
    regex: /(?:username|user|account|admin|administrator)\s*[:=]\s*["'](?:admin|administrator|root|superuser|sa)["'][\s,;}]+(?:[^=\n]{0,80})?(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{4,64})["']/gi,
    description: '同一对象/作用域内同时出现管理员账号与口令字面量。',
    exploit: '直接尝试该账号登录；若是默认账户更可能未改密。',
    recommendation: '前端绝不应包含任何账号密码；后端禁用默认账户或强制首次登录改密。',
    validate(ctx) {
      const pwd = ctx.captured;
      if (isPlaceholder(pwd)) return { drop: true };
      if (/^(?:admin|root|123456|password|qwerty|admin123|root123|test|demo)$/i.test(pwd)) {
        return { confidence: 'confirmed', severity: 'critical', evidence: '弱口令 + 管理员账号同时硬编码' };
      }
      return null;
    }
  },

  {
    id: 'jwt-alg-none-config',
    name: 'JWT 配置允许 alg=none',
    category: 'crypto-vuln', severity: 'critical', confidence: 'confirmed',
    regex: /["']alg["']\s*:\s*["']none["']/gi,
    description: 'JWT 头部出现 alg=none。',
    exploit: '若服务端按 alg 字段处理且支持 none，可任意伪造任意用户 token。',
    recommendation: '服务端强制白名单算法（如 HS256/RS256），明确拒绝 none。'
  },

  // ============ 仅作"可疑"提示，默认隐藏 (suspected) ============
  {
    id: 'cn-id-card',
    name: '中国身份证号',
    category: 'pii', severity: 'high', confidence: 'likely',
    regex: /(?<!\d)([1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])(?!\d)/g,
    description: '18 位身份证号（已校验校验位）。',
    exploit: '真实身份证号可用于钓鱼/社工/伪造资料。',
    recommendation: '前端不应硬编码真实身份证；脱敏展示。',
    validate(ctx) {
      const id = ctx.captured.toUpperCase();
      const w = '7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2'.split(',').map(Number);
      const map = '1,0,X,9,8,7,6,5,4,3,2'.split(',');
      let s = 0;
      for (let i = 0; i < 17; i++) s += parseInt(id[i], 10) * w[i];
      const check = map[s % 11];
      if (check !== id[17]) return { drop: true };
      return { evidence: '校验位通过' };
    }
  },

  {
    id: 'email-address',
    name: '邮箱地址',
    category: 'pii', severity: 'low', confidence: 'likely',
    regex: /\b([A-Z0-9._%+-]{2,64}@[A-Z0-9.-]{2,180}\.[A-Z]{2,24})\b/gi,
    description: '源码或接口响应中出现邮箱地址，可能属于用户资料、账号或员工信息。',
    exploit: '可用于撞库、钓鱼、社工或账号枚举。',
    recommendation: '前端代码中避免硬编码真实邮箱；接口响应应按权限返回并做脱敏。',
    validate(ctx) {
      const mail = String(ctx.captured || '').toLowerCase();
      const host = mail.split('@')[1] || '';
      if (isDocumentationDomain(host)) return { drop: true };
      if (/^(?:support|service|help|admin|noreply|no-reply|info|contact)@/i.test(mail)) {
        return { confidence: 'suspected', evidence: '通用联系邮箱，需人工确认是否敏感' };
      }
      const seg = ctx.source.slice(Math.max(0, ctx.offset - 140), Math.min(ctx.source.length, ctx.offset + 140));
      if (/(?:user|account|customer|member|email|mail|profile|receiver|owner|employee)/i.test(seg)) return null;
      return { confidence: 'suspected' };
    }
  },

  {
    id: 'cn-mobile-phone',
    name: '中国大陆手机号',
    category: 'pii', severity: 'medium', confidence: 'likely',
    regex: /(?<!\d)(1[3-9]\d{9})(?!\d)/g,
    description: '中国大陆 11 位手机号格式。',
    exploit: '可用于短信轰炸、撞库、钓鱼或用户身份关联。',
    recommendation: '接口响应手机号应按权限返回并脱敏；源码中禁止硬编码真实手机号。',
    validate(ctx) {
      const seg = ctx.source.slice(Math.max(0, ctx.offset - 120), Math.min(ctx.source.length, ctx.offset + 120));
      if (/(?:example|demo|test|mock|placeholder|13800138000|手机号示例)/i.test(seg)) return { drop: true };
      if (!/(?:phone|mobile|tel|手机号|手机|电话|user|customer|member|account|contact)/i.test(seg)) {
        return { confidence: 'suspected' };
      }
      return null;
    }
  },

  {
    id: 'international-phone-number',
    name: 'International Phone Number',
    category: 'pii', severity: 'medium', confidence: 'likely',
    regex: /(\+\d[\d\s().-]{7,22}\d)/g,
    description: 'International E.164-like phone number exposure in source code or API payload examples.',
    exploit: 'May be used for user enumeration, phishing, SMS abuse, or correlating leaked user records.',
    recommendation: 'Avoid shipping real phone numbers in frontend code and mask phone fields in API responses.',
    validate(ctx) {
      if (!isLikelyInternationalPhone(ctx.captured)) return { drop: true };
      const seg = ctx.source.slice(Math.max(0, ctx.offset - 120), Math.min(ctx.source.length, ctx.offset + 120));
      if (/(?:example|demo|test|mock|placeholder)/i.test(seg)) return { drop: true };
      if (!/(?:phone|mobile|tel|contact|user|customer|member|account|recipient|owner)/i.test(seg)) {
        return { confidence: 'suspected' };
      }
      return null;
    }
  },

  {
    id: 'public-ip-address',
    name: '公网 IP 地址',
    category: 'pii', severity: 'low', confidence: 'likely',
    regex: /\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b/g,
    description: '公网 IP 地址硬编码或泄露。',
    exploit: '可辅助资产定位、端口扫描、源站识别或绕过 CDN。',
    recommendation: '避免在前端暴露源站/内部资产 IP；配置应由后端或运行时环境注入。',
    validate(ctx) {
      const ip = ctx.captured;
      if (isReservedIp(ip)) return { drop: true };
      const seg = ctx.source.slice(Math.max(0, ctx.offset - 120), Math.min(ctx.source.length, ctx.offset + 120));
      if (/(?:version|chunk|hash|rgba|rgb|color|matrix|translate3d)/i.test(seg)) return { drop: true };
      if (!/(?:host|server|ip|endpoint|baseURL|proxy|gateway|origin|cdn|api|url)/i.test(seg)) return { confidence: 'suspected' };
      return null;
    }
  },

  {
    id: 'private-ip-address',
    name: '内网 IP 地址',
    category: 'exposure', severity: 'low', confidence: 'likely',
    regex: /\b((?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|127\.0\.0\.1))(?::\d{2,5})?\b/g,
    description: '内网、localhost 或私有网段地址暴露。',
    exploit: '可辅助识别内网架构、调试接口、代理配置或 SSRF 目标。',
    recommendation: '前端产物不应暴露内网地址；调试/测试地址需在构建时剔除。',
    validate(ctx) {
      const seg = ctx.source.slice(Math.max(0, ctx.offset - 100), Math.min(ctx.source.length, ctx.offset + 100));
      if (/(?:sourceMappingURL|webpack|devtool|example|demo)/i.test(seg)) return { confidence: 'suspected' };
      return null;
    }
  },

  {
    id: 'bank-card',
    name: '银行卡号（Luhn 通过）',
    category: 'pii', severity: 'medium', confidence: 'likely',
    regex: /(?<!\d)((?:62|4|5[1-5])\d{14,17})(?!\d)/g,
    description: '13–18 位银行卡号且 Luhn 校验通过。',
    exploit: '真实卡号 + 失效月/CVV 可发起欺诈交易。',
    recommendation: '前端禁止存放真实卡号；展示需脱敏。',
    validate(ctx) {
      if (!luhnOk(ctx.captured)) return { drop: true };
      return { evidence: 'Luhn 校验通过' };
    }
  },

  {
    id: 'generic-secret-assignment',
    name: '通用密钥赋值（高熵字符串）',
    category: 'secret', severity: 'medium', confidence: 'suspected',
    regex: /["']?(?:secret|api[_-]?key|access[_-]?key|client[_-]?secret|app[_-]?secret|encrypt(?:ion)?[_-]?key|token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+\/=.]{20,128})["']/gi,
    description: '名为 secret/apiKey/token 的字面量赋值，仅高熵且非占位时报告。',
    exploit: '需人工核实是否为真实凭证。',
    recommendation: '若属真实凭证立即吊销并迁至运行时下发。',
    validate(ctx) {
      const v = ctx.captured;
      if (isPlaceholder(v)) return { drop: true };
      if (shannonEntropy(v) < 3.5) return { drop: true };
      // 排除常见的 UUID / Base64 资源指纹（webpack hash 等）
      if (/^[0-9a-f]{32,40}$/i.test(v)) return { drop: true }; // 文件 hash
      if (/^v\d+\./i.test(v)) return { drop: true };           // 版本字符串
      return null;
    }
  },

  {
    id: 'basic-auth-header',
    name: 'Basic Auth 头（含凭证）',
    category: 'secret', severity: 'high', confidence: 'likely',
    regex: /["']Basic\s+([A-Za-z0-9+\/=]{16,})["']/g,
    description: 'Authorization: Basic <base64>，base64 解码即为 user:pass。',
    exploit: '`echo <base64> | base64 -d` 直接拿到明文用户名/密码。',
    recommendation: '改为 Bearer Token + OAuth；如必须 Basic 也要由后端运行时注入。',
    validate(ctx) {
      const dec = b64urlToStr(ctx.captured.replace(/-/g, '+').replace(/_/g, '/'));
      if (!dec || !dec.includes(':')) return { drop: true };
      const [u, p] = dec.split(':', 2);
      if (!u || !p || isPlaceholder(p)) return { drop: true };
      return { evidence: `解码后 user=${u}, pass.len=${p.length}` };
    }
  }
];

// ---------- META 规则：仅用于"页面元信息"面板，不进 findings ----------
const META_RULES = {
  cryptoLibs: [
    { name: 'CryptoJS',          regex: /\bCryptoJS\.(?:AES|DES|TripleDES|MD5|SHA\d+|HmacSHA\d+|enc|mode)\b/ },
    { name: 'JSEncrypt (RSA)',   regex: /\b(?:new\s+)?JSEncrypt\s*\(/ },
    { name: 'node-forge',        regex: /\bforge\.(?:cipher|pki|md|hmac|rsa)\b/ },
    { name: 'SJCL',              regex: /\bsjcl\.(?:encrypt|decrypt|hash)\b/ },
    { name: 'sm-crypto (国密)',  regex: /\b(?:sm2|sm3|sm4)\.(?:doEncrypt|doDecrypt|encrypt|decrypt|sign)\b/ },
    { name: 'Web Crypto API',    regex: /\bcrypto\.subtle\.(?:encrypt|decrypt|sign|verify|importKey|generateKey|digest)\b/ },
    { name: 'bcrypt.js',         regex: /\bbcrypt(?:js)?\.(?:hash|compare|genSalt)\b/ },
    { name: 'tweetnacl',         regex: /\bnacl\.(?:secretbox|box|sign|hash)\b/ },
    { name: 'CryptoJS Extended', regex: /\bCryptoJS\.(?:AES|DES|TripleDES|RC4|Rabbit|PBKDF2|EvpKDF|pad|mode)\b/ },
    { name: 'Node crypto',       regex: /\bcrypto\.(?:createCipheriv?|createDecipheriv?|createHash|createHmac|pbkdf2|scrypt|randomBytes|publicEncrypt|privateDecrypt|sign|verify)\b/ },
    { name: 'libsodium',         regex: /\bsodium\.(?:crypto_|from_base64|to_base64)/ },
    { name: 'jsrsasign',         regex: /\b(?:KJUR|KEYUTIL|RSAKey|Signature)\b/ },
    { name: 'elliptic',          regex: /\b(?:new\s+)?(?:elliptic\.)?ec\s*\(\s*["'](?:secp256k1|p256|ed25519)["']\s*\)/ },
    { name: 'Base64/encoding',   regex: /\b(?:Base64\.(?:encode|decode|atob|btou)|atob|btoa)\s*\(/ }
  ],
  cryptoAlgos: [
    { name: 'AES',          regex: /\b(?:aes[-_]?(?:128|192|256)?[-_]?(?:cbc|gcm|ctr|cfb|ofb|ecb)|AES\.(?:encrypt|decrypt))\b/i },
    { name: 'DES/3DES',     regex: /\b(?:DES|3DES|TripleDES|TDEA|des-ede3?-(?:cbc|ecb))\b/i },
    { name: 'RSA',          regex: /\b(?:RSA-?(?:OAEP|PSS|PKCS1)?|setPublicKey|setPrivateKey)\b/ },
    { name: 'RC4',          regex: /\b(?:RC4|ARC4|arcfour)\b/i },
    { name: 'MD5',          regex: /\b(?:CryptoJS\.MD5|md5)\s*\(/ },
    { name: 'SHA-1',        regex: /\b(?:CryptoJS\.SHA1|sha1)\s*\(/ },
    { name: 'SHA-2',        regex: /\b(?:SHA-?(?:256|384|512)|sha(?:256|384|512))\b/ },
    { name: 'HMAC',         regex: /\bHmac(?:SHA(?:1|256|384|512)|MD5)\b/ },
    { name: 'SM2/3/4 国密', regex: /\b(?:SM2|SM3|SM4|sm2|sm3|sm4)\b/ },
    { name: 'AES-CBC', family: 'AES', decrypt: 'AES-CBC 需要 key + IV + padding；常见用 CryptoJS.AES.decrypt 或 WebCrypto AES-CBC 解密。', regex: /\b(?:aes[-_]?(?:128|192|256)?[-_]?cbc|mode\s*[:=]\s*CryptoJS\.mode\.CBC|AES-CBC)\b/i },
    { name: 'AES-GCM', family: 'AES', decrypt: 'AES-GCM 需要 key + nonce/IV + authTag；缺少 tag 或 AAD 会解密失败。', regex: /\b(?:aes[-_]?(?:128|192|256)?[-_]?gcm|AES-GCM|GCM)\b/i },
    { name: 'AES-CTR', family: 'AES', decrypt: 'AES-CTR 需要 key + counter/nonce；同一 key+counter 复用会泄露明文异或关系。', regex: /\b(?:aes[-_]?(?:128|192|256)?[-_]?ctr|AES-CTR|CryptoJS\.mode\.CTR)\b/i },
    { name: 'AES-ECB', family: 'AES', decrypt: 'AES-ECB 只需要 key 即可逐块解密；无 IV，相同明文块会产生相同密文块。', regex: /\b(?:aes[-_]?(?:128|192|256)?[-_]?ecb|AES-ECB|CryptoJS\.mode\.ECB)\b/i },
    { name: 'AES-CFB/OFB', family: 'AES', decrypt: 'CFB/OFB 需要 key + IV；常见于 CryptoJS.mode.CFB/OFB 或 OpenSSL cipher 名称。', regex: /\b(?:aes[-_]?(?:128|192|256)?[-_]?(?:cfb|ofb)|CryptoJS\.mode\.(?:CFB|OFB))\b/i },
    { name: 'DES/3DES', family: 'DES', decrypt: 'DES/3DES 需要 key + IV/模式；CryptoJS.DES/TripleDES.decrypt 或 OpenSSL des-ede3-* 可解，算法已淘汰。', regex: /\b(?:DES|3DES|TripleDES|TDEA|des-ede3?-(?:cbc|ecb)|CryptoJS\.(?:DES|TripleDES))\b/i },
    { name: 'RC4/Rabbit', family: 'stream', decrypt: 'RC4/Rabbit 是流加密，通常只需 key/seed；同密钥流复用会严重泄露明文。', regex: /\b(?:RC4|ARC4|arcfour|Rabbit|CryptoJS\.(?:RC4|Rabbit))\b/i },
    { name: 'RSA-OAEP', family: 'RSA', decrypt: 'RSA-OAEP 需要私钥和 hash 参数；公钥只能加密/验签，不能解密。', regex: /\b(?:RSA[-_]?OAEP|RSA-OAEP|oaepHash|RSA\/ECB\/OAEP)\b/i },
    { name: 'RSA-PKCS1', family: 'RSA', decrypt: 'RSA PKCS#1 v1.5 需要私钥；若服务端错误可区分，可能存在 padding oracle 风险。', regex: /\b(?:RSA[-_]?PKCS1|pkcs1|PKCS1Padding|RSA\/ECB\/PKCS1Padding)\b/i },
    { name: 'RSA-PSS', family: 'RSA', decrypt: 'RSA-PSS 是签名算法，不可解密；验证需要公钥、hash、saltLength。', regex: /\b(?:RSA[-_]?PSS|RSA-PSS|pss|saltLength)\b/i },
    { name: 'ECC/ECDSA', family: 'ECC', decrypt: 'ECDSA/EdDSA 是签名，不可解密；ECDH 需要私钥派生共享密钥。', regex: /\b(?:ECDSA|ECDH|Ed25519|ed25519|secp256k1|prime256v1|P-256|elliptic)\b/i },
    { name: 'SM2', family: 'SM', decrypt: 'SM2 非对称加密需要私钥解密；签名验签需要公钥和 userId/ZA 参数。', regex: /\b(?:SM2|sm2)\.(?:doEncrypt|doDecrypt|encrypt|decrypt|sign|verify)\b/ },
    { name: 'SM3', family: 'SM', decrypt: 'SM3 是摘要算法，不可解密；只能用于校验/碰撞风险评估。', regex: /\b(?:SM3|sm3)\.(?:digest|hash|encrypt)\b/ },
    { name: 'SM4', family: 'SM', decrypt: 'SM4 是对称分组加密，解密需要 key + mode + IV/padding。', regex: /\b(?:SM4|sm4)\.(?:encrypt|decrypt|doEncrypt|doDecrypt)\b/ },
    { name: 'PBKDF2', family: 'kdf', decrypt: 'PBKDF2 是密钥派生算法不可解密；验证需 password + salt + iterations + hash。', regex: /\b(?:PBKDF2|pbkdf2|CryptoJS\.PBKDF2)\b/i },
    { name: 'scrypt', family: 'kdf', decrypt: 'scrypt 是 KDF 不可解密；验证需 password + salt + N/r/p 参数。', regex: /\b(?:scrypt|crypto\.scrypt)\b/i },
    { name: 'bcrypt', family: 'password-hash', decrypt: 'bcrypt 是密码哈希不可解密；只能使用候选口令 compare/verify。', regex: /\b(?:bcrypt(?:js)?\.(?:hash|compare)|\$2[aby]\$\d{2}\$)\b/i },
    { name: 'Base64', family: 'encoding', decrypt: 'Base64 只是编码，不是加密；atob/Base64.decode 即可还原原文。', regex: /\b(?:atob|btoa|Base64\.(?:encode|decode|atob|btou))\s*\(/ }
  ],
  bundlers: [
    { name: 'Webpack', regex: /\b(?:__webpack_require__|webpackJsonp|webpackChunk|__webpack_modules__|__webpack_exports__)\b/ },
    { name: 'Vite/Rollup', regex: /\b(?:__vitePreload|import\.meta\.env|System\.register|ROLLUP_FILE_URL_|vite\/preload-helper)\b/ },
    { name: 'Parcel', regex: /\b(?:parcelRequire|newRequire|modules,\s*cache,\s*entry|hmrAcceptRun)\b/ },
    { name: 'Browserify', regex: /\b(?:function\s+require\s*\([^)]*\)\s*\{|\b__browserify_require__|browserify)\b/ },
    { name: 'Next.js', regex: /\b(?:__NEXT_DATA__|_next\/static|webpackChunk_N_E|next\/dist)\b/ },
    { name: 'Nuxt', regex: /\b(?:__NUXT__|_nuxt\/|nuxt-link|nuxt\.config)\b/ },
    { name: 'Angular CLI', regex: /\b(?:ngDevMode|ngJitMode|webpackJsonp|zone\.js|main\.[a-f0-9]{8,}\.js)\b/ },
    { name: 'Umi/Dva', regex: /\b(?:window\.g_umi|umi-request|dva\/core|__UMI_PLUGIN)\b/ }
  ],
  obfuscators: [
    { name: 'JavaScript Obfuscator', severity: 'medium', regex: /\b(?:_0x[a-f0-9]{4,}|String\.fromCharCode|atob\s*\(\s*['"][A-Za-z0-9+/=]{80,}['"]|\\x[0-9a-fA-F]{2})\b/ },
    { name: 'eval/Function 动态执行', severity: 'high', regex: /\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode|_0x[a-f0-9]+)/i },
    { name: 'Packer eval', severity: 'high', regex: /\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)/ },
    { name: '高密度十六进制转义', severity: 'medium', regex: /(?:\\x[0-9a-fA-F]{2}){12,}/ },
    { name: '超长单行压缩代码', severity: 'info', regex: /[^\n]{12000,}/ }
  ],
  apiPatterns: [
    { name: 'URL/接口路径', regex: /["'`]((?:https?:)?\/\/[^"'`\s<>]+|\/(?:api|admin|auth|user|v\d+|graphql|oauth|pay|order|upload|download|internal|openapi|gateway)\/[^"'`\s<>]{1,240})["'`]/g },
    { name: '请求方法调用', regex: /\.(?:get|post|put|patch|delete|request)\s*\(\s*["'`]([^"'`]{2,240})["'`]/g },
    { name: 'GraphQL 端点', regex: /["'`]([^"'`]*\/graphql(?:\/[^"'`]*)?)["'`]/g }
  ],
  exposures: [
    { name: 'Source Map 引用',     severity: 'medium', regex: /\/\/[#@]\s*sourceMappingURL=\S+\.map\b/ },
    { name: 'console.log 残留',    severity: 'info',   regex: /\bconsole\.(?:log|debug|trace)\s*\(/ },
    { name: '内网 IP 引用',        severity: 'low',    regex: /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b/ },
    { name: 'localhost 引用',     severity: 'low',    regex: /\b(?:127\.0\.0\.1|localhost)(?::\d+)?\b/ },
    { name: 'TODO/FIXME 注释',     severity: 'info',   regex: /\/\/\s*(?:TODO|FIXME|XXX|HACK|BUG)\b/i },
    { name: 'Debug 模式开关',      severity: 'low',    regex: /\b(?:DEBUG|isDebug|__DEV__)\s*[:=]\s*(?:true|1|"true")\b/ }
  ]
};

if (typeof self !== 'undefined') {
  self.JS_EXTRACTOR_RULES = {
    RULES, META_RULES,
    util: { b64urlToStr, luhnOk, shannonEntropy, isPlaceholder, isDocumentationDomain, isReservedIp, isLikelyInternationalPhone, inCryptoContext, inSecuritySensitiveContext }
  };
}
