(function (global) {
  const SEV_WEIGHT = { critical: 100, high: 70, medium: 35, low: 12, info: 3 };
  const CODE_EXT = /\.(?:js|mjs|cjs|jsx|ts|tsx|vue|svelte|json|map|html?|xml|txt)(?:[?#]|$)/i;
  const SKIP_EXT = /\.(?:css|png|jpe?g|gif|webp|avif|bmp|ico|svg|mp4|webm|mp3|wav|ogg|woff2?|ttf|otf|eot)(?:[?#]|$)/i;
  const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

  function normalizeEndpoint(raw, baseUrl) {
    const value = String(raw || '').trim();
    if (!value || value.length > 300) return null;
    if (/^(?:javascript:|mailto:|tel:|data:|blob:)/i.test(value)) return null;
    if (SKIP_EXT.test(value)) return null;
    try {
      const url = new URL(value, baseUrl);
      if (!/^https?:$/.test(url.protocol)) return null;
      return url.href;
    } catch {
      return null;
    }
  }

  function isSensitiveApi(url) {
    const text = String(url || '').toLowerCase();
    return /\/(?:admin|manage|system|internal|debug|actuator|swagger|openapi|user|account|member|order|pay|payment|wallet|balance|role|permission|config|upload|download|export|import|token|auth|login|logout)\b/.test(text);
  }

  function isLikelyApi(value) {
    const v = String(value || '').trim();
    if (!v || v.length > 260 || SKIP_EXT.test(v)) return false;
    if (/^(?:https?:)?\/\//i.test(v)) return true;
    return /^(?:\/|\.\.?\/)?(?:api|admin|auth|user|v\d+|graphql|oauth|pay|order|upload|download|internal|openapi|gateway|captcha|login|logout|system|config|manage|member|wallet|role|permission)\b/i.test(v);
  }

  function addFinding(out, item) {
    const key = `${item.type}|${item.target || ''}|${item.file || ''}|${item.title}`;
    if (out._seen.has(key)) return;
    out._seen.add(key);
    out.push({
      id: `vuln-${out.length + 1}`,
      severity: item.severity || 'info',
      type: item.type || 'source-audit',
      title: item.title,
      target: item.target || '',
      file: item.file || '',
      evidence: item.evidence || '',
      codeSnippet: item.codeSnippet || '',
      recommendation: item.recommendation || '',
      confidence: item.confidence || 'suspected',
      verification: item.verification || null
    });
  }

  function classifyVerificationType(finding) {
    const type = finding?.type || '';
    if (type === 'api-doc-exposure') return 'doc-endpoint-probe';
    if (['cors-risk', 'xss-risk', 'redirect-ssrf-risk', 'upload-risk', 'multi-tenant-risk', 'csrf-session-risk'].includes(type)) return 'poc-guidance';
    if (['unauthorized-api', 'auth-inconsistency', 'data-exposure', 'method-exposure', 'sensitive-api'].includes(type)) return 'safe-api-probe';
    if (type === 'client-auth') return 'route-guard-bypass';
    if (['idor-risk', 'payment-logic', 'logic-risk'].includes(type)) return 'manual-guidance';
    if (finding?.target && /^https?:\/\//i.test(finding.target)) return 'safe-api-probe';
    return 'manual-guidance';
  }

  function manualVerificationGuide(finding) {
    const type = finding?.type || '';
    if (type === 'idor-risk') {
      return '准备两个同权限账号，分别获取各自资源 ID；只替换目标 ID 复放读取请求，确认服务端是否校验资源归属。';
    }
    if (type === 'payment-logic') {
      return '在测试环境使用正常订单流程，拦截金额/优惠/订单状态参数；服务端应重新计算金额，禁止信任客户端价格。';
    }
    if (type === 'client-auth') {
      return '清除本地 token/localStorage 后访问路由，并直接请求对应后端接口；如果接口仍返回业务数据，说明服务端缺少鉴权。';
    }
    if (type === 'logic-risk') {
      return '检查该开关是否只存在于测试环境；生产环境应删除客户端放行逻辑，并由服务端做权限判定。';
    }
    return '该发现需要人工复核。建议在测试环境中使用最小权限账号验证，不执行破坏性操作。';
  }

  function buildVerificationPoc(finding, method = 'GET', baseUrl = '') {
    const type = finding?.type || '';
    const origin = getOrigin(baseUrl || finding?.target || '');
    const target = finding?.target || (origin ? `${origin}/` : '<target-url>');
    const safeMethod = methodSafe(method);
    const marker = `CSG_POC_${Date.now().toString(36)}`;
    if (type === 'api-doc-exposure') {
      return {
        summary: '已生成接口文档暴露验证 PoC',
        text: buildDocCandidates(finding, baseUrl).map((url) => `${safeMethod} ${url}`).join('\n')
      };
    }
    if (type === 'xss-risk') {
      const payload = `<csg-poc data-marker="${marker}"></csg-poc>`;
      const pocUrl = `${target.split('#')[0]}#${encodeURIComponent(payload)}`;
      return {
        summary: '已生成 DOM XSS 无害 marker PoC',
        text: [
          `PoC URL: ${pocUrl}`,
          `Marker: ${marker}`,
          '验证点: 打开 PoC 后检查页面 DOM/响应预览中是否出现 csg-poc 或 marker；如被作为 HTML 节点渲染，说明输入进入 HTML sink。',
          '注意: 该 PoC 不包含脚本执行，只验证 HTML 注入路径。'
        ].join('\n')
      };
    }
    if (type === 'redirect-ssrf-risk') {
      const sep = target.includes('?') ? '&' : '?';
      const external = 'https://example.com/csg-poc';
      return {
        summary: '已生成开放重定向/SSRF 参数 PoC',
        text: [
          `${safeMethod} ${target}${sep}redirectUrl=${encodeURIComponent(external)}`,
          `${safeMethod} ${target}${sep}returnUrl=${encodeURIComponent(external)}`,
          `${safeMethod} ${target}${sep}callbackUrl=${encodeURIComponent(external)}`,
          `${safeMethod} ${target}${sep}targetUrl=${encodeURIComponent(external)}`,
          '确认标准: 返回 30x 且 Location 指向外部域名，或响应内容显示服务端请求了该外部 URL。'
        ].join('\n')
      };
    }
    if (type === 'upload-risk') {
      return {
        summary: '已生成文件上传校验 PoC 模板',
        text: [
          `curl -i -X ${methodSafe(method, 'POST')} "${target}" \\`,
          '  -F "file=@csg-poc.txt;type=text/plain" \\',
          `  -F "marker=${marker}"`,
          'csg-poc.txt 内容建议: CSG_UPLOAD_POC_MARKER',
          '确认标准: 服务端必须拒绝不符合业务白名单的文件，或只保存到不可执行、不可直接解析的位置。'
        ].join('\n')
      };
    }
    if (type === 'multi-tenant-risk') {
      return {
        summary: '已生成租户/归属越权复测 PoC',
        text: [
          `1. 账号 A 正常请求: ${safeMethod} ${target}`,
          '2. 账号 B 正常请求同类资源，记录 tenantId/orgId/ownerId/userId/resourceId。',
          '3. 使用账号 A 的 Cookie/Token，把请求中的归属字段替换为账号 B 的值。',
          '4. 确认标准: 服务端应返回 401/403 或空数据；若返回 B 的数据或允许变更，即存在越权风险。'
        ].join('\n')
      };
    }
    if (type === 'csrf-session-risk') {
      return {
        summary: '已生成 CSRF 复测 PoC 模板',
        text: [
          '<form method="POST" action="<replace-with-test-endpoint>">',
          `  <input name="marker" value="${marker}">`,
          '  <button type="submit">CSRF PoC</button>',
          '</form>',
          '<script>document.forms[0].submit()</script>',
          '确认标准: 缺少 CSRF Token 或 Origin/Referer 不可信时，服务端应拒绝变更类请求。仅在测试环境替换真实 endpoint。'
        ].join('\n')
      };
    }
    if (type === 'cors-risk') {
      return {
        summary: '已生成 CORS 配置验证 PoC',
        text: [
          `curl -i "${target}" -H "Origin: https://csg-poc.invalid"`,
          `curl -i -X OPTIONS "${target}" -H "Origin: https://csg-poc.invalid" -H "Access-Control-Request-Method: ${safeMethod}"`,
          '确认标准: 不应同时出现 Access-Control-Allow-Origin 反射/通配 与 Access-Control-Allow-Credentials: true。'
        ].join('\n')
      };
    }
    return {
      summary: '已生成手动复测建议',
      text: `${safeMethod} ${target}\n${manualVerificationGuide(finding)}`
    };
  }

  function methodSafe(method, fallback = 'GET') {
    const allowed = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
    const value = String(method || fallback).toUpperCase();
    return allowed.has(value) ? value : fallback;
  }

  function getOrigin(url) {
    try {
      return new URL(url).origin;
    } catch {
      return '';
    }
  }

  function buildDocCandidates(finding, baseUrl = '') {
    const origin = getOrigin(baseUrl || finding?.target || '');
    if (!origin) return [];
    const text = `${finding?.target || ''}\n${finding?.evidence || ''}\n${finding?.file || ''}`.toLowerCase();
    const paths = [
      '/v3/api-docs',
      '/v2/api-docs',
      '/swagger-ui/index.html',
      '/swagger-ui.html',
      '/swagger-resources',
      '/doc.html',
      '/openapi.json',
      '/graphql',
      '/graphiql'
    ];
    const prioritized = paths.sort((a, b) => Number(text.includes(b.replace(/^\//, ''))) - Number(text.includes(a.replace(/^\//, ''))));
    return prioritized.map((path) => `${origin}${path}`).slice(0, 9);
  }

  function inferVerificationStatus(finding, probeResult) {
    if (!probeResult || probeResult.error) return { status: 'unknown', detail: probeResult?.error || 'no result' };
    const checks = probeResult.checks || [];
    const anonOk = checks.some((c) => c.anon?.status >= 200 && c.anon?.status < 300);
    const anonDenied = checks.some((c) => c.anon?.status === 401 || c.anon?.status === 403);
    const authOk = checks.some((c) => c.auth?.status >= 200 && c.auth?.status < 300);
    const sensitivePreview = checks.some((c) => /(?:password|passwd|token|secret|idcard|身份证|手机号|mobile|accessKey|privateKey)/i.test(c.anon?.preview || ''));
    const allowDanger = checks.some((c) => /\b(?:PUT|PATCH|DELETE|POST)\b/i.test(c.anon?.allow || ''));
    const type = finding?.type || '';
    if (['unauthorized-api', 'sensitive-api'].includes(type) && anonOk) return { status: 'confirmed', detail: '匿名请求返回 2xx' };
    if (type === 'auth-inconsistency' && anonOk && !authOk) return { status: 'confirmed', detail: '匿名可访问但带登录态失败，鉴权状态异常' };
    if (type === 'data-exposure' && sensitivePreview) return { status: 'confirmed', detail: '匿名响应包含敏感字段关键字' };
    if (type === 'method-exposure' && allowDanger) return { status: 'likely', detail: 'OPTIONS 暴露变更类方法' };
    if (anonDenied) return { status: 'not-reproduced', detail: '匿名请求被 401/403 拦截' };
    return { status: 'unknown', detail: '安全探测未得到明确结论' };
  }

  function apiRiskScore(api, test) {
    let score = api?.sensitive || isSensitiveApi(api?.url || test?.url) ? 18 : 0;
    const checks = test?.checks || [];
    for (const check of checks) {
      const anon = check.anon || {};
      const auth = check.auth || {};
      const anonOk = anon.status >= 200 && anon.status < 300;
      const authDenied = auth.status === 401 || auth.status === 403;
      const authOk = auth.status >= 200 && auth.status < 300;
      if (anonOk && (api?.sensitive || isSensitiveApi(test?.url))) score += 90;
      if (authDenied && anonOk) score += 110;
      if (authOk && anonOk && auth.preview && anon.preview && auth.preview !== anon.preview) score += 25;
      if (anon.preview && /(?:password|passwd|token|secret|idcard|identity|mobile|phone|accessKey|privateKey|session|cookie)/i.test(anon.preview)) score += 120;
      if (anon.allow && /\b(?:POST|PUT|PATCH|DELETE)\b/i.test(anon.allow)) score += 24;
      if (anon.status >= 500 || auth.status >= 500) score += 8;
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(check.method) && anonOk) score += 18;
    }
    if (test?.error) score += 2;
    return score;
  }

  function auditSourceHeuristics(source, file = '') {
    const findings = [];
    findings._seen = new Set();
    if (!source || typeof source !== 'string') return findings;
    const sample = source.slice(0, 1200000);
    const snippet = (pattern) => sourceSnippet(sample, pattern);

    const authMeta = /\b(?:requiresAuth|requireAuth|needLogin|loginRequired|permission|permissions|roles?|authority)\b/i.test(sample);
    const routerGuard = /\b(?:beforeEach|beforeEnter|beforeResolve|afterEach)\s*\(/.test(sample);
    const clientToken = /\b(?:localStorage|sessionStorage|document\.cookie)\.(?:getItem|setItem)|\b(?:token|accessToken|Authorization)\b/i.test(sample);
    if ((authMeta || routerGuard) && clientToken) {
      const routeTarget = pickSensitiveRouteTarget(extractRoutePathStrings(sample));
      addFinding(findings, {
        severity: 'medium',
        type: 'client-auth',
        title: '前端路由鉴权依赖客户端状态',
        target: routeTarget,
        file,
        evidence: '发现路由守卫/meta 鉴权与 token/localStorage/sessionStorage 逻辑',
        codeSnippet: snippet(/.{0,120}(?:beforeEach|beforeEnter|beforeResolve|requiresAuth|requireAuth|localStorage|sessionStorage|document\.cookie|accessToken|Authorization).{0,220}/is),
        recommendation: '确认服务端接口是否逐项校验身份和权限，前端守卫只能作为体验层控制。',
        confidence: 'likely'
      });
    }

    if (/\b(?:isAdmin|admin|superAdmin|debug|mockAuth|bypassAuth)\s*[:=]\s*(?:true|1|["']true["'])/i.test(sample)) {
      addFinding(findings, {
        severity: 'high',
        type: 'logic-risk',
        title: '疑似硬编码管理/调试鉴权开关',
        file,
        evidence: '命中 isAdmin/debug/mockAuth/bypassAuth 等放行字段',
        codeSnippet: snippet(/.{0,120}(?:isAdmin|superAdmin|debug|mockAuth|bypassAuth)\s*[:=]\s*(?:true|1|["']true["']).{0,160}/is),
        recommendation: '移除客户端放行开关，服务端基于会话和权限表重新判定。',
        confidence: 'likely'
      });
    }

    const apiMatches = extractApiStrings(sample);
    for (const api of apiMatches.slice(0, 300)) {
      if (isSensitiveApi(api)) {
        addFinding(findings, {
          severity: /\/(?:admin|internal|debug|actuator|config|permission|role)\b/i.test(api) ? 'medium' : 'low',
          type: 'sensitive-api',
          title: '源码暴露敏感接口路径',
          target: api,
          file,
          evidence: api,
          codeSnippet: snippet(api),
          recommendation: '对敏感接口做服务端鉴权、审计日志和最小权限控制。',
          confidence: 'likely'
        });
      }
      if (/[?&](?:id|userId|uid|accountId|orderId|tenantId)=/.test(api) || /\/(?:user|order|account|tenant|member)\/[:{]?\w+/i.test(api)) {
        addFinding(findings, {
          severity: 'medium',
          type: 'idor-risk',
          title: '疑似对象 ID 接口，需人工验证越权',
          target: api,
          file,
          evidence: api,
          codeSnippet: snippet(api),
          recommendation: '用两个低权限账号交叉验证资源归属，服务端必须校验对象所有者和租户边界。',
          confidence: 'suspected'
        });
      }
    }

    if (/\b(?:price|amount|money|totalFee|payAmount|orderAmount|discount|coupon)\b/i.test(sample) &&
        /\b(?:pay|order|checkout|trade|wallet|balance)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'medium',
        type: 'payment-logic',
        title: '支付/订单金额逻辑暴露，需验证参数篡改',
        file,
        evidence: '发现 price/amount/pay/order/coupon 等组合逻辑',
        codeSnippet: snippet(/.{0,120}(?:price|amount|money|totalFee|payAmount|orderAmount|discount|coupon).{0,260}(?:pay|order|checkout|trade|wallet|balance).{0,120}/is),
        recommendation: '订单金额、优惠、余额变更必须由服务端重新计算，不信任客户端提交值。',
        confidence: 'suspected'
      });
    }

    if (/\b(?:Access-Control-Allow-Origin)\b[^;\n]{0,120}\*/i.test(sample) &&
        /\b(?:Access-Control-Allow-Credentials)\b[^;\n]{0,80}true/i.test(sample)) {
      addFinding(findings, {
        severity: 'high',
        type: 'cors-risk',
        title: '疑似 CORS 宽松配置',
        file,
        evidence: 'Access-Control-Allow-Origin:* 与 credentials:true 同时出现',
        codeSnippet: snippet(/.{0,120}Access-Control-Allow-Origin.{0,180}(?:Access-Control-Allow-Credentials|credentials).{0,120}/is),
        recommendation: '限制可信 Origin，避免携带凭证的跨站读取。',
        confidence: 'likely'
      });
    }

    if (/\b(?:swagger|openapi|api-docs|knife4j|springdoc|graphql|graphiql|apollo)\b/i.test(sample) ||
        /\/(?:swagger-ui|swagger-resources|v2\/api-docs|v3\/api-docs|openapi\.json|graphql|graphiql)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'medium',
        type: 'api-doc-exposure',
        title: '疑似接口文档或 GraphQL 调试入口暴露',
        file,
        evidence: '命中 swagger/openapi/knife4j/graphql/graphiql 等接口枚举特征',
        codeSnippet: snippet(/.{0,140}(?:swagger|openapi|api-docs|knife4j|springdoc|graphql|graphiql|apollo|\/v[23]\/api-docs|\/openapi\.json).{0,180}/is),
        recommendation: '生产环境应关闭或鉴权保护接口文档、GraphQL 调试台和 introspection，并审计其中暴露的内部 API。',
        confidence: 'likely'
      });
    }

    if (/\b(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|v-html|dangerouslySetInnerHTML)\b/i.test(sample) &&
        /\b(?:location|searchParams|query|hash|params|decodeURIComponent|route\.query|this\.\$route)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'medium',
        type: 'xss-risk',
        title: '疑似 DOM XSS 数据流',
        file,
        evidence: '发现 URL/路由参数与 HTML 注入 sink 同时出现',
        codeSnippet: snippet(/.{0,140}(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|v-html|dangerouslySetInnerHTML).{0,260}(?:location|searchParams|query|hash|params|decodeURIComponent|route\.query|this\.\$route).{0,140}/is),
        recommendation: '对进入 innerHTML/document.write/v-html 的数据做白名单过滤或改用 textContent，服务端也要做输出编码。',
        confidence: 'suspected'
      });
    }

    if (/\b(?:redirectUrl|returnUrl|callbackUrl|nextUrl|targetUrl|url)\b/i.test(sample) &&
        /\b(?:location\.href|location\.replace|window\.open|fetch|axios|XMLHttpRequest)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'medium',
        type: 'redirect-ssrf-risk',
        title: '疑似重定向/外部 URL 参数风险',
        file,
        evidence: '发现 redirect/return/callback/target URL 参数与跳转或请求逻辑',
        codeSnippet: snippet(/.{0,140}(?:redirectUrl|returnUrl|callbackUrl|nextUrl|targetUrl|url).{0,260}(?:location\.href|location\.replace|window\.open|fetch|axios|XMLHttpRequest).{0,140}/is),
        recommendation: '跳转地址和服务端代请求目标必须做同源/白名单校验，禁止直接信任用户可控 URL。',
        confidence: 'suspected'
      });
    }

    if (/\b(?:upload|fileUpload|multipart|FormData|accept|beforeUpload|fileType|extension|ext)\b/i.test(sample) &&
        /\b(?:\.exe|\.jsp|\.php|\.asp|\.aspx|\.jspx|\.html|image\/|application\/octet-stream|size)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'medium',
        type: 'upload-risk',
        title: '疑似文件上传校验依赖前端',
        file,
        evidence: '发现上传组件、文件类型/后缀/大小校验逻辑',
        codeSnippet: snippet(/.{0,140}(?:upload|fileUpload|multipart|FormData|accept|beforeUpload|fileType|extension|ext).{0,260}(?:\.exe|\.jsp|\.php|\.asp|\.aspx|\.jspx|\.html|image\/|application\/octet-stream|size).{0,140}/is),
        recommendation: '上传类型、后缀、MIME、文件内容和存储路径必须在服务端校验，前端限制只能作为体验提示。',
        confidence: 'suspected'
      });
    }

    if (/\b(?:tenantId|orgId|companyId|deptId|ownerId|userId|roleId|permissionId)\b/i.test(sample) &&
        /\b(?:params|query|body|data|headers|localStorage|sessionStorage)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'medium',
        type: 'multi-tenant-risk',
        title: '疑似租户/角色/归属字段可控',
        file,
        evidence: '发现 tenant/org/owner/user/role/permission 等字段与请求参数或本地状态组合',
        codeSnippet: snippet(/.{0,140}(?:tenantId|orgId|companyId|deptId|ownerId|userId|roleId|permissionId).{0,260}(?:params|query|body|data|headers|localStorage|sessionStorage).{0,140}/is),
        recommendation: '服务端必须从会话上下文计算租户和权限边界，不应信任客户端提交的归属、角色或权限字段。',
        confidence: 'suspected'
      });
    }

    if (/\b(?:withCredentials\s*:\s*true|credentials\s*:\s*["']include["']|SameSite\s*=\s*None|csrf\s*:\s*false|xsrfCookieName|xsrfHeaderName)\b/i.test(sample)) {
      addFinding(findings, {
        severity: 'low',
        type: 'csrf-session-risk',
        title: '疑似跨站凭证或 CSRF 相关配置',
        file,
        evidence: '发现 withCredentials/credentials include/SameSite=None/CSRF 配置特征',
        codeSnippet: snippet(/.{0,140}(?:withCredentials\s*:\s*true|credentials\s*:\s*["']include["']|SameSite\s*=\s*None|csrf\s*:\s*false|xsrfCookieName|xsrfHeaderName).{0,220}/is),
        recommendation: '检查变更类接口是否具备 CSRF Token、SameSite、Origin/Referer 校验和服务端鉴权。',
        confidence: 'suspected'
      });
    }

    delete findings._seen;
    return findings;
  }

  function extractApiStrings(source) {
    const out = new Set();
    const patterns = [
      /["'`]((?:https?:)?\/\/[^"'`\s<>]{2,260})["'`]/g,
      /["'`]((?:\/|\.\.?\/)?(?:api|admin|auth|user|v\d+|graphql|oauth|pay|order|upload|download|internal|openapi|gateway|captcha|login|logout|system|config|manage|member|wallet|role|permission)[^"'`\s<>]{0,240})["'`]/gi,
      /\b(?:fetch|open|new\s+Request)\s*\(\s*["'`]([^"'`]{2,260})["'`]/g,
      /\b(?:axios|request|http|service|client|api)\s*\.\s*(?:get|post|put|patch|delete|head|options|request)\s*\(\s*["'`]([^"'`]{2,260})["'`]/gi,
      /\burl\s*:\s*["'`]([^"'`]{2,260})["'`]/gi
    ];
    for (const re of patterns) {
      let m, count = 0;
      while ((m = re.exec(source)) !== null) {
        if (isLikelyApi(m[1])) out.add(m[1]);
        if (++count >= 500) break;
      }
    }
    return Array.from(out);
  }

  function extractRoutePathStrings(source) {
    const out = new Set();
    const patterns = [
      /\bpath\s*:\s*["'`]([^"'`]{1,160})["'`]/gi,
      /\bredirect\s*:\s*["'`]([^"'`]{1,160})["'`]/gi,
      /\b(?:router\.push|router\.replace|next|navigateTo)\s*\(\s*["'`]([^"'`]{1,160})["'`]/gi,
      /["'`]((?:\/|#\/)(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|member|order|wallet|profile|center|internal|debug)[^"'`\s<>]{0,140})["'`]/gi
    ];
    for (const re of patterns) {
      let m, count = 0;
      while ((m = re.exec(source)) !== null) {
        const path = normalizeRoutePath(m[1]);
        if (path) out.add(path);
        if (++count > 400) break;
      }
    }
    return Array.from(out);
  }

  function pickSensitiveRouteTarget(paths) {
    const list = (paths || []).filter(Boolean);
    return list.find((p) => /(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|member|order|wallet|internal|debug)/i.test(p)) ||
      list.find((p) => p !== '/' && !/[():*+?]/.test(p)) || '';
  }

  function normalizeRoutePath(path) {
    const value = String(path || '').trim();
    if (!value || value.length > 180 || /^(?:https?:|javascript:|mailto:|data:)/i.test(value)) return '';
    const clean = value.replace(/^#/, '');
    if (!clean.startsWith('/')) return '';
    if (/\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:[?#]|$)/i.test(clean)) return '';
    return clean;
  }

  function riskLevel(score) {
    if (score >= 180) return '严重';
    if (score >= 90) return '高危';
    if (score >= 45) return '中危';
    if (score > 0) return '低危';
    return '安全';
  }

  async function safeDelay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function sourceSnippet(source, needle, pad = 180) {
    const text = String(source || '');
    if (!text) return '';
    let index = -1;
    let length = 0;
    if (needle instanceof RegExp) {
      const flags = needle.flags.includes('g') ? needle.flags : `${needle.flags}g`;
      const re = new RegExp(needle.source, flags);
      const m = re.exec(text);
      if (m) {
        index = m.index;
        length = m[0].length;
      }
    } else {
      const value = String(needle || '');
      if (value) {
        index = text.indexOf(value);
        length = value.length;
      }
    }
    if (index < 0) return '';
    const start = Math.max(0, index - pad);
    const end = Math.min(text.length, index + length + pad);
    return text.slice(start, end).replace(/\s+/g, ' ').trim().slice(0, 900);
  }

  if (typeof document === 'undefined') {
    global.CSG_VULN_AUDIT_HELPERS = {
      normalizeEndpoint, isSensitiveApi, isLikelyApi, auditSourceHeuristics,
      extractApiStrings, riskLevel, classifyVerificationType,
      manualVerificationGuide, inferVerificationStatus, apiRiskScore,
      buildVerificationPoc, buildDocCandidates, extractRoutePathStrings,
      pickSensitiveRouteTarget
    };
    return;
  }

  const params = new URLSearchParams(location.search);
  const targetTabId = Number(params.get('tabId'));
  const els = {
    origin: document.getElementById('origin'),
    depth: document.getElementById('depth'),
    concurrency: document.getElementById('concurrency'),
    apiTest: document.getElementById('apiTest'),
    start: document.getElementById('start'),
    stop: document.getElementById('stop'),
    exportJson: document.getElementById('exportJson'),
    exportMd: document.getElementById('exportMd'),
    riskLevel: document.getElementById('riskLevel'),
    riskScore: document.getElementById('riskScore'),
    fileCount: document.getElementById('fileCount'),
    codeSize: document.getElementById('codeSize'),
    apiCount: document.getElementById('apiCount'),
    apiTested: document.getElementById('apiTested'),
    findingCount: document.getElementById('findingCount'),
    progress: document.getElementById('progress'),
    runApiTests: document.getElementById('runApiTests'),
    apiBody: document.getElementById('apiBody'),
    search: document.getElementById('search'),
    severity: document.getElementById('severity'),
    findings: document.getElementById('findings'),
    apis: document.getElementById('apis'),
    apiStatus: document.getElementById('apiStatus')
  };

  const state = {
    origin: '',
    baseUrl: '',
    stopped: false,
    running: false,
    files: [],
    apis: new Map(),
    findings: [],
    apiTests: [],
    score: 0,
    verifyingIds: new Set()
  };

  els.start.addEventListener('click', runAudit);
  els.stop.addEventListener('click', () => { state.stopped = true; setProgress('正在停止...'); });
  els.exportJson.addEventListener('click', exportJson);
  els.exportMd.addEventListener('click', exportMd);
  els.runApiTests.addEventListener('click', () => runSelectedApiTests());
  els.search.addEventListener('input', renderFindings);
  els.severity.addEventListener('change', renderFindings);

  init().catch((err) => setProgress(`初始化失败: ${err.message}`, true));

  async function init() {
    const tab = await chrome.tabs.get(targetTabId);
    state.baseUrl = tab?.url || '';
    state.origin = new URL(state.baseUrl).origin;
    els.origin.textContent = state.baseUrl;
    await runAudit();
  }

  async function runAudit() {
    if (state.running) return;
    state.running = true;
    state.stopped = false;
    state.files = [];
    state.apis = new Map();
    state.findings = [];
    state.apiTests = [];
    state.score = 0;
    state.verifyingIds.clear();
    state._seen = new Set();
    renderAll();

    const maxDepth = clamp(Number(els.depth.value || 2), 1, 4);
    const concurrency = clamp(Number(els.concurrency.value || 4), 1, 8);
    const initial = await collectInitialTargets();
    const queue = [];
    const seen = new Set();
    const enqueue = (item) => {
      if (!item?.url) return;
      const key = item.inline ? `inline:${item.url}` : item.url;
      if (seen.has(key) || queue.length > 700) return;
      seen.add(key);
      queue.push(item);
    };

    enqueue({ url: `[page] ${initial.url}`, inline: true, content: initial.html || '', depth: 0, kind: 'document' });
    for (const item of initial.resources || []) enqueue({ ...item, depth: 0 });
    for (const item of initial.scripts || []) enqueue({ ...item, depth: 0, kind: item.inline ? 'inline' : 'script' });
    for (const link of initial.links || []) enqueue({ url: link, depth: 1, kind: 'document' });

    let cursor = 0, active = 0, done = 0;
    await new Promise((resolve) => {
      const pump = () => {
        if (state.stopped) {
          if (active === 0) resolve();
          return;
        }
        while (active < concurrency && cursor < queue.length) {
          const item = queue[cursor++];
          active++;
          processCodeItem(item, enqueue, maxDepth)
            .catch((err) => addAuditFinding({
              severity: 'info',
              type: 'fetch',
              title: '源码资源读取失败',
              target: item.url,
              evidence: err.message,
              confidence: 'suspected'
            }))
            .finally(() => {
              done++;
              active--;
              setProgress(`源码审计 ${done}/${queue.length}`);
              renderAll();
              if (cursor >= queue.length && active === 0) resolve();
              else pump();
            });
        }
      };
      pump();
    });

    if (!state.stopped && els.apiTest.checked) {
      await runApiTests(concurrency, {
        methods: getSelectedApiMethods(),
        body: getApiBody()
      });
    }
    updateScore();
    renderAll();
    setProgress(state.stopped ? '已停止' : '完成');
    state.running = false;
  }

  async function collectInitialTargets() {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SCRIPTS', tabId: targetTabId });
    const scripts = resp?.scripts || [];
    let snapshot = {};
    try {
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: targetTabId },
        func: collectPageAuditSnapshot
      });
      snapshot = result?.result || {};
    } catch (err) {
      snapshot = { url: state.baseUrl, html: '', resources: [], links: [], error: err.message };
    }
    return { ...snapshot, scripts };
  }

  function collectPageAuditSnapshot() {
    const resources = new Map();
    const links = new Set();
    const addResource = (raw, kind = 'resource') => {
      try {
        const url = new URL(raw, location.href);
        if (!/^https?:$/.test(url.protocol)) return;
        if (/\.(?:css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|mp3)(?:[?#]|$)/i.test(url.href)) return;
        if (kind === 'script' || kind === 'document' || /\.(?:js|mjs|cjs|json|map|html?|xml|txt)(?:[?#]|$)/i.test(url.href)) {
          resources.set(url.href, { url: url.href, kind });
        }
      } catch { /* ignore */ }
    };
    for (const el of document.querySelectorAll('script[src]')) addResource(el.src || el.getAttribute('src'), 'script');
    for (const el of document.querySelectorAll('iframe[src], frame[src]')) addResource(el.src || el.getAttribute('src'), 'document');
    for (const el of document.querySelectorAll('link[href]')) {
      const rel = (el.rel || '').toLowerCase();
      if (rel.includes('stylesheet') || rel.includes('icon')) continue;
      addResource(el.href || el.getAttribute('href'), rel.includes('manifest') ? 'manifest' : 'resource');
    }
    for (const entry of performance.getEntriesByType('resource')) {
      if (['css', 'img', 'image', 'font', 'media', 'audio', 'video'].includes(entry.initiatorType)) continue;
      addResource(entry.name, entry.initiatorType === 'script' ? 'script' : 'resource');
    }
    for (const a of document.querySelectorAll('a[href]')) {
      try {
        const url = new URL(a.href || a.getAttribute('href'), location.href);
        if (url.origin === location.origin && !/\.(?:css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|mp3|zip|rar|pdf)(?:[?#]|$)/i.test(url.href)) {
          links.add(url.href);
        }
      } catch { /* ignore */ }
    }
    return {
      url: location.href,
      html: '<!DOCTYPE html>\n' + document.documentElement.outerHTML,
      resources: Array.from(resources.values()),
      links: Array.from(links).slice(0, 80)
    };
  }

  async function processCodeItem(item, enqueue, maxDepth) {
    let text = item.content || '';
    if (!item.inline) {
      text = await fetchText(item.url);
    }
    const file = item.inline ? item.url : item.url;
    state.files.push({ file, size: text.length, kind: item.kind || 'resource' });
    analyzeCodeText(text, file);
    if (item.kind === 'sourcemap' || /\.map(?:[?#]|$)/i.test(item.url || '')) {
      analyzeSourceMap(text, item.url || file);
    }
    discoverFromText(text, item.url || state.baseUrl, item.depth || 0, maxDepth).forEach(enqueue);
    await safeDelay(0);
  }

  function analyzeSourceMap(text, mapUrl) {
    let map;
    try { map = JSON.parse(text); } catch { return; }
    const contents = Array.isArray(map.sourcesContent) ? map.sourcesContent : [];
    const sources = Array.isArray(map.sources) ? map.sources : [];
    for (let i = 0; i < contents.length && i < 180; i++) {
      const source = contents[i];
      if (!source || typeof source !== 'string') continue;
      const name = sources[i] || `source-${i}.js`;
      const file = `[sourcemap] ${name}`;
      state.files.push({ file, size: source.length, kind: 'source' });
      analyzeCodeText(source, file);
    }
  }

  async function fetchText(url) {
    const target = new URL(url, state.baseUrl);
    const sameOrigin = target.origin === state.origin;
    const res = await fetch(target.href, {
      credentials: sameOrigin ? 'include' : 'omit',
      cache: 'force-cache',
      referrer: state.baseUrl
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    return text.length > 6 * 1024 * 1024 ? text.slice(0, 6 * 1024 * 1024) : text;
  }

  function analyzeCodeText(text, file) {
    const normalized = normalizeSource(text);
    const analyzer = global.JS_EXTRACTOR_ANALYZER;
    if (analyzer) {
      const result = analyzer.analyzeSource(normalized, { url: file });
      for (const f of result.findings || []) {
        if (f.confidence === 'suspected') continue;
        addAuditFinding({
          severity: f.severity,
          type: f.category,
          title: f.ruleName,
          target: f.captured || f.match,
          file,
          evidence: f.evidence || f.description || '',
          codeSnippet: f.context ? `${f.context.before || ''}${f.context.match || f.match || ''}${f.context.after || ''}`.replace(/\s+/g, ' ').trim().slice(0, 900) : sourceSnippet(normalized, f.match || f.captured),
          recommendation: f.recommendation || '',
          confidence: f.confidence
        });
      }
      for (const api of result.stats?.apiEndpoints || []) addApi(api.value, file);
      for (const route of result.stats?.routes || []) addApi(route.value, file);
    }
    for (const api of extractApiStrings(normalized)) addApi(api, file, sourceSnippet(normalized, api));
    for (const finding of auditSourceHeuristics(normalized, file)) addAuditFinding(finding);
  }

  function discoverFromText(text, baseUrl, depth, maxDepth) {
    const out = [];
    const add = (raw, kind = 'resource', nextDepth = depth) => {
      try {
        const url = new URL(raw, baseUrl);
        if (!/^https?:$/.test(url.protocol)) return;
        if (SKIP_EXT.test(url.href)) return;
        if (url.origin !== state.origin && kind === 'document') return;
        if (kind !== 'document' && !CODE_EXT.test(url.href)) return;
        out.push({ url: url.href, kind, depth: nextDepth });
      } catch { /* ignore */ }
    };
    let m;
    const codeRe = /["'`]((?:(?:https?:)?\/\/|\/|\.{1,2}\/|(?:static|assets|js|dist|chunks|_next|_nuxt)\/)[^"'`\s<>]{1,240}\.(?:js|mjs|cjs|json|map|html?)(?:\?[^"'`\s<>]*)?)["'`]/gi;
    while ((m = codeRe.exec(text)) !== null) add(m[1], CODE_EXT.test(m[1]) ? 'resource' : 'document');
    const mapRe = /\/\/[#@]\s*sourceMappingURL=([^\s"'<>]+)/g;
    while ((m = mapRe.exec(text)) !== null) add(m[1], 'sourcemap');
    if (depth < maxDepth) {
      const hrefRe = /href\s*=\s*["']([^"']+)["']/gi;
      while ((m = hrefRe.exec(text)) !== null) add(m[1], 'document', depth + 1);
    }
    return out.slice(0, 180);
  }

  async function runSelectedApiTests() {
    if (state.running) {
      setProgress('扫描仍在运行，请稍后再批量测试 API');
      return;
    }
    const concurrency = clamp(Number(els.concurrency.value || 4), 1, 8);
    state.stopped = false;
    await runApiTests(concurrency, {
      methods: getSelectedApiMethods(),
      body: getApiBody(),
      manual: true
    });
    renderAll();
  }

  function getSelectedApiMethods() {
    const selected = Array.from(document.querySelectorAll('input[name="apiMethod"]:checked'))
      .map((el) => el.value.toUpperCase());
    return selected.length ? Array.from(new Set(selected)) : ['GET'];
  }

  function getApiBody() {
    const text = els.apiBody.value.trim();
    return text || '{}';
  }

  function confirmRiskyMethods(methods) {
    const risky = methods.filter((m) => !['GET', 'HEAD', 'OPTIONS'].includes(m));
    if (!risky.length) return true;
    return window.confirm(`你选择了 ${risky.join(', ')} 请求方法，可能触发业务操作。请确认只在授权测试环境中执行。`);
  }

  async function runApiTests(concurrency, options = {}) {
    const methods = normalizeMethods(options.methods || ['GET', 'POST']);
    if (!confirmRiskyMethods(methods)) {
      els.apiStatus.textContent = '已取消';
      return;
    }
    const endpoints = Array.from(state.apis.values())
      .map((x) => x.url)
      .filter((url) => {
        try { return new URL(url).origin === state.origin; } catch { return false; }
      })
      .slice(0, 160);
    let cursor = 0, active = 0, done = 0;
    els.apiStatus.textContent = `testing ${endpoints.length} · ${methods.join('/')}`;
    await new Promise((resolve) => {
      const pump = () => {
        if (state.stopped) {
          if (active === 0) resolve();
          return;
        }
        while (active < concurrency && cursor < endpoints.length) {
          const url = endpoints[cursor++];
          active++;
          testEndpoint(url, { methods, body: options.body || '{}' })
            .then((result) => {
              upsertApiTest(result);
              assessApiResult(result);
            })
            .catch((err) => upsertApiTest({ url, methods, error: err.message }))
            .finally(() => {
              done++;
              active--;
              els.apiStatus.textContent = `${done}/${endpoints.length}`;
              renderAll();
              if (cursor >= endpoints.length && active === 0) resolve();
              else pump();
            });
        }
      };
      pump();
    });
  }

  function normalizeMethods(methods) {
    const allowed = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
    return Array.from(new Set(methods.map((m) => String(m || '').toUpperCase()).filter((m) => allowed.has(m))));
  }

  function upsertApiTest(result) {
    state.apiTests = state.apiTests.filter((x) => x.url !== result.url);
    state.apiTests.push(result);
  }

  async function testEndpoint(url, options = {}) {
    const methods = normalizeMethods(options.methods || SAFE_METHODS);
    const result = { url, sensitive: isSensitiveApi(url), methods, checks: [], testedAt: Date.now() };
    for (const method of methods) {
      const auth = await probe(url, method, 'include', options);
      const anon = await probe(url, method, 'omit', options);
      result.checks.push({ method, auth, anon });
      await safeDelay(40);
    }
    return result;
  }

  async function probe(url, method, credentials, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6500);
    try {
      const headers = { 'X-AegisScope-Audit': 'batch-api-test' };
      const init = {
        method,
        credentials,
        cache: 'no-store',
        redirect: 'manual',
        signal: controller.signal,
        headers
      };
      if (!['GET', 'HEAD'].includes(method)) {
        const body = options.body || '{}';
        headers['Content-Type'] = looksLikeJson(body) ? 'application/json' : 'text/plain;charset=UTF-8';
        init.body = body;
      }
      const res = await fetch(url, {
        ...init
      });
      const ct = res.headers.get('content-type') || '';
      const allow = res.headers.get('allow') || '';
      let preview = '';
      if (method !== 'HEAD' && /(?:json|text|javascript|xml|html|plain)/i.test(ct)) {
        preview = (await res.text()).slice(0, 800);
      }
      return { status: res.status, ok: res.ok, redirected: res.redirected, type: res.type, contentType: ct, allow, preview };
    } catch (err) {
      return { error: err.name === 'AbortError' ? 'timeout' : err.message };
    } finally {
      clearTimeout(timer);
    }
  }

  function looksLikeJson(text) {
    try {
      JSON.parse(text);
      return true;
    } catch {
      return false;
    }
  }

  function assessApiResult(result) {
    const sensitive = result.sensitive;
    const sourceMeta = getApiSourceMeta(result.url);
    for (const check of result.checks || []) {
      const anon = check.anon || {};
      const auth = check.auth || {};
      const anonOk = anon.status >= 200 && anon.status < 300;
      const authDenied = auth.status === 401 || auth.status === 403;
      if (sensitive && anonOk) {
        addAuditFinding({
          severity: 'high',
          type: 'unauthorized-api',
          title: '敏感接口匿名可访问',
          target: result.url,
          file: sourceMeta.file,
          evidence: `${check.method} without credentials => HTTP ${anon.status}`,
          codeSnippet: sourceMeta.codeSnippet,
          recommendation: '敏感接口应在服务端校验登录态和权限，匿名请求返回 401/403。',
          confidence: 'confirmed'
        });
      }
      if (authDenied && anonOk) {
        addAuditFinding({
          severity: 'critical',
          type: 'auth-inconsistency',
          title: '接口鉴权状态异常',
          target: result.url,
          file: sourceMeta.file,
          evidence: `with credentials => ${auth.status}, without credentials => ${anon.status}`,
          codeSnippet: sourceMeta.codeSnippet,
          recommendation: '检查会话识别、网关鉴权和缓存策略是否存在绕过。',
          confidence: 'confirmed'
        });
      }
      if (anon.preview && /(?:password|passwd|token|secret|idcard|身份证|手机号|mobile|accessKey|privateKey)/i.test(anon.preview)) {
        addAuditFinding({
          severity: 'critical',
          type: 'data-exposure',
          title: '匿名响应疑似包含敏感数据',
          target: result.url,
          file: sourceMeta.file,
          evidence: anon.preview.slice(0, 220),
          codeSnippet: sourceMeta.codeSnippet,
          recommendation: '接口响应需最小化字段，敏感数据必须鉴权后返回并脱敏。',
          confidence: 'likely'
        });
      }
      if (anon.allow && /\b(?:PUT|PATCH|DELETE|POST)\b/i.test(anon.allow)) {
        addAuditFinding({
          severity: 'low',
          type: 'method-exposure',
          title: '接口暴露可变更 HTTP 方法',
          target: result.url,
          file: sourceMeta.file,
          evidence: `Allow: ${anon.allow}`,
          codeSnippet: sourceMeta.codeSnippet,
          recommendation: '确认变更类方法均有 CSRF/鉴权/权限校验。',
          confidence: 'suspected'
        });
      }
    }
  }

  function addApi(raw, file, codeSnippet = '') {
    const url = normalizeEndpoint(raw, state.baseUrl);
    if (!url) return;
    const item = state.apis.get(url) || { url, files: new Set(), snippets: [], count: 0, sensitive: isSensitiveApi(url) };
    item.count++;
    if (file) item.files.add(file);
    if (codeSnippet && item.snippets.length < 5 && !item.snippets.includes(codeSnippet)) item.snippets.push(codeSnippet);
    state.apis.set(url, item);
  }

  function getApiSourceMeta(url) {
    const item = state.apis.get(url);
    const files = item?.files ? Array.from(item.files) : [];
    return {
      file: files[0] || '',
      codeSnippet: item?.snippets?.[0] || (url ? `接口: ${url}` : '')
    };
  }

  function addAuditFinding(item) {
    if (!state._seen) state._seen = new Set();
    const key = `${item.type}|${item.target}|${item.file}|${item.title}|${item.evidence}`;
    if (state._seen.has(key)) return;
    state._seen.add(key);
    state.findings.push({
      id: `finding-${state.findings.length + 1}`,
      ...item,
      verification: item.verification || null
    });
    updateScore();
  }

  function updateScore() {
    state.score = state.findings.reduce((sum, f) => sum + (SEV_WEIGHT[f.severity] || 0), 0);
  }

  function renderAll() {
    updateScore();
    els.riskLevel.textContent = riskLevel(state.score);
    els.riskScore.textContent = `score ${state.score}`;
    els.fileCount.textContent = String(state.files.length);
    els.codeSize.textContent = formatBytes(state.files.reduce((sum, f) => sum + (f.size || 0), 0));
    els.apiCount.textContent = String(state.apis.size);
    els.apiTested.textContent = `${state.apiTests.length} tested`;
    els.findingCount.textContent = String(state.findings.length);
    renderFindings();
    renderApis();
  }

  function renderFindings() {
    const keyword = els.search.value.trim().toLowerCase();
    const sev = els.severity.value;
    const list = state.findings
      .filter((f) => sev === 'all' || f.severity === sev)
      .filter((f) => !keyword || JSON.stringify(f).toLowerCase().includes(keyword))
      .sort((a, b) => (SEV_WEIGHT[b.severity] || 0) - (SEV_WEIGHT[a.severity] || 0));
    els.findings.innerHTML = '';
    if (!list.length) {
      els.findings.innerHTML = '<div class="finding"><div class="title">暂无发现</div><div class="desc">等待扫描结果或调整过滤条件。</div></div>';
      return;
    }
    for (const f of list) {
      const node = document.createElement('div');
      node.className = `finding ${f.severity}`;
      const verification = renderVerification(f);
      const isVerifying = state.verifyingIds.has(f.id) || f.verification?.status === 'running';
      const selectedMethod = f.verification?.method && f.verification.method !== 'ROUTE' ? f.verification.method : 'GET';
      const autoVerify = canAutoVerifyFinding(f);
      const mode = classifyVerificationType(f);
      const actionHtml = autoVerify
        ? `${mode === 'route-guard-bypass' ? '' : `<select class="verify-method" title="HTTP Method" ${isVerifying ? 'disabled' : ''}>${renderMethodOptions(selectedMethod)}</select>`}
            <button class="verify" data-id="${escapeHtml(f.id)}" ${isVerifying ? 'disabled' : ''}>${isVerifying ? '验证中...' : '验证'}</button>`
        : `<span class="tag low" title="该类型需要业务上下文，插件不自动发送验证请求">人工复核</span>`;
      const sourceHtml = renderFindingSource(f);
      const manualHtml = !autoVerify && !f.verification ? renderManualReviewHint(f) : '';
      node.innerHTML = `
        <div class="topline">
          <div class="title">${escapeHtml(f.title)}</div>
          <div class="inline-actions">
            <span class="tag ${f.severity}">${sevLabel(f.severity)}</span>
            ${actionHtml}
          </div>
        </div>
        <div class="desc">${escapeHtml(f.recommendation || '')}</div>
        <div class="meta">${escapeHtml(f.target || f.file || '')}</div>
        ${f.evidence ? `<div class="meta">证据: ${escapeHtml(f.evidence)}</div>` : ''}
        ${sourceHtml}
        ${verification}
        ${manualHtml}
        <div><span class="tag">${escapeHtml(f.type)}</span><span class="tag">${escapeHtml(f.confidence || 'suspected')}</span></div>`;
      node.querySelector('.verify')?.addEventListener('click', () => {
        const method = node.querySelector('.verify-method')?.value || 'GET';
        verifyFinding(f.id, method).catch((err) => {
          const target = state.findings.find((x) => x.id === f.id);
          if (target) {
            setVerification(target, 'unknown', `验证异常: ${err?.message || String(err)}`, { method });
          }
          state.verifyingIds.delete(f.id);
          renderAll();
        });
      });
      els.findings.appendChild(node);
    }
  }

  function renderVerification(f) {
    if (!f.verification) return '';
    const status = f.verification.status || 'unknown';
    const cls = status === 'confirmed' ? 'critical' : status === 'likely' ? 'medium' : status === 'not-reproduced' ? 'low' : 'info';
    const detail = f.verification.detail || '';
    const at = f.verification.verifiedAt ? ` · ${new Date(f.verification.verifiedAt).toLocaleString()}` : '';
    const poc = f.verification.poc ? `<div class="preview">${escapeHtml(f.verification.poc)}</div>` : '';
    const packages = renderProbeResponsePackages(f.verification.probe, { emptyText: '本次验证未产生 HTTP 返回包。' });
    return `<div class="verification"><span class="tag ${cls}">${escapeHtml(verifyLabel(status))}</span><span class="meta">${escapeHtml(detail + at)}</span></div>${poc}${packages}`;
  }

  function canAutoVerifyFinding(finding) {
    return ['doc-endpoint-probe', 'route-guard-bypass', 'safe-api-probe'].includes(classifyVerificationType(finding));
  }

  function renderFindingSource(f) {
    const rows = [];
    if (f.file) rows.push(`<div><span class="source-label">文件</span>${escapeHtml(f.file)}</div>`);
    if (f.codeSnippet) rows.push(`<pre>${escapeHtml(f.codeSnippet)}</pre>`);
    if (!rows.length) return '';
    return `<div class="source-box">${rows.join('')}</div>`;
  }

  function renderManualReviewHint(f) {
    const poc = buildVerificationPoc(f, 'GET', state.baseUrl);
    return `<div class="verification manual-review">
      <span class="tag low">复核方式</span>
      <span class="meta">${escapeHtml(poc.summary || manualVerificationGuide(f))}</span>
    </div>
    <div class="preview">${escapeHtml(poc.text || manualVerificationGuide(f))}</div>`;
  }

  function setVerification(finding, status, detail, extra = {}) {
    finding.verification = {
      ...(finding.verification || {}),
      ...extra,
      status,
      detail,
      verifiedAt: Date.now()
    };
  }

  function verifyLabel(status) {
    return ({
      confirmed: '已验证',
      likely: '大概率',
      'not-reproduced': '未复现',
      manual: '需人工',
      running: '验证中',
      canceled: '已取消',
      unknown: '未知'
    })[status] || status;
  }

  function renderApis() {
    const tested = new Map(state.apiTests.map((x) => [x.url, x]));
    const apis = Array.from(state.apis.values())
      .sort((a, b) => apiRiskScore(b, tested.get(b.url)) - apiRiskScore(a, tested.get(a.url)) ||
        Number(b.sensitive) - Number(a.sensitive) || b.count - a.count)
      .slice(0, 260);
    els.apis.innerHTML = '';
    if (!apis.length) {
      els.apis.innerHTML = '<div class="api"><div class="method">No API</div><div class="meta">尚未提取到接口资产。</div></div>';
      return;
    }
    for (const api of apis) {
      const test = tested.get(api.url);
      const riskScore = apiRiskScore(api, test);
      const checksHtml = test ? renderApiChecks(test) : '<div class="meta">pending</div>';
      const packages = renderProbeResponsePackages(test, { emptyText: '暂未获取到返回包。' });
      const node = document.createElement('div');
      node.className = 'api';
      node.innerHTML = `
        <div class="api-row">
          <div class="method">${escapeHtml(api.url)}</div>
          <div class="api-actions">
            <span class="tag ${apiRiskTagClass(riskScore)}">risk ${riskScore}</span>
            <span class="tag ${api.sensitive ? 'medium' : 'low'}">${api.sensitive ? 'sensitive' : 'api'}</span>
            <select class="manual-method" title="HTTP Method">${renderMethodOptions('GET')}</select>
            <button class="manual-api-test">手动测试</button>
          </div>
        </div>
        <div class="checks">${checksHtml}</div>
        ${packages}`;
      node.querySelector('.manual-api-test')?.addEventListener('click', () => {
        const method = node.querySelector('.manual-method')?.value || 'GET';
        runSingleApiTest(api.url, method);
      });
      els.apis.appendChild(node);
    }
  }

  function renderApiChecks(test) {
    if (test.error) return `<div class="meta">${escapeHtml(test.error)}</div>`;
    return (test.checks || []).map((c) => {
      const auth = c.auth?.status || c.auth?.error || '-';
      const anon = c.anon?.status || c.anon?.error || '-';
      const cls = c.anon?.status >= 200 && c.anon?.status < 300 ? 'medium' : c.anon?.status === 401 || c.anon?.status === 403 ? 'low' : '';
      return `<div class="check-line">
        <span class="tag">${escapeHtml(c.method)}</span>
        <span class="tag">auth ${escapeHtml(auth)}</span>
        <span class="tag ${cls}">anon ${escapeHtml(anon)}</span>
        ${c.anon?.contentType ? `<span class="tag">${escapeHtml(c.anon.contentType.split(';')[0])}</span>` : ''}
      </div>`;
    }).join('');
  }

  function firstPreview(test) {
    if (!test?.checks?.length) return '';
    for (const c of test.checks) {
      if (c.anon?.preview) return `[${c.method} anon]\n${c.anon.preview}`;
      if (c.auth?.preview) return `[${c.method} auth]\n${c.auth.preview}`;
    }
    return '';
  }

  function renderProbeResponsePackages(probeData, options = {}) {
    const entries = collectResponsePackages(probeData);
    if (!entries.length) {
      return options.emptyText ? `<div class="response-packages"><div class="response-title">${escapeHtml(options.emptyText)}</div></div>` : '';
    }
    const html = entries.slice(0, options.limit || 18).map((entry) => {
      const parts = (entry.responses || []).map((res) => {
        const status = res.error ? `error=${res.error}` : `HTTP ${res.status || '-'}`;
        const meta = [res.label, status, res.contentType, res.allow ? `Allow: ${res.allow}` : '']
          .filter(Boolean)
          .join(' · ');
        const body = res.body || (res.error ? '' : '(无响应体或内容类型不可预览)');
        return `<div class="response-part">
          <div class="meta">${escapeHtml(meta)}</div>
          <pre>${escapeHtml(body)}</pre>
        </div>`;
      }).join('');
      return `<div class="response-package">
        <div class="response-title">
          <span class="tag">${escapeHtml(entry.method || '-')}</span>
          <span>${escapeHtml(entry.label)}</span>
        </div>
        ${parts}
      </div>`;
    }).join('');
    return `<div class="response-packages">${html}</div>`;
  }

  function collectResponsePackages(probeData) {
    if (!probeData?.checks?.length) return [];
    const entries = [];
    for (const check of probeData.checks) {
      if (check.auth || check.anon) {
        entries.push({
          method: check.method || '-',
          label: probeData.url || '接口返回包',
          responses: [
            buildResponsePart('带登录态返回包', check.auth),
            buildResponsePart('匿名返回包', check.anon)
          ].filter(Boolean)
        });
        continue;
      }
      if (check.result) {
        entries.push({
          method: check.method || '-',
          label: check.url || '验证返回包',
          responses: [buildResponsePart('验证返回包', check.result)].filter(Boolean)
        });
      }
    }
    return entries;
  }

  function buildResponsePart(label, response) {
    if (!response) return null;
    return {
      label,
      status: response.status,
      error: response.error,
      contentType: response.contentType || response.type || '',
      allow: response.allow || '',
      body: response.preview || ''
    };
  }

  function formatResponsePackages(probeData, maxBody = 600) {
    const entries = collectResponsePackages(probeData);
    return entries.map((entry) => {
      const responses = (entry.responses || []).map((res) => {
        const status = res.error ? `error=${res.error}` : `HTTP ${res.status || '-'}`;
        const body = res.body ? res.body.replace(/\s+/g, ' ').slice(0, maxBody) : '(无响应体或内容类型不可预览)';
        return `${res.label} ${status}\n${body}`;
      }).join('\n');
      return `${entry.method} ${entry.label}\n${responses}`;
    }).join('\n\n');
  }

  function renderMethodOptions(selected = 'GET') {
    return ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE']
      .map((method) => `<option value="${method}"${method === selected ? ' selected' : ''}>${method}</option>`)
      .join('');
  }

  function apiRiskTagClass(score) {
    if (score >= 120) return 'critical';
    if (score >= 80) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  }

  async function runSingleApiTest(url, method = 'GET') {
    const methods = normalizeMethods([method]);
    if (!methods.length || !confirmRiskyMethods(methods)) return;
    els.apiStatus.textContent = `manual ${methods[0]}`;
    try {
      const result = await testEndpoint(url, { methods, body: getApiBody() });
      upsertApiTest(result);
      assessApiResult(result);
      els.apiStatus.textContent = 'manual done';
    } catch (err) {
      upsertApiTest({ url, methods, error: err.message });
      els.apiStatus.textContent = 'manual error';
    }
    renderAll();
  }

  async function verifyDocExposure(finding, method = 'GET') {
    const safe = SAFE_METHODS.includes(method) ? method : 'GET';
    const candidates = buildDocCandidates(finding, state.baseUrl);
    const checks = [];
    for (const url of candidates) {
      const res = await probe(url, safe, 'include', { body: '{}' });
      checks.push({ url, method: safe, result: res });
      const preview = res.preview || '';
      const docLike = /(?:openapi|swagger|paths|components|graphql|graphiql|knife4j|api-docs)/i.test(preview) ||
        /(?:json|html|text)/i.test(res.contentType || '');
      if (res.status >= 200 && res.status < 300 && docLike) {
        return {
          status: 'confirmed',
          detail: `发现可访问接口文档入口: ${url} HTTP ${res.status}`,
          poc: buildVerificationPoc(finding, safe, state.baseUrl).text,
          probe: { checks }
        };
      }
      await safeDelay(30);
    }
    const reachable = checks.find((x) => x.result?.status >= 200 && x.result?.status < 400);
    return {
      status: reachable ? 'likely' : 'not-reproduced',
      detail: reachable ? `发现疑似文档/调试入口: ${reachable.url} HTTP ${reachable.result.status}` : '常见文档入口未复现 2xx/3xx',
      poc: buildVerificationPoc(finding, safe, state.baseUrl).text,
      probe: { checks }
    };
  }

  async function verifyClientRouteGuard(finding) {
    const desiredPath = normalizeRoutePath(finding.target || '');
    const [result] = await chrome.scripting.executeScript({
      target: { tabId: targetTabId },
      world: 'MAIN',
      func: bypassClientRouteGuardInPage,
      args: [desiredPath]
    });
    let payload = result?.result || {};
    if (payload.fallbackUrl) {
      await chrome.tabs.update(targetTabId, { url: payload.fallbackUrl });
      await waitForAuditTabSettled();
      payload = { ...payload, navigated: true, method: 'URL fallback', href: payload.fallbackUrl };
    }
    const changed = Number(payload.guardChanged || 0) + Number(payload.metaChanged || 0);
    const route = payload.targetPath || desiredPath || '';
    const status = payload.ok && (payload.navigated || payload.routeChanged || payload.fallbackUrl) ? 'likely' : 'unknown';
    return {
      status,
      detail: payload.ok
        ? `已尝试绕过前端路由守卫并进入 ${route || '候选路由'}，清理/修改 ${changed} 项；请继续观察页面接口是否返回 401/403`
        : `路由守卫绕过失败: ${payload.error || '未发现可用 Vue Router'}`,
      poc: [
        `目标路由: ${route || '(未定位)'}`,
        `方式: ${payload.method || 'runtime patch'}`,
        `清理守卫: ${payload.guardChanged || 0}`,
        `修改鉴权 meta: ${payload.metaChanged || 0}`,
        `命中路由: ${payload.routeName || '-'}`,
        `当前 URL: ${payload.href || ''}`
      ].join('\n'),
      probe: payload
    };
  }

  async function waitForAuditTabSettled(timeout = 4500) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try {
        const tab = await chrome.tabs.get(targetTabId);
        if (tab.status === 'complete') return;
      } catch {
        return;
      }
      await safeDelay(150);
    }
  }

  async function verifyFinding(id, method = 'GET') {
    const finding = state.findings.find((x) => x.id === id);
    if (!finding) return;
    if (state.verifyingIds.has(id)) return;
    const methods = normalizeMethods([method]);
    if (!methods.length) {
      setVerification(finding, 'unknown', `不支持的 HTTP 方法: ${method || '-'}`, { method: String(method || '') });
      renderFindings();
      return;
    }
    if (!confirmRiskyMethods(methods)) {
      setVerification(finding, 'canceled', `已取消 ${methods[0]} 验证；未发送请求。`, { method: methods[0] });
      renderFindings();
      return;
    }

    state.verifyingIds.add(id);
    setVerification(finding, 'running', `正在使用 ${methods[0]} 执行安全验证...`, { method: methods[0] });
    renderFindings();

    try {
      const mode = classifyVerificationType(finding);
      if (mode === 'doc-endpoint-probe') {
        const verdict = await verifyDocExposure(finding, methods[0]);
        finding.verification = {
          ...verdict,
          mode,
          method: methods[0],
          verifiedAt: Date.now()
        };
        renderAll();
        return;
      }
      if (mode === 'poc-guidance') {
        const poc = buildVerificationPoc(finding, methods[0], state.baseUrl);
        finding.verification = {
          status: 'manual',
          detail: poc.summary,
          poc: poc.text,
          mode,
          method: methods[0],
          verifiedAt: Date.now()
        };
        renderFindings();
        return;
      }
      if (mode === 'route-guard-bypass') {
        const verdict = await verifyClientRouteGuard(finding);
        finding.verification = {
          ...verdict,
          mode,
          method: 'ROUTE',
          verifiedAt: Date.now()
        };
        renderAll();
        return;
      }
      if (mode === 'manual-guidance') {
        finding.verification = {
          status: 'manual',
          poc: buildVerificationPoc(finding, methods[0], state.baseUrl).text,
          detail: `${methods[0]}: ${manualVerificationGuide(finding)}`,
          method: methods[0],
          verifiedAt: Date.now()
        };
        renderFindings();
        return;
      }

      const target = normalizeEndpoint(finding.target, state.baseUrl);
      if (!target || new URL(target).origin !== state.origin) {
        finding.verification = {
          status: 'manual',
          detail: '目标不是同源 HTTP 接口，插件不会自动验证；请在授权测试环境手动复核。',
          method: methods[0],
          verifiedAt: Date.now()
        };
        renderFindings();
        return;
      }

      const result = await testEndpoint(target, { methods, body: getApiBody() });
      upsertApiTest(result);
      const verdict = inferVerificationStatus(finding, result);
      finding.verification = {
        ...verdict,
        mode: 'safe-api-probe',
        method: methods[0],
        probe: result,
        verifiedAt: Date.now()
      };
      renderAll();
    } catch (err) {
      finding.verification = {
        status: 'unknown',
        detail: `验证失败: ${err?.message || String(err)}`,
        method: methods[0],
        verifiedAt: Date.now()
      };
      renderAll();
    } finally {
      state.verifyingIds.delete(id);
      renderFindings();
    }
  }

  function bypassClientRouteGuardInPage(desiredPath = '') {
    try {
      const roots = findVueRoots();
      const router = findRouter(roots);
      if (!router) return { ok: false, error: '未发现 Vue Router 运行时实例' };
      const routes = getRoutes(router);
      ensureBackup(router, routes);
      const guardChanged = clearRouteGuards(router, routes);
      const metaChanged = patchRouteAuthMeta(routes);
      const target = selectTargetRoute(routes, desiredPath);
      const targetPath = target?.path || desiredPath || '';
      if (!targetPath) {
        return {
          ok: false,
          error: '未定位到可跳转的鉴权路由',
          guardChanged,
          metaChanged,
          routes: routes.map(serializeRoute).slice(0, 80)
        };
      }
      const beforeHref = location.href;
      const beforeRoute = readRouterPath(router);
      return navigate(targetPath, router).then((nav) => ({
        ok: true,
        targetPath,
        routeName: target?.name || '',
        guardChanged,
        metaChanged,
        beforeHref,
        beforeRoute,
        ...nav
      }));
    } catch (error) {
      return { ok: false, error: error?.message || String(error) };
    }

    function findVueRoots() {
      const out = [];
      const queue = [];
      if (document.body) queue.push(document.body);
      if (document.documentElement) queue.push(document.documentElement);
      const app = document.getElementById('app');
      if (app) queue.unshift(app);
      const seen = new Set();
      let scanned = 0;
      while (queue.length && scanned < 2600) {
        const node = queue.shift();
        scanned++;
        if (!node || seen.has(node)) continue;
        seen.add(node);
        if (node.__vue_app__ || node.__vue__ || node._vnode) out.push(node);
        if (node.children) for (const child of node.children) queue.push(child);
      }
      return out;
    }

    function findRouter(roots) {
      for (const root of roots) {
        const candidates = [];
        const app = root.__vue_app__;
        const vue = root.__vue__;
        if (app) {
          candidates.push(app.config?.globalProperties?.$router, app._instance?.proxy?.$router, app._instance?.ctx?.$router);
          const provides = app._context?.provides || app._instance?.provides;
          if (provides) for (const key of Reflect.ownKeys(provides)) candidates.push(provides[key]);
        }
        if (vue) candidates.push(vue.$router, vue.$root?.$router, vue._routerRoot?._router);
        for (const item of candidates) if (isRouterLike(item)) return item;
      }
      for (const item of [window.$router, window.router, window.__router, window.app?.config?.globalProperties?.$router]) {
        if (isRouterLike(item)) return item;
      }
      return null;
    }

    function isRouterLike(obj) {
      return !!obj && typeof obj === 'object' &&
        (typeof obj.push === 'function' || typeof obj.replace === 'function') &&
        (typeof obj.getRoutes === 'function' || Array.isArray(obj.options?.routes) || obj.matcher);
    }

    function getRoutes(router) {
      if (typeof router.getRoutes === 'function') return router.getRoutes();
      if (router.matcher?.getRoutes) return router.matcher.getRoutes();
      if (Array.isArray(router.options?.routes)) return flattenRoutes(router.options.routes);
      if (router.history?.current?.matched) return router.history.current.matched;
      return [];
    }

    function flattenRoutes(routes, out = []) {
      for (const route of routes || []) {
        out.push(route);
        if (Array.isArray(route.children)) flattenRoutes(route.children, out);
      }
      return out;
    }

    function ensureBackup(router, routes) {
      if (window.__CSG_ROUTE_GUARD_VERIFY_BACKUP__) return;
      const backup = { patchedAt: Date.now(), guardCollections: [], routeGuards: [], metaEntries: [] };
      for (const prop of guardProps()) {
        const val = router[prop];
        if (Array.isArray(val)) backup.guardCollections.push({ target: router, prop, type: 'array', value: val.slice() });
        else if (val instanceof Set) backup.guardCollections.push({ target: router, prop, type: 'set', value: Array.from(val) });
      }
      for (const route of routes) {
        if (route && Object.prototype.hasOwnProperty.call(route, 'beforeEnter')) backup.routeGuards.push({ route, value: route.beforeEnter });
        if (route?.meta && typeof route.meta === 'object') {
          for (const key of Object.keys(route.meta)) {
            if (isAuthKey(key)) backup.metaEntries.push({ meta: route.meta, key, value: route.meta[key] });
          }
        }
      }
      window.__CSG_ROUTE_GUARD_VERIFY_BACKUP__ = backup;
    }

    function clearRouteGuards(router, routes) {
      let changed = 0;
      for (const prop of guardProps()) {
        const val = router[prop];
        if (Array.isArray(val) && val.length) {
          changed += val.length;
          val.length = 0;
        } else if (val instanceof Set && val.size) {
          changed += val.size;
          val.clear();
        }
      }
      for (const route of routes) {
        if (route?.beforeEnter) {
          try {
            route.beforeEnter = undefined;
            changed++;
          } catch { /* ignore readonly route records */ }
        }
      }
      return changed;
    }

    function patchRouteAuthMeta(routes) {
      let changed = 0;
      for (const route of routes) {
        if (!route?.meta || typeof route.meta !== 'object') continue;
        for (const key of Object.keys(route.meta)) {
          if (!isAuthKey(key)) continue;
          const next = nextAuthValue(key, route.meta[key]);
          if (route.meta[key] !== next) {
            route.meta[key] = next;
            changed++;
          }
        }
      }
      return changed;
    }

    function selectTargetRoute(routes, desired) {
      const normalized = normalizeRoute(desired);
      const serial = routes.map((route) => ({ route, ...serializeRoute(route) }))
        .filter((item) => isJumpable(item.path));
      if (normalized) {
        const hit = serial.find((item) => normalizeRoute(item.path) === normalized);
        if (hit) return hit;
      }
      return serial.find((item) => item.hasAuth && item.sensitive) ||
        serial.find((item) => item.sensitive) ||
        serial.find((item) => item.hasAuth) ||
        serial.find((item) => item.path && item.path !== '/');
    }

    function serializeRoute(route) {
      const meta = route?.meta || {};
      const path = route?.path || route?.regex?.toString?.() || '';
      const name = route?.name != null ? String(route.name) : '';
      const hasAuth = !!route?.beforeEnter || Object.keys(meta).some((key) => isAuthKey(key) && Boolean(meta[key]));
      const sensitive = hasAuth || /(?:admin|manage|dashboard|system|config|setting|permission|role|user|account|member|order|wallet|internal|debug)/i.test(`${path} ${name}`);
      return { route, path, name, hasAuth, sensitive };
    }

    async function navigate(path, router) {
      if (router && typeof router.push === 'function') {
        const beforeHref = location.href;
        const beforeRoute = readRouterPath(router);
        let pushError = '';
        try {
          const ret = router.push(path);
          if (ret && typeof ret.then === 'function') await ret;
        } catch (error) {
          pushError = error?.message || String(error);
        }
        await waitForNavigation(router, beforeHref, beforeRoute, path);
        const changed = routeChanged(router, beforeHref, beforeRoute, path);
        if (changed) return { navigated: true, routeChanged: true, method: 'router.push', href: location.href };
        return { navigated: false, routeChanged: false, method: 'router.push-no-change', error: pushError, fallbackUrl: buildFallbackUrl(path, router), href: location.href };
      }
      return { navigated: false, method: 'url-fallback', fallbackUrl: buildFallbackUrl(path, router), href: location.href };
    }

    async function waitForNavigation(router, beforeHref, beforeRoute, targetPath) {
      const start = Date.now();
      while (Date.now() - start < 1400) {
        if (routeChanged(router, beforeHref, beforeRoute, targetPath)) return;
        await new Promise((resolve) => setTimeout(resolve, 80));
      }
    }

    function routeChanged(router, beforeHref, beforeRoute, targetPath) {
      const currentRoute = readRouterPath(router);
      if (currentRoute && normalizeRoute(currentRoute) === normalizeRoute(targetPath)) return true;
      if (currentRoute && currentRoute !== beforeRoute && currentRoute.includes(targetPath)) return true;
      if (location.href !== beforeHref && (location.pathname === targetPath || location.hash === `#${targetPath}`)) return true;
      return false;
    }

    function readRouterPath(router) {
      const cur = router?.currentRoute;
      if (!cur) return '';
      const route = cur.value || cur;
      return route.fullPath || route.path || '';
    }

    function buildFallbackUrl(targetPath, router) {
      const resolved = safeResolve(router, targetPath);
      if (resolved) return resolved;
      const url = new URL(location.href);
      const likelyHashMode = (url.hash && /^#\/?/.test(url.hash)) ||
        /hash/i.test(String(router?.mode || router?.history?.mode || router?.history?.type || ''));
      if (likelyHashMode) {
        url.hash = '#' + targetPath;
        return url.href;
      }
      const base = router?.options?.base || router?.history?.base || '';
      const cleanBase = base && base !== '/' ? String(base).replace(/\/+$/, '') : '';
      url.pathname = `${cleanBase}${targetPath}`.replace(/\/{2,}/g, '/');
      url.search = '';
      url.hash = '';
      return url.href;
    }

    function safeResolve(router, targetPath) {
      try {
        const resolved = router?.resolve?.(targetPath);
        const href = typeof resolved === 'string' ? resolved : resolved?.href;
        if (!href) return '';
        return new URL(href, location.href).href;
      } catch {
        return '';
      }
    }

    function guardProps() {
      return ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks', 'hooks'];
    }

    function isAuthKey(key) {
      return /^(?:requiresAuth|requireAuth|auth|authenticated|needLogin|loginRequired|permission|permissions|role|roles|admin|access|authority|authorize|whiteList|noAuth)$/i.test(key);
    }

    function nextAuthValue(key, value) {
      if (/^(?:permission|permissions|role|roles|authority|access)$/i.test(key)) return Array.isArray(value) ? [] : '';
      if (/^(?:whiteList|noAuth)$/i.test(key)) return true;
      if (typeof value === 'string') return '';
      if (typeof value === 'number') return 0;
      if (Array.isArray(value)) return [];
      if (value && typeof value === 'object') return {};
      return false;
    }

    function normalizeRoute(value) {
      return String(value || '').split('?')[0].replace(/^#/, '').replace(/\/+$/, '') || '/';
    }

    function isJumpable(path) {
      return !!path && typeof path === 'string' && path.startsWith('/') && !/[():*+?]/.test(path);
    }
  }

  function normalizeSource(source) {
    if (!source || source.length < 5000) return source || '';
    const newlineCount = (source.match(/\n/g) || []).length;
    if (newlineCount > source.length / 4000) return source;
    return source.replace(/;/g, ';\n').replace(/\{/g, '{\n').replace(/\}/g, '\n}\n');
  }

  function setProgress(text, error = false) {
    els.progress.textContent = text;
    els.progress.style.color = error ? '#ff9f9f' : '';
  }

  async function exportJson() {
    const payload = buildReport();
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    await chrome.downloads.download({ url, filename: `js-extractor/vuln-audit-${Date.now()}.json`, saveAs: true });
  }

  async function exportMd() {
    const r = buildReport();
    const lines = [
      '# 玄镜 AegisScope 漏洞审计报告',
      `- 目标: ${r.origin}`,
      `- 时间: ${new Date(r.exportedAt).toLocaleString()}`,
      `- 风险: ${r.level} (score=${r.score})`,
      `- 代码文件: ${r.files.length}`,
      `- API: ${r.apis.length}`,
      `- 发现: ${r.findings.length}`,
      '',
      '## 漏洞发现'
    ];
    for (const f of r.findings) {
      lines.push(`### [${sevLabel(f.severity)}] ${f.title}`);
      if (f.target) lines.push(`- 目标: ${f.target}`);
      if (f.file) lines.push(`- 文件: ${f.file}`);
      if (f.evidence) lines.push(`- 证据: ${String(f.evidence).slice(0, 300)}`);
      if (f.codeSnippet) lines.push(`- 代码片段:\n\`\`\`\n${String(f.codeSnippet).slice(0, 1200)}\n\`\`\``);
      if (f.verification) lines.push(`- 验证: ${verifyLabel(f.verification.status)} - ${f.verification.detail || ''}`);
      if (f.verification?.poc) lines.push(`- PoC:\n\`\`\`\n${String(f.verification.poc).slice(0, 1800)}\n\`\`\``);
      const verificationPackages = formatResponsePackages(f.verification?.probe, 800);
      if (verificationPackages) lines.push(`- 验证返回包:\n\`\`\`\n${verificationPackages.slice(0, 2400)}\n\`\`\``);
      if (f.recommendation) lines.push(`- 建议: ${f.recommendation}`);
      lines.push('');
    }
    lines.push('## API 测试');
    for (const t of r.apiTests) {
      lines.push(`- ${t.url}: ${(t.checks || []).map((c) => `${c.method} auth=${c.auth?.status || c.auth?.error || '-'} anon=${c.anon?.status || c.anon?.error || '-'}`).join('; ')}`);
      const packages = formatResponsePackages(t, 500);
      if (packages) lines.push(`  - 返回包:\n\`\`\`\n${packages.slice(0, 2200)}\n\`\`\``);
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    await chrome.downloads.download({ url, filename: `js-extractor/vuln-audit-${Date.now()}.md`, saveAs: true });
  }

  function buildReport() {
    return {
      origin: state.baseUrl,
      exportedAt: new Date().toISOString(),
      level: riskLevel(state.score),
      score: state.score,
      files: state.files,
      apis: Array.from(state.apis.values()).map((a) => ({ ...a, files: Array.from(a.files || []) })),
      findings: state.findings,
      apiTests: state.apiTests
    };
  }

  function formatBytes(n) {
    if (!n) return '0 B';
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  function sevLabel(sev) {
    return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' })[sev] || sev;
  }

  function escapeHtml(str) {
    return String(str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function clamp(n, min, max) {
    return Math.min(max, Math.max(min, Number.isFinite(n) ? n : min));
  }

  global.CSG_VULN_AUDIT_HELPERS = {
    normalizeEndpoint, isSensitiveApi, isLikelyApi, auditSourceHeuristics,
    extractApiStrings, riskLevel, classifyVerificationType,
      manualVerificationGuide, inferVerificationStatus, apiRiskScore,
      buildVerificationPoc, buildDocCandidates, extractRoutePathStrings,
      pickSensitiveRouteTarget
  };
})(typeof globalThis !== 'undefined' ? globalThis : self);
