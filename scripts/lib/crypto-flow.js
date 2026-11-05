// Bounded, scope-aware constant tracing. Source is parsed, never executed.
// resource-profile:flagqaz/AegisScope:248438a8519bb75e:b8e5561ab7b6ef20
(() => {
  const MAX_SOURCE = 8 * 1024 * 1024, MAX_NODES = 300000, MAX_DEPTH = 24;
  const property = node => node?.computed
    ? (node.property?.type === 'Literal' ? String(node.property.value) : '')
    : node?.property?.name || '';
  const memberPath = (node, depth = 0) => {
    if (depth > MAX_DEPTH) return '';
    if (node?.type === 'Identifier') return node.name;
    if (node?.type === 'MemberExpression') {
      const base = memberPath(node.object, depth + 1), key = property(node);
      return base && key ? `${base}.${key}` : '';
    }
    return '';
  };
  const isFunction = node => /^(?:FunctionExpression|FunctionDeclaration|ArrowFunctionExpression)$/.test(node.type);
  const namesInPattern = node => {
    if (!node) return [];
    if (node.type === 'Identifier') return [node.name];
    if (node.type === 'RestElement') return namesInPattern(node.argument);
    if (node.type === 'AssignmentPattern') return namesInPattern(node.left);
    if (node.type === 'ArrayPattern') return node.elements.flatMap(namesInPattern);
    if (node.type === 'ObjectPattern') return node.properties.flatMap(p => namesInPattern(p.value || p.argument));
    return [];
  };

  function analyze(source, options = {}) {
    const findings = [], coverage = { status: 'not-applicable', nodes: 0, calls: 0, unresolved: 0 };
    if (!/\b(?:AES|DES|TripleDES|RC4|RC4Drop|Rabbit|RabbitLegacy|Hmac\w*|HMAC|PBKDF2|EvpKDF|sm4|sm2|createCipheriv|createDecipheriv|createHmac|createSecretKey|createPrivateKey|pbkdf2(?:Sync)?|scrypt(?:Sync)?|importKey|deriveKey|deriveBits|setPrivateKey)\b/.test(source) || /^\s*</.test(source)) return { findings, coverage };
    if (options.findings === 0) return { findings, coverage: { ...coverage, status: 'limited', reason: '加密参数常量追踪命中数量达到上限' } };
    if (source.length > MAX_SOURCE) return { findings, coverage: { ...coverage, status: 'limited', reason: '加密参数常量追踪超过 8MiB 源码预算，其他规则仍继续扫描' } };
    if (!self.acorn) return { findings, coverage: { ...coverage, status: 'failed', reason: '加密参数静态解析器未加载' } };
    const started = Date.now();
    let ast;
    try {
      const parseOptions = { ecmaVersion: 'latest', allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowHashBang: true };
      try { ast = self.acorn.parse(source, { ...parseOptions, sourceType: 'script' }); }
      catch (_) { ast = self.acorn.parse(source, { ...parseOptions, sourceType: 'module' }); }
    } catch (error) {
      return { findings, coverage: { ...coverage, status: 'unparsed', reason: `加密参数常量追踪无法解析此文件（字符偏移 ${Number(error.pos) || 0}），其他规则仍继续扫描` } };
    }
    const scopeOf = new WeakMap(), root = { parent: null, functionScope: true, bindings: new Map() };
    const assignments = [], calls = [], mutations = [];
    const bind = (scope, name, expr, conditional, unknown = false) => {
      let binding = scope.bindings.get(name);
      if (!binding) { binding = { scope, name, writes: [], mutated: false }; scope.bindings.set(name, binding); }
      if (expr || unknown) binding.writes.push({ expr, conditional, unknown });
      return binding;
    };
    const lookup = (scope, name) => {
      for (let current = scope; current; current = current.parent) if (current.bindings.has(name)) return current.bindings.get(name);
      return null;
    };
    const stack = [{ node: ast, scope: root, conditional: false }];
    while (stack.length) {
      const item = stack.pop(), node = item.node;
      if (++coverage.nodes > MAX_NODES || (coverage.nodes % 1024 === 0 && Date.now() - started > 2500)) {
        return { findings, coverage: { ...coverage, status: 'limited', reason: '加密参数常量追踪达到语法节点或时间预算' } };
      }
      let scope = item.scope, conditional = item.conditional;
      if (node.type === 'FunctionDeclaration' && node.id) bind(scope, node.id.name, null, false, true);
      if (isFunction(node)) {
        scope = { parent: scope, functionScope: true, bindings: new Map() };
        conditional = false;
        if (node.id) bind(scope, node.id.name, null, false, true);
        for (const param of node.params) for (const name of namesInPattern(param)) bind(scope, name, null, false, true);
      } else if (node.type === 'BlockStatement' || node.type === 'CatchClause' || /^(?:ForStatement|ForInStatement|ForOfStatement|SwitchStatement)$/.test(node.type)) {
        scope = { parent: scope, functionScope: false, bindings: new Map() };
        if (node.type === 'CatchClause') for (const name of namesInPattern(node.param)) bind(scope, name, null, false, true);
      }
      scopeOf.set(node, scope);
      if (node.type === 'VariableDeclaration') {
        let target = scope;
        if (node.kind === 'var') while (target.parent && !target.functionScope) target = target.parent;
        for (const decl of node.declarations) {
          for (const name of namesInPattern(decl.id)) bind(target, name, decl.id.type === 'Identifier' ? decl.init : null, conditional, decl.id.type !== 'Identifier');
        }
      }
      if (node.type === 'ImportDeclaration') for (const spec of node.specifiers) {
        const binding = bind(scope, spec.local.name, null, false, true);
        const module = { 'crypto-js': 'CryptoJS', 'crypto': 'crypto', 'node:crypto': 'crypto', 'sm-crypto': 'sm' }[node.source.value];
        if (module) binding.apiName = module + (spec.type === 'ImportSpecifier' ? '.' + (spec.imported.name || spec.imported.value) : '');
      }
      if (node.type === 'ClassDeclaration' && node.id) bind(scope, node.id.name, null, false, true);
      if (node.type === 'AssignmentExpression' || node.type === 'UpdateExpression') assignments.push({ node, scope, conditional });
      if (node.type === 'UnaryExpression' && node.operator === 'delete' && node.argument.type === 'MemberExpression') mutations.push({ left: node.argument, scope });
      if (node.type === 'CallExpression') calls.push({ node, scope });
      const childConditional = conditional || /^(?:IfStatement|ConditionalExpression|LogicalExpression|SwitchCase|ForStatement|ForInStatement|ForOfStatement|WhileStatement|DoWhileStatement|TryStatement)$/.test(node.type);
      for (const key of Object.keys(node)) {
        if (key === 'start' || key === 'end') continue;
        const value = node[key];
        if (Array.isArray(value)) {
          for (let i = value.length - 1; i >= 0; i--) if (value[i]?.type) stack.push({ node: value[i], scope, conditional: childConditional });
        } else if (value?.type) stack.push({ node: value, scope, conditional: childConditional });
      }
    }
    for (const { node, scope, conditional } of assignments) {
      const left = node.left || node.argument;
      if (left?.type === 'Identifier') {
        const binding = lookup(scope, left.name);
        if (binding) binding.writes.push({ expr: node.type === 'AssignmentExpression' && node.operator === '=' ? node.right : null, conditional, unknown: node.operator !== '=' });
      } else if (left?.type === 'MemberExpression') mutations.push({ left, scope });
      else for (const name of namesInPattern(left)) { const b = lookup(scope, name); if (b) b.mutated = true; }
    }
    const markMutation = (initial) => {
      const pending = [initial];
      while (pending.length) {
        const binding = pending.pop();
        if (!binding || binding.mutated) continue;
        binding.mutated = true;
        for (const write of binding.writes) {
          if (write.expr?.type === 'Identifier') pending.push(lookup(scopeOf.get(write.expr) || binding.scope, write.expr.name));
        }
      }
    };
    for (const { node, scope } of calls) {
      const name = memberPath(node.callee);
      if (/^(?:(?:window|globalThis)\.)?crypto\.getRandomValues$/.test(name) || name === 'Object.assign') {
        const target = node.arguments[0];
        if (target?.type === 'Identifier') markMutation(lookup(scope, target.name));
      }
      if (node.callee.type === 'MemberExpression' && /^(?:set|fill|copyWithin|reverse|sort|push|pop|shift|unshift|splice|write|writeUInt\w*|writeInt\w*)$/.test(property(node.callee))) {
        mutations.push({ left: node.callee, scope });
      }
    }
    for (const { left, scope } of mutations) {
      let base = left;
      while (base?.type === 'MemberExpression') base = base.object;
      const binding = base?.type === 'Identifier' && lookup(scope, base.name);
      markMutation(binding);
    }
    const expressionFor = (node, scope, use, seen) => {
      const binding = lookup(scope, node.name);
      if (!binding || binding.mutated || binding.writes.length !== 1 || seen.has(binding)) return null;
      const write = binding.writes[0];
      if (!write.expr || write.conditional || write.unknown || write.expr.start >= use) return null;
      const writeScope = scopeOf.get(write.expr) || binding.scope;
      const functionScope = scope => { while (scope.parent && !scope.functionScope) scope = scope.parent; return scope; };
      if (functionScope(writeScope) !== functionScope(binding.scope)) return null;
      return { node: write.expr, scope: writeScope, seen: new Set([...seen, binding]) };
    };
    const objectNode = (node, scope, use, seen, depth) => {
      if (!node || depth > MAX_DEPTH) return null;
      if (node.type === 'ObjectExpression') return { node, scope, seen };
      if (node.type === 'Identifier') {
        const resolved = expressionFor(node, scope, use, seen);
        return resolved && objectNode(resolved.node, resolved.scope, resolved.node.start, resolved.seen, depth + 1);
      }
      return null;
    };
    const objectProperty = (object, key) => {
      if (!object || object.node.properties.some(p => p.type === 'SpreadElement' || p.computed || p.kind !== 'init' || p.method)) return null;
      const entries = object.node.properties.filter(p => (p.key.name || p.key.value) === key);
      return entries.length === 1 ? entries[0].value : null;
    };
    // Recognise static module/API aliases without calling require or target functions.
    const apiPath = (node, scope, use, seen = new Set(), depth = 0) => {
      if (!node || depth > MAX_DEPTH) return '';
      if (node.type === 'Identifier') {
        const binding = lookup(scope, node.name);
        if (binding?.apiName && binding.writes.length === 1 && !binding.mutated) return binding.apiName;
        const ref = expressionFor(node, scope, use, seen);
        if (ref) {
          const path = apiPath(ref.node, ref.scope, ref.node.start, ref.seen, depth + 1);
          if (path) return path;
        }
        return node.name;
      }
      if (node.type === 'MemberExpression') {
        const base = apiPath(node.object, scope, use, seen, depth + 1), key = property(node);
        return base && key ? `${base}.${key}` : '';
      }
      if (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'require' && !lookup(scope, 'require') && node.arguments.length === 1) {
        return { 'crypto-js': 'CryptoJS', 'crypto': 'crypto', 'node:crypto': 'crypto', 'sm-crypto': 'sm' }[node.arguments[0]?.value] || '';
      }
      return '';
    };
    const unwrap = (node, scope, use, seen = new Set(), depth = 0) => {
      if (!node || depth > MAX_DEPTH) return null;
      if (node.type !== 'Identifier') return { node, scope, seen };
      const ref = expressionFor(node, scope, use, seen);
      return ref && unwrap(ref.node, ref.scope, ref.node.start, ref.seen, depth + 1);
    };
    const resolve = (node, scope, use, prefix, seen = new Set(), depth = 0) => {
      if (!node || depth > MAX_DEPTH) return null;
      if (node.type === 'Literal' && typeof node.value === 'string') return { value: node.value, start: node.start + 1, end: node.end - 1, encoding: 'literal', path: [] };
      if (node.type === 'TemplateLiteral' && !node.expressions.length) return { value: node.quasis[0].value.cooked, start: node.start + 1, end: node.end - 1, encoding: 'literal', path: [] };
      if (node.type === 'Identifier') {
        const resolved = expressionFor(node, scope, use, seen);
        if (!resolved) return null;
        const value = resolve(resolved.node, resolved.scope, resolved.node.start, prefix, resolved.seen, depth + 1);
        return value && { ...value, path: [...value.path, node.name] };
      }
      if (node.type === 'CallExpression') {
        const name = apiPath(node.callee, scope, use);
        const encoding = ['Utf8', 'Hex', 'Base64', 'Latin1'].find(enc => name === `${prefix}.enc.${enc}.parse`);
        if (encoding && node.arguments.length === 1) {
          const value = resolve(node.arguments[0], scope, use, prefix, seen, depth + 1);
          return value && { ...value, encoding };
        }
        if (/^(?:globalThis\.)?Buffer\.from$/.test(name) && node.arguments.length >= 1 && node.arguments.length <= 2 && !lookup(scope, 'Buffer')) {
          const enc = node.arguments[1] ? resolve(node.arguments[1], scope, use, prefix, seen, depth + 1)?.value : 'utf8';
          if (!/^(?:utf-?8|hex|base64(?:url)?|latin1|ascii|utf16le)$/i.test(enc || '')) return null;
          const value = resolve(node.arguments[0], scope, use, prefix, seen, depth + 1);
          return value && { ...value, encoding: value.encoding === 'bytes-hex' ? value.encoding : enc, bufferSource: true };
        }
        if (property(node.callee) === 'encode' && node.arguments.length === 1) {
          const receiver = unwrap(node.callee.object, scope, use);
          if (receiver?.node.type === 'NewExpression' && apiPath(receiver.node.callee, receiver.scope, use) === 'TextEncoder' && !lookup(receiver.scope, 'TextEncoder')) {
            const value = resolve(node.arguments[0], scope, use, prefix, seen, depth + 1);
            return value && value.encoding === 'literal' ? { ...value, encoding: 'Utf8', bufferSource: true } : null;
          }
        }
        return null;
      }
      if (node.type === 'NewExpression' && node.callee.type === 'Identifier' && node.callee.name === 'Uint8Array' && !lookup(scope, 'Uint8Array') && node.arguments.length === 1) {
        const value = resolve(node.arguments[0], scope, use, prefix, seen, depth + 1);
        return value?.encoding === 'bytes-hex' ? { ...value, bufferSource: true } : null;
      }
      if (node.type === 'ArrayExpression') {
        if (!node.elements.length || node.elements.length > 8192 || node.elements.some(n => n?.type !== 'Literal' || !Number.isInteger(n.value) || n.value < 0 || n.value > 255)) return null;
        return { value: node.elements.map(n => n.value.toString(16).padStart(2, '0')).join(''), start: node.start, end: node.end, encoding: 'bytes-hex', path: [] };
      }
      if (node.type === 'MemberExpression') {
        const object = objectNode(node.object, scope, use, seen, depth + 1);
        const value = objectProperty(object, property(node));
        return value && resolve(value, object.scope, value.start, prefix, object.seen, depth + 1);
      }
      if (node.type === 'BinaryExpression' && node.operator === '+') {
        const left = resolve(node.left, scope, use, prefix, seen, depth + 1), right = resolve(node.right, scope, use, prefix, seen, depth + 1);
        if (left?.encoding !== 'literal' || right?.encoding !== 'literal') return null;
        return { value: left.value + right.value, start: node.start, end: node.end, encoding: 'literal', path: [...left.path, ...right.path] };
      }
      return null;
    };
    const byIdentity = new Map(), perRole = {};
    const add = (value, role, call, operation, prefix, algorithm = 'AES', api = '') => {
      if (!value || typeof value.value !== 'string' || !value.value.length || value.value.length > (role === 'privateKey' ? 16384 : 1024)) { coverage.unresolved++; return; }
      if (role === 'privateKey' && /-----BEGIN (?:RSA |EC |)PUBLIC KEY-----/.test(value.value)) { coverage.unresolved++; return; }
      const identity = `${role}:${value.start}:${value.value}`;
      const usage = { algorithm, operation, role, receiver: prefix, api: api || `${prefix}.${algorithm}.${operation}`, encoding: value.encoding,
        variablePath: value.path, callOffset: call.start, callEnd: call.end };
      const existing = byIdentity.get(identity);
      if (existing) { if (existing.cryptoUsages.length < 20) existing.cryptoUsages.push(usage); return; }
      if ((perRole[role] || 0) >= (options.perRule || 1000) || findings.length >= (options.findings || 10000)) {
        coverage.status = 'limited'; coverage.reason = '加密参数常量追踪命中数量达到上限'; return;
      }
      const finding = { role, ...value, cryptoUsages: [usage] };
      perRole[role] = (perRole[role] || 0) + 1; byIdentity.set(identity, finding); findings.push(finding);
    };
    coverage.status = 'completed';
    for (const { node, scope } of calls) {
      if (Date.now() - started > 2500) { coverage.status = 'limited'; coverage.reason = '加密参数常量追踪达到时间预算'; break; }
      const name = apiPath(node.callee, scope, node.start), args = node.arguments;
      const prefix = name.slice(0, name.lastIndexOf('.'));
      const value = (n, receiver = prefix) => resolve(n, scope, node.start, receiver);
      const field = (object, key, receiver = prefix) => {
        const obj = objectNode(object, scope, node.start, new Set(), 0), n = objectProperty(obj, key);
        return n && resolve(n, obj.scope, n.start, receiver, obj.seen);
      };
      const algorithmName = n => value(n)?.value || field(n, 'name')?.value || '';
      const emit = (v, role, algorithm, operation) => add(v, role, node, operation, prefix, algorithm, name);
      const cipher = /^(.*)\.(AES|DES|TripleDES|RC4|RC4Drop|Rabbit|RabbitLegacy)\.(encrypt|decrypt)$/.exec(name);
      if (cipher && args.length >= 2) {
        coverage.calls++;
        emit(value(args[1], cipher[1]), 'key', cipher[2], cipher[3]);
        const iv = /^RC4/.test(cipher[2]) ? null : field(args[2], 'iv', cipher[1]);
        if (iv) emit(iv, 'iv', cipher[2], cipher[3]);
        continue;
      }
      const hmac = /^(.*)\.Hmac(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160)$/.exec(name);
      if (hmac && args.length >= 2) { coverage.calls++; emit(value(args[1], hmac[1]), 'key', `HMAC-${hmac[2]}`, 'sign'); continue; }
      if (/\.algo\.HMAC\.create$/.test(name) && args.length >= 2) {
        coverage.calls++; emit(value(args[1], prefix.replace(/\.algo\.HMAC$/, '')), 'key', 'HMAC', 'create'); continue;
      }
      if (/\.(?:PBKDF2|EvpKDF)$/.test(name) && args.length >= 2) {
        coverage.calls++; emit(value(args[0]), 'password', name.split('.').pop(), 'derive');
        emit(value(args[1]), 'salt', name.split('.').pop(), 'derive'); continue;
      }
      if (/(?:^|\.)sm4\.(?:encrypt|decrypt)$/.test(name) && args.length >= 2) {
        coverage.calls++; emit(value(args[1]), 'key', 'SM4', name.split('.').pop());
        const iv = field(args[2], 'iv'); if (iv) emit(iv, 'iv', 'SM4', name.split('.').pop()); continue;
      }
      if (/(?:^|\.)sm2\.(?:doDecrypt|doSignature)$/.test(name) && args.length >= 2) {
        coverage.calls++; emit(value(args[1]), 'privateKey', 'SM2', name.endsWith('doDecrypt') ? 'decrypt' : 'sign'); continue;
      }
      if (/\.create(?:Decipher|Cipher)iv$/.test(name) && args.length >= 3) {
        const algorithm = algorithmName(args[0]);
        if (!/^(?:aes(?:-?\d+)?(?:-[a-z0-9-]+)?|des(?:-ede3?)?(?:-[a-z0-9-]+)?|chacha20(?:-poly1305)?|rc4|sm4(?:-[a-z0-9-]+)?)$/i.test(algorithm)) continue;
        coverage.calls++; const operation = name.endsWith('Decipheriv') ? 'decrypt' : 'encrypt';
        emit(value(args[1]), 'key', algorithm, operation);
        if (!/^rc4$/i.test(algorithm) && args[2]?.value !== null) emit(value(args[2]), /chacha|gcm|ccm/i.test(algorithm) ? 'nonce' : 'iv', algorithm, operation);
        continue;
      }
      if (/\.createHmac$/.test(name) && args.length >= 2) { coverage.calls++; emit(value(args[1]), 'key', `HMAC${algorithmName(args[0]) ? '-' + algorithmName(args[0]) : ''}`, 'sign'); continue; }
      if (/\.(?:pbkdf2(?:Sync)?|scrypt(?:Sync)?)$/.test(name) && args.length >= 3) {
        coverage.calls++; const algorithm = /scrypt/.test(name) ? 'scrypt' : 'PBKDF2';
        emit(value(args[0]), 'password', algorithm, 'derive'); emit(value(args[1]), 'salt', algorithm, 'derive'); continue;
      }
      if (/\.createSecretKey$/.test(name) && args.length >= 1) { coverage.calls++; emit(value(args[0]), 'key', 'SecretKey', 'import'); continue; }
      if (/\.(?:setPrivateKey|createPrivateKey)$/.test(name) && args.length >= 1) {
        coverage.calls++; emit(value(args[0]) || field(args[0], 'key'), 'privateKey', 'PrivateKey', 'import'); continue;
      }
      const subtle = /^(?:(?:window|globalThis)\.)?crypto\.subtle\.(importKey|encrypt|decrypt|deriveKey|deriveBits)$/.exec(name);
      if (!subtle) continue;
      if (subtle[1] === 'importKey' && args.length >= 3) {
        const format = value(args[0])?.value, algorithm = algorithmName(args[2]);
        if (!algorithm) continue;
        coverage.calls++;
        if (format === 'raw' && /^(AES-(?:CBC|CTR|GCM|KW)|HMAC|PBKDF2|HKDF)$/i.test(algorithm)) {
          const material = value(args[1]); emit(material?.bufferSource ? material : null, /^PBKDF2$/i.test(algorithm) ? 'password' : 'key', algorithm, 'import');
        } else if (format === 'pkcs8') { const material = value(args[1]); emit(material?.bufferSource ? material : null, 'privateKey', algorithm, 'import'); }
        else if (format === 'jwk') {
          const kty = field(args[1], 'kty')?.value;
          if (kty === 'oct') { const k = field(args[1], 'k'); if (k) emit({ ...k, encoding: 'base64url' }, 'key', algorithm, 'import'); }
          else if (['RSA', 'EC', 'OKP'].includes(kty)) { const d = field(args[1], 'd'); if (d) emit({ ...d, encoding: 'base64url' }, 'privateKey', algorithm, 'import'); }
        }
      } else if (['encrypt','decrypt','deriveKey','deriveBits'].includes(subtle[1]) && args.length >= 2) {
        const algorithm = algorithmName(args[0]);
        if (/^AES-(CBC|GCM|CTR)$/i.test(algorithm)) {
          coverage.calls++; const role = /CBC$/i.test(algorithm) ? 'iv' : 'nonce';
          const v = field(args[0], /CTR$/i.test(algorithm) ? 'counter' : 'iv'); if (v) emit(v, role, algorithm, subtle[1]);
        } else if (/^(PBKDF2|HKDF)$/i.test(algorithm)) {
          coverage.calls++; const salt = field(args[0], 'salt'); if (salt) emit(salt, 'salt', algorithm, subtle[1]);
        }
      }
    }
    return { findings, coverage };
  }
  self.AEGISSCOPE_CRYPTO_FLOW = { analyze };
})();
