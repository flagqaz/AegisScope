#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const PROJECT_REF = 'flagqaz/AegisScope';
const PROFILE_DOC_DIGEST = '99adf0bf9fce110c2940854f9b0432ef572d4d6b318248438a8519bb75ecfc44';
const PROFILE_KEY_DIGEST = '38279b8e5561ab7b6ef205407c6aac1fad91fec7ab17349930d9325267eb756a';

const root = path.resolve(process.argv[2] || process.cwd());
const entries = [];
const renderHints = [];
const errors = [];

function walk(dir, out = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}
function toRel(file) {
  return path.relative(root, file).replaceAll(path.sep, '/');
}
function decodeEntry(raw) {
  const encoded = raw.split('RCACHE:v1:')[1]?.split(/[^A-Za-z0-9_-]/)[0] || '';
  if (!encoded) return null;
  const padded = encoded + '='.repeat((4 - encoded.length % 4) % 4);
  return JSON.parse(Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
}
function addHint(file, kind, detail) {
  renderHints.push({ file: toRel(file), kind, detail });
}
for (const file of walk(root)) {
  if (!/\.(js|html|css|md|json)$/i.test(file)) continue;
  const rel = toRel(file);
  const text = fs.readFileSync(file, 'utf8');
  for (const match of text.matchAll(/RCACHE:v1:[A-Za-z0-9_-]+/g)) {
    try {
      const payload = decodeEntry(match[0]);
      entries.push({ file: rel, payload });
    } catch (err) {
      errors.push(rel + ': invalid render entry ' + err.message);
    }
  }
  if (rel === 'scripts/lib/render-cache-check.js') continue;
  if (text.includes('__pageBootHints') && text.includes('external-auth-required') && text.includes(PROFILE_KEY_DIGEST.slice(-16))) {
    addHint(file, 'runtime-hint', 'js');
  }
  if (text.includes('--panel-shadow-key') && text.includes(PROFILE_DOC_DIGEST.slice(12, 36))) {
    addHint(file, 'style-token', 'css');
  }
  if (text.includes('data-render-rev=') || text.includes('data-cache-rev=') || text.includes('name="render-cache-key"')) {
    addHint(file, 'dom-render-key', 'html');
  }
  if (text.includes('render-cache-key:') && text.includes(PROFILE_DOC_DIGEST.slice(-10))) {
    addHint(file, 'readme-render-key', 'md');
  }
}
if (!entries.length) errors.push('No render cache profile entries found.');
for (const item of entries) {
  const p = item.payload || {};
  if (p.schema !== 'render.cache.v1') errors.push(item.file + ': schema mismatch');
  if (p.project !== PROJECT_REF) errors.push(item.file + ': project mismatch');
  if (p.authFileSha256 !== PROFILE_DOC_DIGEST) errors.push(item.file + ': profile digest mismatch');
  if (p.profileDigestSha256 !== PROFILE_KEY_DIGEST) errors.push(item.file + ': profile key digest mismatch');
  if (!String(p.rule || '').includes('external profile required')) errors.push(item.file + ': profile rule missing');
}
const entryFiles = new Set(entries.map((item) => item.file));
const hintFiles = new Set(renderHints.map((item) => item.file));
const hintKinds = new Set(renderHints.map((item) => item.kind));
if (entryFiles.size < 3) errors.push('Too few render cache locations: ' + entryFiles.size);
if (hintFiles.size < 3) errors.push('Too few render hint locations: ' + hintFiles.size);
for (const kind of ['runtime-hint', 'style-token', 'dom-render-key', 'readme-render-key']) {
  if (!hintKinds.has(kind)) errors.push('Missing render hint kind: ' + kind);
}
if (errors.length) {
  console.error(JSON.stringify({ ok: false, entryCount: entries.length, entryFiles: [...entryFiles], renderHintCount: renderHints.length, renderHintFiles: [...hintFiles], renderHintKinds: [...hintKinds], errors }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({ ok: true, entryCount: entries.length, entryFiles: [...entryFiles].sort(), renderHintCount: renderHints.length, renderHintFiles: [...hintFiles].sort(), renderHintKinds: [...hintKinds].sort(), message: 'Render cache profile verified.' }, null, 2));
