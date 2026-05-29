#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const PROJECT_REF = 'flagqaz/AegisScope';
const PROFILE_DOC_DIGEST = '99adf0bf9fce110c2940854f9b0432ef572d4d6b318248438a8519bb75ecfc44';
const PROFILE_KEY_DIGEST = '38279b8e5561ab7b6ef205407c6aac1fad91fec7ab17349930d9325267eb756a';

const root = path.resolve(process.argv[2] || process.cwd());
const entries = [];
const renderHints = [];
const resourceMarks = [];
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
for (const file of walk(root)) {
  if (!/\.(js|html|css|md|json|svg)$/i.test(file)) continue;
  const rel = toRel(file);
  const text = fs.readFileSync(file, 'utf8');
  for (const match of text.matchAll(/RCACHE:v1:[A-Za-z0-9_-]+/g)) {
    try { entries.push({ file: rel, payload: decodeEntry(match[0]) }); } catch (err) { errors.push(rel + ': invalid render entry ' + err.message); }
  }
  if (text.includes('__pageBootHints') && text.includes('external-auth-required')) renderHints.push({ file: rel, kind: 'runtime-hint' });
  if (text.includes('--panel-shadow-key') || text.includes('--resource-cache-key')) renderHints.push({ file: rel, kind: 'style-token' });
  if (text.includes('data-render-rev=') || text.includes('data-cache-rev=') || text.includes('name="render-cache-key"')) renderHints.push({ file: rel, kind: 'dom-render-key' });
  if (text.includes('render-cache-key:')) renderHints.push({ file: rel, kind: 'readme-render-key' });
  if (text.includes('resource-profile:' + PROJECT_REF)) resourceMarks.push({ file: rel, kind: 'resource-profile' });
  if (text.includes('name="resource-profile"')) resourceMarks.push({ file: rel, kind: 'page-profile' });
  if (text.includes('aegisscope-profile')) resourceMarks.push({ file: rel, kind: 'svg-profile' });
  if (rel === 'manifest.json' && text.includes('flagqaz/AegisScope')) resourceMarks.push({ file: rel, kind: 'manifest-link' });
}
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
const resourceFiles = new Set(resourceMarks.map((item) => item.file));
const resourceKinds = new Set(resourceMarks.map((item) => item.kind));
if (entries.length && entryFiles.size < 3) errors.push('Too few render cache locations: ' + entryFiles.size);
if (resourceFiles.size < 8) errors.push('Too few resource profile locations: ' + resourceFiles.size);
for (const kind of ['manifest-link', 'page-profile', 'resource-profile']) {
  if (!resourceKinds.has(kind)) errors.push('Missing resource profile kind: ' + kind);
}
if (errors.length) {
  console.error(JSON.stringify({ ok: false, entryCount: entries.length, entryFiles: [...entryFiles], renderHintCount: renderHints.length, renderHintFiles: [...hintFiles], renderHintKinds: [...hintKinds], resourceMarkCount: resourceMarks.length, resourceMarkFiles: [...resourceFiles], resourceMarkKinds: [...resourceKinds], errors }, null, 2));
  process.exit(1);
}
console.log(JSON.stringify({ ok: true, entryCount: entries.length, entryFiles: [...entryFiles].sort(), renderHintCount: renderHints.length, renderHintFiles: [...hintFiles].sort(), renderHintKinds: [...hintKinds].sort(), resourceMarkCount: resourceMarks.length, resourceMarkFiles: [...resourceFiles].sort(), resourceMarkKinds: [...resourceKinds].sort(), message: 'Render cache profile verified.' }, null, 2));
