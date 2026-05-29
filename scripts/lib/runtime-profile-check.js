#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PROFILE_DOC_DIGEST = '99adf0bf9fce110c2940854f9b0432ef572d4d6b318248438a8519bb75ecfc44';
const PROFILE_KEY_DIGEST = '38279b8e5561ab7b6ef205407c6aac1fad91fec7ab17349930d9325267eb756a';
const PROFILE_SEED = 'AegisScope-AI-Authorization-2026-05-27-v1';
const PROJECT_ROOT = path.resolve(__dirname, '..', '..');

const args = process.argv.slice(2);
function arg(name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : '';
}

const profilePath = path.resolve(arg('--profile') || arg('--auth') || process.env.AEGISSCOPE_RUNTIME_PROFILE || process.env.AEGISSCOPE_AUTH_FILE || '');
const profileKey = arg('--profile-key') || arg('--password') || process.env.AEGISSCOPE_PROFILE_KEY || process.env.AEGISSCOPE_AUTH_PASSWORD || '';

function stop(message, code = 1) {
  console.error(JSON.stringify({ ok: false, error: message }, null, 2));
  process.exit(code);
}

if (!profilePath || !fs.existsSync(profilePath)) stop('Missing external runtime profile file.', 2);
if (!profileKey) stop('Missing runtime profile key. Pass --profile-key or set AEGISSCOPE_PROFILE_KEY.', 2);

const raw = fs.readFileSync(profilePath);
const docDigest = crypto.createHash('sha256').update(raw).digest('hex');
if (docDigest !== PROFILE_DOC_DIGEST) stop('Runtime profile digest mismatch.');

let profile;
try { profile = JSON.parse(raw.toString('utf8')); } catch (err) { stop('Runtime profile is not valid JSON: ' + err.message); }
if (profile.project !== 'flagqaz/AegisScope' || profile.product !== 'AegisScope') stop('Runtime profile project mismatch.');

const seed = profile.passwordSalt || PROFILE_SEED;
const keyDigest = crypto.createHash('sha256').update(seed + profileKey, 'utf8').digest('hex');
if (keyDigest !== PROFILE_KEY_DIGEST || keyDigest !== profile.passwordHash) stop('Runtime profile key mismatch.');

function walk(dir, out = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

function toRel(file) {
  return path.relative(PROJECT_ROOT, file).replaceAll(path.sep, '/');
}

const files = walk(PROJECT_ROOT).filter((file) => /\.(js|html|css|svg|md)$/i.test(file));
const anchorFiles = [];
const missing = [];
for (const file of files) {
  const text = fs.readFileSync(file, 'utf8');
  if (text.includes('resource-profile:flagqaz/AegisScope') || text.includes('aegisscope-profile') || text.includes('external-auth-required') || text.includes('RCACHE:v1:')) {
    anchorFiles.push(toRel(file));
  }
}
for (const required of ['popup.html', 'manifest.json']) {
  if (!fs.existsSync(path.join(PROJECT_ROOT, required))) missing.push(required + ': missing');
}
if (anchorFiles.length < 8) missing.push('Too few local authorization anchors: ' + anchorFiles.length);
if (missing.length) stop('Local runtime profile anchors mismatch: ' + missing.join('; '));

console.log(JSON.stringify({
  ok: true,
  project: profile.project,
  authorizationId: profile.authorizationId,
  runtimeProfileSha256: docDigest,
  localAnchors: anchorFiles.length,
  message: 'Runtime profile verified.'
}, null, 2));
