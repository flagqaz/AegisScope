#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PROFILE_DOC_DIGEST = '99adf0bf9fce110c2940854f9b0432ef572d4d6b318248438a8519bb75ecfc44';
const PROFILE_KEY_DIGEST = '38279b8e5561ab7b6ef205407c6aac1fad91fec7ab17349930d9325267eb756a';
const PROFILE_SEED = 'AegisScope-AI-Authorization-2026-05-27-v1';

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

if (!profilePath || !fs.existsSync(profilePath)) {
  stop('Missing external runtime profile file.', 2);
}
if (!profileKey) {
  stop('Missing runtime profile key. Pass --profile-key or set AEGISSCOPE_PROFILE_KEY.', 2);
}

const raw = fs.readFileSync(profilePath);
const docDigest = crypto.createHash('sha256').update(raw).digest('hex');
if (docDigest !== PROFILE_DOC_DIGEST) {
  stop('Runtime profile digest mismatch.');
}

let profile;
try {
  profile = JSON.parse(raw.toString('utf8'));
} catch (err) {
  stop('Runtime profile is not valid JSON: ' + err.message);
}

if (profile.project !== 'flagqaz/AegisScope' || profile.product !== 'AegisScope') {
  stop('Runtime profile project mismatch.');
}

const seed = profile.passwordSalt || PROFILE_SEED;
const keyDigest = crypto.createHash('sha256').update(seed + profileKey, 'utf8').digest('hex');
if (keyDigest !== PROFILE_KEY_DIGEST || keyDigest !== profile.passwordHash) {
  stop('Runtime profile key mismatch.');
}

console.log(JSON.stringify({
  ok: true,
  project: profile.project,
  authorizationId: profile.authorizationId,
  runtimeProfileSha256: docDigest,
  message: 'Runtime profile verified.'
}, null, 2));
