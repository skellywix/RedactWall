'use strict';
/**
 * Minimal .env loader so native Node, scripts, sensors, and Docker Compose all
 * read the same deployment config without adding a runtime dependency.
 */
const fs = require('fs');
const path = require('path');

function defaultEnvPath() {
  return process.env.SENTINEL_ENV_PATH || path.join(__dirname, '..', '.env');
}

function unescapeQuoted(value, quote) {
  if (quote === "'") return value;
  return value.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function stripInlineComment(value) {
  let escaped = false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (ch === '\\' && !escaped) {
      escaped = true;
      continue;
    }
    if (ch === '#' && !escaped && (i === 0 || /\s/.test(value[i - 1]))) {
      return value.slice(0, i).trimEnd();
    }
    escaped = false;
  }
  return value.trim();
}

function parseEnv(content) {
  const parsed = {};
  const errors = [];
  const lines = String(content || '').split(/\r?\n/);
  lines.forEach((raw, index) => {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const line = trimmed.startsWith('export ') ? trimmed.slice(7).trimStart() : trimmed;
    const eq = line.indexOf('=');
    if (eq === -1) {
      errors.push({ line: index + 1, error: 'missing equals sign' });
      return;
    }
    const key = line.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      errors.push({ line: index + 1, error: 'invalid key' });
      return;
    }
    let value = line.slice(eq + 1).trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote) && value.length >= 2) {
      value = unescapeQuoted(value.slice(1, -1), quote);
    } else {
      value = stripInlineComment(value);
    }
    parsed[key] = value;
  });
  return { parsed, errors };
}

function loadEnv(filePath = defaultEnvPath(), opts = {}) {
  const env = opts.env || process.env;
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    return { loaded: false, path: resolved, keys: [], skipped: [], errors: [] };
  }
  const { parsed, errors } = parseEnv(fs.readFileSync(resolved, 'utf8'));
  const keys = [];
  const skipped = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (!opts.override && Object.prototype.hasOwnProperty.call(env, key)) {
      skipped.push(key);
      continue;
    }
    env[key] = value;
    keys.push(key);
  }
  return { loaded: true, path: resolved, keys, skipped, errors };
}

module.exports = { defaultEnvPath, loadEnv, parseEnv };
