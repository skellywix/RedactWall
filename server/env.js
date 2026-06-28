'use strict';
/**
 * Minimal .env loader so native Node, scripts, sensors, and Docker Compose all
 * read the same deployment config without adding a runtime dependency.
 */
const fs = require('fs');
const path = require('path');

const ENV_ALIASES = [
  ['SENTINEL_ENV_PATH', 'PROMPTWALL_ENV_PATH'],
  ['SENTINEL_URL', 'PROMPTWALL_URL'],
  ['SENTINEL_DB_PATH', 'PROMPTWALL_DB_PATH'],
  ['SENTINEL_POLICY_PATH', 'PROMPTWALL_POLICY_PATH'],
  ['SENTINEL_CUSTOM_DETECTORS_PATH', 'PROMPTWALL_CUSTOM_DETECTORS_PATH'],
  ['SENTINEL_SAAS_MODE', 'PROMPTWALL_SAAS_MODE'],
  ['SENTINEL_TENANT_ID', 'PROMPTWALL_TENANT_ID'],
  ['SENTINEL_SEAT_LIMIT', 'PROMPTWALL_SEAT_LIMIT'],
  ['SENTINEL_REQUIRE_TENANT_CONTEXT', 'PROMPTWALL_REQUIRE_TENANT_CONTEXT'],
  ['SENTINEL_REQUIRE_USER_IDENTITY', 'PROMPTWALL_REQUIRE_USER_IDENTITY'],
  ['SENTINEL_SECRET', 'PROMPTWALL_SECRET'],
  ['SENTINEL_DATA_KEY', 'PROMPTWALL_DATA_KEY'],
  ['SENTINEL_REQUEST_TIMEOUT_MS', 'PROMPTWALL_REQUEST_TIMEOUT_MS'],
  ['INGEST_API_KEY', 'PROMPTWALL_INGEST_API_KEY'],
  ['SCIM_BEARER_TOKEN', 'PROMPTWALL_SCIM_BEARER_TOKEN'],
  ['OIDC_ISSUER', 'PROMPTWALL_OIDC_ISSUER'],
  ['OIDC_CLIENT_ID', 'PROMPTWALL_OIDC_CLIENT_ID'],
  ['OIDC_CLIENT_SECRET', 'PROMPTWALL_OIDC_CLIENT_SECRET'],
  ['OIDC_REDIRECT_URI', 'PROMPTWALL_OIDC_REDIRECT_URI'],
  ['OIDC_AUTHORIZATION_ENDPOINT', 'PROMPTWALL_OIDC_AUTHORIZATION_ENDPOINT'],
  ['OIDC_TOKEN_ENDPOINT', 'PROMPTWALL_OIDC_TOKEN_ENDPOINT'],
  ['OIDC_JWKS_URI', 'PROMPTWALL_OIDC_JWKS_URI'],
  ['OIDC_SCOPE', 'PROMPTWALL_OIDC_SCOPE'],
  ['ENDPOINT_AGENT_WATCH_DIR', 'PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR'],
  ['ENDPOINT_AGENT_HANDOFF_DIR', 'PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR'],
  ['ENDPOINT_AGENT_HANDOFF_SECRET', 'PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET'],
  ['ENDPOINT_AGENT_OCR_COMMAND', 'PROMPTWALL_ENDPOINT_AGENT_OCR_COMMAND'],
  ['ENDPOINT_AGENT_OCR_ARGS_JSON', 'PROMPTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON'],
  ['ENDPOINT_AGENT_OCR_TIMEOUT_MS', 'PROMPTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS'],
  ['ENDPOINT_AGENT_OCR_MAX_CHARS', 'PROMPTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS'],
  ['ENDPOINT_AGENT_APPROVED_AI_TOOLS', 'PROMPTWALL_ENDPOINT_AGENT_APPROVED_AI_TOOLS'],
];

function configured(value) {
  return value != null && String(value).trim() !== '';
}

function applyEnvAliases(env = process.env) {
  const aliases = [];
  for (const [legacy, promptwall] of ENV_ALIASES) {
    if (!configured(env[legacy]) && configured(env[promptwall])) {
      env[legacy] = env[promptwall];
      aliases.push({ key: legacy, source: promptwall });
    }
  }
  return aliases;
}

function withEnvAliases(env = {}) {
  const copy = { ...(env || {}) };
  applyEnvAliases(copy);
  return copy;
}

function defaultEnvPath() {
  return process.env.SENTINEL_ENV_PATH || process.env.PROMPTWALL_ENV_PATH || path.join(__dirname, '..', '.env');
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
    const aliases = applyEnvAliases(env);
    return { loaded: false, path: resolved, keys: [], skipped: [], errors: [], aliases };
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
  const aliases = applyEnvAliases(env);
  return { loaded: true, path: resolved, keys, skipped, errors, aliases };
}

module.exports = {
  ENV_ALIASES,
  applyEnvAliases,
  defaultEnvPath,
  loadEnv,
  parseEnv,
  withEnvAliases,
};
