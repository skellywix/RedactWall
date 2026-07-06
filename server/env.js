'use strict';
/**
 * Minimal .env loader so native Node, scripts, sensors, and Docker Compose all
 * read the same deployment config without adding a runtime dependency.
 */
const fs = require('fs');
const path = require('path');

// Core settings renamed across the RedactWall rebrand. Deployments that still
// export the legacy PROMPTWALL_* / SENTINEL_* names keep working; the newer
// prefix wins when both are set.
const REBRANDED_KEYS = [
  'ENV_PATH',
  'URL',
  'DB_PATH',
  'POLICY_PATH',
  'CUSTOM_DETECTORS_PATH',
  'SAAS_MODE',
  'TENANT_ID',
  'SEAT_LIMIT',
  'LICENSE_PATH',
  'LICENSE_PUBLIC_KEY',
  'REQUIRE_TENANT_CONTEXT',
  'REQUIRE_USER_IDENTITY',
  'SECRET',
  'DATA_KEY',
  'DATA_KEY_PREVIOUS',
  'DB_DRIVER',
  'DATABASE_URL',
  'SEMANTIC_REMOTE_URL',
  'SEMANTIC_REMOTE_KEY',
  'SEMANTIC_REMOTE_TIMEOUT_MS',
  'REQUEST_TIMEOUT_MS',
];

// Keys whose canonical name is unprefixed (INGEST_API_KEY, OIDC_*, endpoint-agent
// settings). Historically these accepted a PROMPTWALL_-prefixed alias; the rebrand
// adds a REDACTWALL_-prefixed alias and keeps the legacy PROMPTWALL_ one working.
const UNPREFIXED_ALIASED_KEYS = [
  'INGEST_API_KEY',
  'SCIM_BEARER_TOKEN',
  'OIDC_ISSUER',
  'OIDC_CLIENT_ID',
  'OIDC_CLIENT_SECRET',
  'OIDC_REDIRECT_URI',
  'OIDC_AUTHORIZATION_ENDPOINT',
  'OIDC_TOKEN_ENDPOINT',
  'OIDC_JWKS_URI',
  'OIDC_SCOPE',
  'ENDPOINT_AGENT_WATCH_DIR',
  'ENDPOINT_AGENT_HANDOFF_DIR',
  'ENDPOINT_AGENT_HANDOFF_SECRET',
  'ENDPOINT_AGENT_OCR_COMMAND',
  'ENDPOINT_AGENT_OCR_ARGS_JSON',
  'ENDPOINT_AGENT_OCR_TIMEOUT_MS',
  'ENDPOINT_AGENT_OCR_MAX_CHARS',
  'ENDPOINT_AGENT_APPROVED_AI_TOOLS',
  'ENDPOINT_AGENT_FILE_FLOW_PROFILES',
];

const ENV_ALIASES = [
  ...REBRANDED_KEYS.flatMap((key) => [
    [`REDACTWALL_${key}`, `PROMPTWALL_${key}`],
    [`REDACTWALL_${key}`, `SENTINEL_${key}`],
  ]),
  ...UNPREFIXED_ALIASED_KEYS.flatMap((key) => [
    [key, `REDACTWALL_${key}`],
    [key, `PROMPTWALL_${key}`],
  ]),
];

function configured(value) {
  return value != null && String(value).trim() !== '';
}

function applyEnvAliases(env = process.env) {
  const aliases = [];
  for (const [canonical, alias] of ENV_ALIASES) {
    if (!configured(env[canonical]) && configured(env[alias])) {
      env[canonical] = env[alias];
      aliases.push({ key: canonical, source: alias });
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
  return process.env.REDACTWALL_ENV_PATH || process.env.PROMPTWALL_ENV_PATH || process.env.SENTINEL_ENV_PATH || path.join(__dirname, '..', '.env');
}

const UNESCAPE_MAP = { '\\n': '\n', '\\r': '\r', '\\t': '\t', '\\"': '"', '\\\\': '\\' };

function unescapeQuoted(value, quote) {
  if (quote === "'") return value;
  // Single left-to-right pass so an escaped backslash (\\) is consumed before
  // the following character can be mistaken for its own escape sequence.
  return value.replace(/\\[nrt"\\]/g, (m) => UNESCAPE_MAP[m]);
}

// Index of the value's closing quote, or -1 if it never closes. Double quotes
// honor backslash escaping; single quotes are literal.
function findClosingQuote(value, quote) {
  let escaped = false;
  for (let i = 1; i < value.length; i++) {
    const ch = value[i];
    if (quote === '"' && ch === '\\' && !escaped) { escaped = true; continue; }
    if (ch === quote && !escaped) return i;
    escaped = false;
  }
  return -1;
}

function parseValue(raw) {
  const value = raw.trim();
  const quote = value[0];
  if (quote === '"' || quote === "'") {
    const end = findClosingQuote(value, quote);
    // A closed quote wins even when trailing text (an inline comment) follows,
    // so `KEY="v" # note` yields v, not the literal `"v"`.
    if (end !== -1) return unescapeQuoted(value.slice(1, end), quote);
  }
  return stripInlineComment(value);
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
    parsed[key] = parseValue(line.slice(eq + 1));
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
