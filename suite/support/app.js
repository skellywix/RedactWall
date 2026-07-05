'use strict';
/**
 * Shared bootstrap for the black-box regression suite (suite/**).
 *
 * Usage pattern (same as the unit suite): call bootEnv() at the TOP of a
 * *.suite.js file BEFORE requiring the app, so server modules read the temp
 * DB/policy paths and suite credentials at load time. Then boot the real
 * Express app on an ephemeral port with withServer().
 *
 * All seeded data is synthetic (123-45-6789 style markers only).
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');
const { listen } = require(path.join(ROOT, 'test', 'support', 'listen'));

const CREDENTIALS = {
  admin: { user: 'admin', password: 'suite-admin-pass' },
  approver: { user: 'approver@example.test', password: 'suite-approver-pass' },
  auditor: { user: 'auditor@example.test', password: 'suite-auditor-pass' },
};
const INGEST_KEY = 'suite-ingest-key';
const SCIM_TOKEN = 'suite-scim-bearer-token-0123456789abcdef';

/** Set env for an isolated app instance. Call before require()ing server/app. */
function bootEnv(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-suite-'));
  const policyPath = path.join(dir, 'policy.json');
  if (opts.policy) fs.writeFileSync(policyPath, JSON.stringify(opts.policy, null, 2));
  else fs.copyFileSync(path.join(ROOT, 'config', 'policy.json'), policyPath);
  process.env.ADMIN_PASSWORD = CREDENTIALS.admin.password;
  process.env.APPROVER_USER = CREDENTIALS.approver.user;
  process.env.APPROVER_PASSWORD = CREDENTIALS.approver.password;
  process.env.AUDITOR_USER = CREDENTIALS.auditor.user;
  process.env.AUDITOR_PASSWORD = CREDENTIALS.auditor.password;
  process.env.SENTINEL_SECRET = 'suite-session-secret-stable';
  process.env.SENTINEL_DATA_KEY = 'suite-data-key-stable';
  process.env.INGEST_API_KEY = INGEST_KEY;
  process.env.SENTINEL_DB_PATH = path.join(dir, 'sentinel.db');
  process.env.SENTINEL_POLICY_PATH = policyPath;
  Object.assign(process.env, opts.env || {});
  return { dir, policyPath, dbPath: process.env.SENTINEL_DB_PATH };
}

function requireApp() {
  return require(path.join(ROOT, 'server', 'app'));
}

/** Boot the app on an ephemeral loopback port, run fn(port), always close. */
async function withServer(app, fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function request(port, apiPath, { method = 'GET', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** Log a console session in; returns cookie + CSRF token for later writes. */
async function login(port, roleName) {
  const account = CREDENTIALS[roleName];
  if (!account) throw new Error(`unknown suite role: ${roleName}`);
  const res = await request(port, '/api/login', {
    method: 'POST',
    body: { user: account.user, password: account.password },
  });
  if (res.status !== 200) throw new Error(`login as ${roleName} failed: ${res.status}`);
  const body = await res.json();
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrfRes = await request(port, '/api/csrf', { headers: { cookie } });
  if (csrfRes.status !== 200) throw new Error(`csrf fetch failed: ${csrfRes.status}`);
  const { csrfToken } = await csrfRes.json();
  return { cookie, csrfToken, body, user: account.user, password: account.password };
}

/** Sensor ingest call against POST /api/v1/gate with the suite ingest key. */
function gate(port, payload, headers = {}) {
  return request(port, '/api/v1/gate', {
    method: 'POST',
    headers: { 'x-api-key': INGEST_KEY, ...headers },
    body: payload,
  });
}

/** Seed one held (pending) item via the real ingest path; returns gate body. */
async function seedHeldPrompt(port, { suffix = '9001', user = 'seed@example.test', destination = 'chatgpt.com', prompt } = {}) {
  const res = await gate(port, {
    prompt: prompt || `Synthetic suite seed with member SSN 524-71-${suffix} inside.`,
    user,
    destination,
    source: 'browser_extension',
    channel: 'submit',
  });
  if (res.status !== 200) throw new Error(`seed gate failed: ${res.status}`);
  const body = await res.json();
  if (body.status !== 'pending') throw new Error(`seed expected pending, got ${body.status}`);
  return body;
}

module.exports = {
  ROOT,
  CREDENTIALS,
  INGEST_KEY,
  SCIM_TOKEN,
  bootEnv,
  requireApp,
  withServer,
  request,
  login,
  gate,
  seedHeldPrompt,
};
