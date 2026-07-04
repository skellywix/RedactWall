'use strict';
/**
 * Security: baseline browser hardening headers, asserted black-box over HTTP
 * (the unit suite checks the source; this checks what actually ships).
 */
const test = require('node:test');
const assert = require('node:assert');

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();

function assertHardened(res, label) {
  const csp = res.headers.get('content-security-policy') || '';
  const scriptSrc = (csp.split(';').find((part) => part.trim().startsWith('script-src')) || '').trim();
  assert.strictEqual(scriptSrc, "script-src 'self'", `${label}: CSP must restrict scripts to self only`);
  assert.ok(csp.includes("frame-ancestors 'none'"), `${label}: frame-ancestors none`);
  assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff', label);
  assert.strictEqual(res.headers.get('x-frame-options'), 'DENY', label);
  assert.strictEqual(res.headers.get('referrer-policy'), 'no-referrer', label);
  assert.ok(res.headers.get('permissions-policy'), `${label}: permissions-policy present`);
  assert.strictEqual(res.headers.get('x-powered-by'), null, `${label}: framework fingerprint disabled`);
}

test('login page and API responses ship hardened security headers', async () => support.withServer(app, async (port) => {
  const page = await support.request(port, '/login.html');
  assert.strictEqual(page.status, 200);
  assertHardened(page, '/login.html');

  const api = await support.request(port, '/api/login-options');
  assert.strictEqual(api.status, 200);
  assertHardened(api, '/api/login-options');

  const unauth = await support.request(port, '/api/stats');
  assert.strictEqual(unauth.status, 401);
  assertHardened(unauth, '/api/stats (401)');
}));

test('session cookie is HttpOnly and SameSite=Strict', async () => support.withServer(app, async (port) => {
  const res = await support.request(port, '/api/login', {
    method: 'POST',
    body: { user: 'admin', password: support.CREDENTIALS.admin.password },
  });
  assert.strictEqual(res.status, 200);
  const setCookie = res.headers.get('set-cookie') || '';
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Strict/i);
  assert.match(setCookie, /Path=\//i);
}));
