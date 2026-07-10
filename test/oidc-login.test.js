'use strict';
/** OIDC login must map signed identity tokens to active SCIM users and roles. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable-oidc-000000000000000001';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable-oidc-000000000000001';
process.env.INGEST_API_KEY = 'unit-ingest-key-oidc-00000000000000000001';
process.env.SCIM_BEARER_TOKEN = 'unit-scim-token-oidc-00000000000000000001';
process.env.OIDC_CLIENT_ID = 'redactwall-console';
process.env.OIDC_CLIENT_SECRET = 'oidc-client-secret-00000000000000000001';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-oidc-login-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const auth = require('../server/auth');
const db = require('../server/db');
const oidc = require('../server/oidc');
const { listen } = require('./support/listen');

test.beforeEach(() => oidc._resetLoginAttemptsForTest());

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: init.status || 200,
    headers: { 'content-type': 'application/json', ...(init.headers || {}) },
  });
}

test('OIDC requires an explicit callback URI and never derives it from request headers', () => {
  const incomplete = oidc.config({
    OIDC_ISSUER: 'https://login.example.test',
    OIDC_CLIENT_ID: 'redactwall-console',
    OIDC_CLIENT_SECRET: 'unit-secret',
  });

  assert.strictEqual(incomplete.enabled, false);
  assert.throws(
    () => oidc.redirectUriFor({ ...incomplete, enabled: true }, 'https://attacker.example'),
    /redirect uri/i,
  );
});

test('production OIDC rejects every cleartext URL before provider traffic or redirect', async () => {
  const secure = {
    issuer: 'https://login.example.test',
    clientId: 'redactwall-console',
    clientSecret: 'unit-secret',
    redirectUri: 'https://redactwall.example.test/auth/oidc/callback',
    authorizationEndpoint: 'https://login.example.test/authorize',
    tokenEndpoint: 'https://login.example.test/token',
    jwksUri: 'https://login.example.test/jwks',
    scope: 'openid email profile',
    production: true,
    enabled: true,
  };

  for (const key of ['issuer', 'redirectUri', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri']) {
    await assert.rejects(
      () => oidc.resolvedConfig({
        config: { ...secure, [key]: secure[key].replace('https://', 'http://') },
      }),
      /https/i,
      key,
    );
  }

  let requests = 0;
  await assert.rejects(
    () => oidc.resolvedConfig({
      env: {
        NODE_ENV: 'production',
        OIDC_ISSUER: 'http://login.example.test',
        OIDC_CLIENT_ID: 'redactwall-console',
        OIDC_CLIENT_SECRET: 'unit-secret',
        OIDC_REDIRECT_URI: 'https://redactwall.example.test/auth/oidc/callback',
      },
      fetchImpl: async () => {
        requests += 1;
        throw new Error('must not fetch');
      },
    }),
    /https/i,
  );
  assert.strictEqual(requests, 0, 'cleartext issuer is rejected before discovery');
});

test('OIDC rejects credentials, queries, and fragments in every configured URL without echoing secrets', async () => {
  const secure = {
    issuer: 'https://login.example.test',
    clientId: 'redactwall-console',
    clientSecret: 'unit-secret',
    redirectUri: 'https://redactwall.example.test/auth/oidc/callback',
    authorizationEndpoint: 'https://login.example.test/authorize',
    tokenEndpoint: 'https://login.example.test/token',
    jwksUri: 'https://login.example.test/jwks',
    scope: 'openid email profile',
    production: true,
    enabled: true,
  };
  const secret = 'embedded-provider-password';
  for (const field of ['issuer', 'redirectUri', 'authorizationEndpoint', 'tokenEndpoint', 'jwksUri']) {
    const credential = new URL(secure[field]);
    credential.username = 'provider-user';
    credential.password = secret;
    for (const unsafe of [credential.toString(), `${secure[field]}?tenant=hidden`, `${secure[field]}#override`]) {
      await assert.rejects(
        () => oidc.resolvedConfig({ config: { ...secure, [field]: unsafe } }),
        (error) => /credentials, query parameters, or fragments/i.test(error.message)
          && !error.message.includes(secret),
        `${field}: ${unsafe.replace(secret, '[secret]')}`,
      );
    }
  }
});

test('OIDC provider JSON rejects declared and streamed oversized bodies, timeouts, and secret-bearing fetch errors', async () => {
  const env = {
    OIDC_ISSUER: 'https://login.example.test',
    OIDC_CLIENT_ID: 'redactwall-console',
    OIDC_CLIENT_SECRET: 'unit-secret',
    OIDC_REDIRECT_URI: 'https://redactwall.example.test/auth/oidc/callback',
  };
  let bodyReads = 0;
  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      fetchImpl: async () => ({
        ok: true,
        headers: { get: (name) => name.toLowerCase() === 'content-length' ? String(50 * 1024 * 1024) : '' },
        body: {
          async *[Symbol.asyncIterator]() {
            bodyReads += 1;
            yield Buffer.from('{}');
          },
        },
      }),
    }),
    /safe size limit/,
  );
  assert.strictEqual(bodyReads, 0, 'Content-Length is rejected before reading the body');

  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      fetchImpl: async () => ({
        ok: true,
        headers: { get: () => '' },
        body: {
          async *[Symbol.asyncIterator]() {
            yield Buffer.alloc(150 * 1024, 0x7b);
            yield Buffer.alloc(150 * 1024, 0x7d);
          },
        },
      }),
    }),
    /safe size limit/,
  );

  let cancelled = false;
  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      responseTimeoutMs: 20,
      fetchImpl: async () => ({
        ok: true,
        headers: new Headers(),
        body: { getReader: () => ({
          read: async () => new Promise(() => {}),
          cancel: async () => { cancelled = true; },
        }) },
      }),
    }),
    /provider response timed out/,
  );
  assert.strictEqual(cancelled, true);

  let textCalled = false;
  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      fetchImpl: async () => ({
        ok: true,
        text: async () => { textCalled = true; return '{}'; },
      }),
    }),
    /response body was unavailable/,
  );
  assert.strictEqual(textCalled, false);

  let nonSuccessCancelled = false;
  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      fetchImpl: async () => ({
        ok: false,
        status: 503,
        body: { cancel: async () => { nonSuccessCancelled = true; } },
      }),
    }),
    /provider request failed/,
  );
  assert.strictEqual(nonSuccessCancelled, true);

  const providerSecret = 'provider-internal-secret-value';
  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      requestTimeoutMs: 10,
      fetchImpl: async (_url, options) => new Promise((resolve, reject) => {
        options.signal.addEventListener('abort', () => reject(new Error(providerSecret)), { once: true });
      }),
    }),
    (error) => /timed out/.test(error.message) && !error.message.includes(providerSecret),
  );
  await assert.rejects(
    () => oidc.resolvedConfig({
      env,
      fetchImpl: async () => { throw new Error(providerSecret); },
    }),
    (error) => /provider request failed/.test(error.message) && !error.message.includes(providerSecret),
  );
});

test('production OIDC rejects cleartext endpoints returned by HTTPS discovery', async () => {
  const base = {
    NODE_ENV: 'production',
    OIDC_ISSUER: 'https://login.example.test',
    OIDC_CLIENT_ID: 'redactwall-console',
    OIDC_CLIENT_SECRET: 'unit-secret',
    OIDC_REDIRECT_URI: 'https://redactwall.example.test/auth/oidc/callback',
  };

  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    await assert.rejects(
      () => oidc.resolvedConfig({
        env: base,
        fetchImpl: async () => jsonResponse({
            issuer: base.OIDC_ISSUER,
            authorization_endpoint: 'https://login.example.test/authorize',
            token_endpoint: 'https://login.example.test/token',
            jwks_uri: 'https://login.example.test/jwks',
            [key]: `http://login.example.test/${key}`,
        }),
      }),
      /https/i,
      key,
    );
  }
});

test('OIDC provider requests reject redirects without dropping request options', async () => {
  let discoveryOptions;
  await oidc.resolvedConfig({
    env: {
      NODE_ENV: 'production',
      OIDC_ISSUER: 'https://login.example.test',
      OIDC_CLIENT_ID: 'redactwall-console',
      OIDC_CLIENT_SECRET: 'unit-secret',
      OIDC_REDIRECT_URI: 'https://redactwall.example.test/auth/oidc/callback',
    },
    fetchImpl: async (_url, options) => {
      discoveryOptions = options;
      return jsonResponse({
          issuer: 'https://login.example.test',
          authorization_endpoint: 'https://login.example.test/authorize',
          token_endpoint: 'https://login.example.test/token',
          jwks_uri: 'https://login.example.test/jwks',
      });
    },
  });
  assert.strictEqual(discoveryOptions.redirect, 'error');

  const fixture = idTokenFixture();
  let jwksOptions;
  await oidc.validateIdToken(fixture.token, {
    config: fixture.config,
    nonce: 'nonce-1',
    now: fixture.now,
    fetchImpl: async (url, options) => {
      jwksOptions = options;
      return fixture.fetchImpl(url);
    },
  });
  assert.strictEqual(jwksOptions.redirect, 'error');

  const now = Date.parse('2026-06-28T13:00:00.000Z');
  const state = 'redirect-test-state';
  let tokenOptions;
  const redirectError = new Error('synthetic provider redirect rejected');
  await assert.rejects(
    () => oidc.handleCallback({
      query: { code: 'code-1', state },
      stateCookie: oidc.signState({ state, nonce: 'nonce-1', returnTo: '/app/', exp: now + 60_000 }),
      now,
      config: {
        issuer: 'https://login.example.test',
        clientId: 'redactwall-console',
        clientSecret: 'unit-secret',
        redirectUri: 'https://redactwall.example.test/auth/oidc/callback',
        authorizationEndpoint: 'https://login.example.test/authorize',
        tokenEndpoint: 'https://login.example.test/token',
        jwksUri: 'https://login.example.test/jwks',
        scope: 'openid email profile',
        production: true,
        enabled: true,
      },
      fetchImpl: async (_url, options) => {
        tokenOptions = options;
        throw redirectError;
      },
    }),
    /OIDC provider request failed/,
  );
  assert.strictEqual(tokenOptions.redirect, 'error');
  assert.strictEqual(tokenOptions.method, 'POST');
  assert.match(tokenOptions.headers.authorization, /^Basic /);
  assert.match(tokenOptions.body, /grant_type=authorization_code/);
  assert.strictEqual(oidc.publicError(redirectError), 'oidc login failed');
});

test('OIDC discovery is shared in flight and cached only for its bounded TTL', async () => {
  const env = {
    OIDC_ISSUER: 'https://cached-login.example.test',
    OIDC_CLIENT_ID: 'redactwall-console',
    OIDC_CLIENT_SECRET: 'unit-secret',
    OIDC_REDIRECT_URI: 'https://redactwall.example.test/auth/oidc/callback',
  };
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return jsonResponse({
      issuer: env.OIDC_ISSUER,
      authorization_endpoint: `${env.OIDC_ISSUER}/authorize`,
      token_endpoint: `${env.OIDC_ISSUER}/token`,
      jwks_uri: `${env.OIDC_ISSUER}/jwks`,
    });
  };
  const options = { env, fetchImpl, discoveryCacheTtlMs: 10, now: 1000 };
  await Promise.all([oidc.resolvedConfig(options), oidc.resolvedConfig(options)]);
  assert.strictEqual(calls, 1, 'concurrent starts share one discovery request');
  await oidc.resolvedConfig({ ...options, now: 1009 });
  assert.strictEqual(calls, 1, 'fresh discovery result is reused');
  await oidc.resolvedConfig({ ...options, now: 1011 });
  assert.strictEqual(calls, 2, 'expired discovery is refreshed');
});

test('OIDC token responses are bounded before the authenticated body is read', async () => {
  const now = Date.parse('2026-06-28T13:00:00.000Z');
  const state = 'large-token-state';
  let bodyReads = 0;
  await assert.rejects(
    () => oidc.handleCallback({
      query: { code: 'code-1', state },
      stateCookie: oidc.signState({ state, nonce: 'nonce-1', returnTo: '/app/', exp: now + 60_000 }),
      now,
      config: {
        issuer: 'https://login.example.test',
        clientId: 'redactwall-console',
        clientSecret: 'token-client-secret',
        redirectUri: 'https://redactwall.example.test/auth/oidc/callback',
        authorizationEndpoint: 'https://login.example.test/authorize',
        tokenEndpoint: 'https://login.example.test/token',
        jwksUri: 'https://login.example.test/jwks',
        enabled: true,
      },
      fetchImpl: async () => ({
        ok: true,
        headers: { get: (name) => name.toLowerCase() === 'content-length' ? String(50 * 1024 * 1024) : '' },
        body: {
          async *[Symbol.asyncIterator]() {
            bodyReads += 1;
            yield Buffer.from('{}');
          },
        },
      }),
    }),
    (error) => /safe size limit/.test(error.message) && !error.message.includes('token-client-secret'),
  );
  assert.strictEqual(bodyReads, 0);
});

test('OIDC caps JWKS key count and caches only successful bounded key sets', async () => {
  const tooMany = idTokenFixture();
  await assert.rejects(
    () => oidc.validateIdToken(tooMany.token, {
      config: tooMany.config,
      nonce: 'nonce-1',
      now: tooMany.now,
      fetchImpl: async () => jsonResponse({
        keys: Array.from({ length: 65 }, (_, index) => ({ kty: 'RSA', kid: `key-${index}` })),
      }),
    }),
    /key-count limit/,
  );

  const cached = idTokenFixture();
  let requests = 0;
  const fetchImpl = async (url) => {
    requests += 1;
    return cached.fetchImpl(url);
  };
  for (let i = 0; i < 2; i += 1) {
    await oidc.validateIdToken(cached.token, {
      config: cached.config,
      nonce: 'nonce-1',
      now: cached.now,
      fetchImpl,
    });
  }
  assert.strictEqual(requests, 1, 'successful JWKS response is reused only within its bounded TTL');
});

test('identity self-test reports unsafe OIDC URLs without reflecting embedded credentials', async () => {
  const previousIssuer = process.env.OIDC_ISSUER;
  const previousRedirect = process.env.OIDC_REDIRECT_URI;
  const embeddedSecret = 'identity-check-provider-secret';
  process.env.OIDC_ISSUER = `https://provider:${embeddedSecret}@login.example.test`;
  process.env.OIDC_REDIRECT_URI = 'https://redactwall.example.test/auth/oidc/callback';
  try {
    await withServer(async (port) => {
      const cookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('admin', 'security_admin')}`;
      const csrfResponse = await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } });
      const csrf = await csrfResponse.json();
      const response = await fetch(`http://127.0.0.1:${port}/api/identity/test`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': csrf.csrfToken },
        body: '{}',
      });
      assert.strictEqual(response.status, 200);
      const body = await response.json();
      const oidcCheck = body.checks.find((check) => check.id === 'oidc');
      assert.deepStrictEqual(oidcCheck, {
        id: 'oidc',
        label: 'OIDC single sign-on',
        ok: false,
        detail: 'configured issuer URL is unsafe',
      });
      assert.ok(!JSON.stringify(body).includes(embeddedSecret));
      assert.ok(!JSON.stringify(db.listAudit(20)).includes(embeddedSecret));
    });
  } finally {
    if (previousIssuer === undefined) delete process.env.OIDC_ISSUER;
    else process.env.OIDC_ISSUER = previousIssuer;
    if (previousRedirect === undefined) delete process.env.OIDC_REDIRECT_URI;
    else process.env.OIDC_REDIRECT_URI = previousRedirect;
  }
});

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

function signJwt(privateKey, kid, claims) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signingInput = `${header}.${payload}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function signedStateCookieBody(body) {
  const mac = crypto.createHmac('sha256', process.env.REDACTWALL_SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function idTokenFixture(claimOverrides = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'oidc-validation-key';
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = kid;
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  const nowSec = Math.floor(Date.parse('2026-06-28T13:00:00.000Z') / 1000);
  const config = {
    issuer: 'https://login.example.test',
    clientId: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    jwksUri: 'https://login.example.test/jwks',
    enabled: true,
  };
  const claims = {
    iss: config.issuer,
    sub: 'subject-1',
    aud: config.clientId,
    nonce: 'nonce-1',
    iat: nowSec,
    exp: nowSec + 300,
    ...claimOverrides,
  };
  return {
    token: signJwt(privateKey, kid, claims),
    config,
    now: nowSec * 1000,
    fetchImpl: async () => jsonResponse({ keys: [jwk] }),
  };
}

async function startIssuer() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'oidc-unit-key';
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = kid;
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  const authRequests = new Map();
  const issuer = {
    url: '',
    nextEmail: 'reviewer@example.test',
  };
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, issuer.url || 'http://127.0.0.1');
    if (url.pathname === '/.well-known/openid-configuration') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({
        issuer: issuer.url,
        authorization_endpoint: issuer.url + '/authorize',
        token_endpoint: issuer.url + '/token',
        jwks_uri: issuer.url + '/jwks',
      }));
      return;
    }
    if (url.pathname === '/jwks') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    if (url.pathname === '/authorize') {
      const code = 'code-' + crypto.randomBytes(5).toString('hex');
      authRequests.set(code, {
        nonce: url.searchParams.get('nonce'),
        email: issuer.nextEmail,
      });
      const redirect = new URL(url.searchParams.get('redirect_uri'));
      redirect.searchParams.set('code', code);
      redirect.searchParams.set('state', url.searchParams.get('state') || '');
      res.writeHead(302, { location: redirect.toString() });
      res.end();
      return;
    }
    if (url.pathname === '/token') {
      let raw = '';
      req.on('data', (chunk) => { raw += chunk; });
      req.on('end', () => {
        const basic = req.headers.authorization || '';
        const expectedBasic = 'Basic ' + Buffer.from(`${process.env.OIDC_CLIENT_ID}:${process.env.OIDC_CLIENT_SECRET}`).toString('base64');
        const params = new URLSearchParams(raw);
        const request = authRequests.get(params.get('code'));
        if (basic !== expectedBasic || !request) {
          res.writeHead(401);
          res.end('{}');
          return;
        }
        const now = Math.floor(Date.now() / 1000);
        const idToken = signJwt(privateKey, kid, {
          iss: issuer.url,
          sub: 'sub-' + request.email,
          aud: process.env.OIDC_CLIENT_ID,
          email: request.email,
          preferred_username: request.email,
          nonce: request.nonce,
          auth_time: now,
          iat: now,
          exp: now + 300,
        });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({
          token_type: 'Bearer',
          expires_in: 300,
          id_token: idToken,
        }));
      });
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer.url = `http://127.0.0.1:${server.address().port}`;
  issuer.close = () => close(server);
  return issuer;
}

function cookiePair(setCookie) {
  return String(setCookie || '').split(';')[0];
}

async function followOidcLogin(appPort, cookie) {
  const start = await fetch(`http://127.0.0.1:${appPort}/auth/oidc/start`, { redirect: 'manual' });
  assert.strictEqual(start.status, 302);
  const stateCookie = cookiePair(start.headers.get('set-cookie'));
  assert.match(stateCookie, /^redactwall_oidc=/);

  const authorize = await fetch(start.headers.get('location'), { redirect: 'manual' });
  assert.strictEqual(authorize.status, 302);
  const callbackUrl = authorize.headers.get('location');
  const callback = await fetch(callbackUrl, {
    redirect: 'manual',
    headers: { cookie: cookie || stateCookie },
  });
  return { callback, stateCookie };
}

test('oidc callback issues a RedactWall session for an active SCIM approver', async () => {
  const issuer = await startIssuer();
  try {
    process.env.OIDC_ISSUER = issuer.url;
    await withServer(async (port) => {
      process.env.OIDC_REDIRECT_URI = `http://127.0.0.1:${port}/auth/oidc/callback`;
      const user = db.saveScimUser({
        userName: 'reviewer@example.test',
        externalId: 'sub-reviewer@example.test',
        displayName: 'OIDC Reviewer',
        active: true,
      });
      db.saveScimGroup({
        displayName: 'RedactWall Approvers',
        members: [{ value: user.id, display: user.userName }],
      });

      const options = await fetch(`http://127.0.0.1:${port}/api/login-options`);
      assert.deepStrictEqual(await options.json(), {
        oidc: { enabled: true, startUrl: '/auth/oidc/start' },
        defaultAdminCredential: false,
      });

      const { callback } = await followOidcLogin(port);
      assert.strictEqual(callback.status, 302);
      assert.strictEqual(callback.headers.get('location'), '/app/');
      const sessionCookie = cookiePair(callback.headers.get('set-cookie'));
      assert.match(sessionCookie, /^redactwall_session=/);

      const me = await fetch(`http://127.0.0.1:${port}/api/me`, {
        headers: { cookie: sessionCookie },
      });
      assert.strictEqual(me.status, 200);
      assert.deepStrictEqual(await me.json(), {
        user: 'reviewer@example.test',
        role: 'approver',
        authProvider: 'oidc',
        defaultPassword: false,
      });

      const audit = db.listAudit(10);
      assert.ok(audit.some((entry) => entry.action === 'APPROVER_LOGIN' && /oidc/.test(entry.detail || '')));
      assert.strictEqual(db.verifyAuditChain().ok, true);
    });
  } finally {
    await issuer.close();
  }
});

test('oidc callback refuses inactive SCIM users without issuing a session', async () => {
  const issuer = await startIssuer();
  try {
    process.env.OIDC_ISSUER = issuer.url;
    await withServer(async (port) => {
      process.env.OIDC_REDIRECT_URI = `http://127.0.0.1:${port}/auth/oidc/callback`;
      issuer.nextEmail = 'disabled@example.test';
      db.saveScimUser({
        userName: 'disabled@example.test',
        externalId: 'sub-disabled@example.test',
        displayName: 'Disabled OIDC User',
        active: false,
        role: 'security_admin',
      });

      const { callback } = await followOidcLogin(port);
      assert.strictEqual(callback.status, 302);
      assert.strictEqual(callback.headers.get('location'), '/login.html?oidc=failed');
      assert.doesNotMatch(callback.headers.get('set-cookie') || '', /redactwall_session=/);

      const audit = db.listAudit(10);
      assert.ok(audit.some((entry) => entry.action === 'OIDC_LOGIN_FAILED' && /not provisioned/.test(entry.detail || '')));
      assert.strictEqual(db.verifyAuditChain().ok, true);
    });
  } finally {
    await issuer.close();
  }
});

test('oidc callback refuses active SCIM users without an assigned role', async () => {
  const issuer = await startIssuer();
  try {
    process.env.OIDC_ISSUER = issuer.url;
    await withServer(async (port) => {
      process.env.OIDC_REDIRECT_URI = `http://127.0.0.1:${port}/auth/oidc/callback`;
      issuer.nextEmail = 'unassigned@example.test';
      db.saveScimUser({
        userName: 'unassigned@example.test',
        externalId: 'sub-unassigned@example.test',
        displayName: 'Unassigned OIDC User',
        active: true,
        role: '',
      });

      const { callback } = await followOidcLogin(port);
      assert.strictEqual(callback.status, 302);
      assert.strictEqual(callback.headers.get('location'), '/login.html?oidc=failed');
      assert.doesNotMatch(callback.headers.get('set-cookie') || '', /redactwall_session=/);

      const audit = db.listAudit(10);
      assert.ok(audit.some((entry) => entry.action === 'OIDC_LOGIN_FAILED' && /not provisioned/.test(entry.detail || '')));
      assert.strictEqual(db.verifyAuditChain().ok, true);
    });
  } finally {
    await issuer.close();
  }
});

test('oidc step-up requires fresh strong IdP assurance, not auth_time alone', () => {
  const now = Date.parse('2026-06-28T12:00:00.000Z');
  const authTime = Math.floor((now - 4 * 60 * 1000) / 1000);
  const passwordOnly = oidc.sessionExtrasForClaims({
    sub: 'subject-1',
    auth_time: authTime,
    amr: ['pwd'],
  }, {
    issuer: 'https://login.example.test',
  }, now);

  assert.strictEqual(passwordOnly.provider, 'oidc');
  assert.strictEqual(passwordOnly.stepUpUntil, undefined, 'recent password-only auth is not step-up');

  const mfa = oidc.sessionExtrasForClaims({
    sub: 'subject-1',
    auth_time: authTime,
    amr: ['pwd', 'mfa'],
  }, {
    issuer: 'https://login.example.test',
  }, now);
  assert.strictEqual(mfa.stepUpUntil, authTime * 1000 + oidc.STEP_UP_TTL_MS);
  assert.ok(mfa.stepUpUntil < now + oidc.STEP_UP_TTL_MS);

  const staleMfa = oidc.sessionExtrasForClaims({
    sub: 'subject-1',
    auth_time: Math.floor((now - oidc.STEP_UP_TTL_MS - 1000) / 1000),
    amr: ['mfa'],
  }, {
    issuer: 'https://login.example.test',
  }, now);
  assert.strictEqual(staleMfa.stepUpUntil, undefined, 'stale MFA is not step-up');

  const configuredAcr = oidc.sessionExtrasForClaims({
    sub: 'subject-1',
    auth_time: authTime,
    acr: 'urn:customer:assurance:mfa',
  }, {
    issuer: 'https://login.example.test',
    stepUpAcrValues: ['urn:customer:assurance:mfa'],
  }, now);
  assert.ok(configuredAcr.stepUpUntil > now, 'an explicitly allowed strong ACR can satisfy step-up');
});

test('oidc step-up authorization requests fresh configured assurance', async () => {
  const redirect = await oidc.buildAuthorizationRedirect({
    stepUp: true,
    returnTo: '/app/#queue',
    config: {
      issuer: 'https://login.example.test',
      clientId: 'redactwall-console',
      clientSecret: 'unit-secret',
      redirectUri: 'https://redactwall.example.test/auth/oidc/callback',
      authorizationEndpoint: 'https://login.example.test/authorize',
      tokenEndpoint: 'https://login.example.test/token',
      jwksUri: 'https://login.example.test/jwks',
      scope: 'openid email profile',
      stepUpAcrValues: ['urn:customer:assurance:mfa'],
      enabled: true,
    },
  });
  const url = new URL(redirect.url);
  assert.strictEqual(url.searchParams.get('prompt'), 'login');
  assert.strictEqual(url.searchParams.get('max_age'), '0');
  assert.strictEqual(url.searchParams.get('acr_values'), 'urn:customer:assurance:mfa');
  assert.strictEqual(redirect.state.requireStepUp, true);
});

test('oidc discovery and state cookies fail closed on mismatches and tampering', async () => {
  await assert.rejects(
    () => oidc.resolvedConfig({
      env: {
        OIDC_ISSUER: 'https://issuer.example.test',
        OIDC_CLIENT_ID: 'redactwall-console',
        OIDC_CLIENT_SECRET: 'secret',
        OIDC_REDIRECT_URI: 'https://redactwall.example.test/auth/oidc/callback',
      },
      fetchImpl: async () => jsonResponse({
          issuer: 'https://other-issuer.example.test',
          authorization_endpoint: 'https://issuer.example.test/auth',
          token_endpoint: 'https://issuer.example.test/token',
          jwks_uri: 'https://issuer.example.test/jwks',
      }),
    }),
    /issuer mismatch/,
  );

  const badJsonBody = Buffer.from('{bad-json').toString('base64url');
  assert.throws(
    () => oidc.readStateCookie(signedStateCookieBody(badJsonBody), Date.now()),
    /state cookie is invalid/,
  );

  const expired = oidc.signState({
    state: 'state-1',
    nonce: 'nonce-1',
    exp: Date.parse('2026-06-28T12:00:00.000Z') - 1,
  });
  assert.throws(
    () => oidc.readStateCookie(expired, Date.parse('2026-06-28T12:00:00.000Z')),
    /state cookie expired/,
  );

  assert.strictEqual(oidc.safeReturnTo('/dashboard.html'), '/dashboard.html');
  assert.strictEqual(oidc.safeReturnTo('https://evil.example/'), '/app/');
});

test('oidc id token validation rejects malformed and out-of-window signed claims', async () => {
  const malformed = idTokenFixture();
  await assert.rejects(
    () => oidc.validateIdToken('not-json.not-json.not-signature', {
      config: malformed.config,
      fetchImpl: malformed.fetchImpl,
      nonce: 'nonce-1',
      now: malformed.now,
    }),
    /cannot be decoded/,
  );

  const expired = idTokenFixture({ exp: Math.floor(Date.parse('2026-06-28T13:00:00.000Z') / 1000) - 61 });
  await assert.rejects(
    () => oidc.validateIdToken(expired.token, {
      config: expired.config,
      fetchImpl: expired.fetchImpl,
      nonce: 'nonce-1',
      now: expired.now,
    }),
    /expired/,
  );

  const futureNbf = idTokenFixture({ nbf: Math.floor(Date.parse('2026-06-28T13:00:00.000Z') / 1000) + 120 });
  await assert.rejects(
    () => oidc.validateIdToken(futureNbf.token, {
      config: futureNbf.config,
      fetchImpl: futureNbf.fetchImpl,
      nonce: 'nonce-1',
      now: futureNbf.now,
    }),
    /not yet valid/,
  );

  const futureIat = idTokenFixture({ iat: Math.floor(Date.parse('2026-06-28T13:00:00.000Z') / 1000) + 120 });
  await assert.rejects(
    () => oidc.validateIdToken(futureIat.token, {
      config: futureIat.config,
      fetchImpl: futureIat.fetchImpl,
      nonce: 'nonce-1',
      now: futureIat.now,
    }),
    /issued in the future/,
  );

  const nonce = idTokenFixture();
  await assert.rejects(
    () => oidc.validateIdToken(nonce.token, {
      config: nonce.config,
      fetchImpl: nonce.fetchImpl,
      nonce: 'other-nonce',
      now: nonce.now,
    }),
    /nonce mismatch/,
  );
});

test('oidc id token validation rejects wrong keys, issuers, audiences, and missing subjects', async () => {
  const foreignKey = idTokenFixture();
  const advertised = idTokenFixture();
  await assert.rejects(
    () => oidc.validateIdToken(foreignKey.token, {
      config: foreignKey.config,
      fetchImpl: advertised.fetchImpl,
      nonce: 'nonce-1',
      now: foreignKey.now,
    }),
    /signature is invalid/,
  );

  const issuer = idTokenFixture({ iss: 'https://intruder.example.test' });
  await assert.rejects(
    () => oidc.validateIdToken(issuer.token, {
      config: issuer.config,
      fetchImpl: issuer.fetchImpl,
      nonce: 'nonce-1',
      now: issuer.now,
    }),
    /issuer mismatch/,
  );

  const stringAud = idTokenFixture({ aud: 'other-client' });
  await assert.rejects(
    () => oidc.validateIdToken(stringAud.token, {
      config: stringAud.config,
      fetchImpl: stringAud.fetchImpl,
      nonce: 'nonce-1',
      now: stringAud.now,
    }),
    /audience mismatch/,
  );

  const arrayAud = idTokenFixture({
    aud: [process.env.OIDC_CLIENT_ID, 'other-audience'],
    azp: 'other-audience',
  });
  await assert.rejects(
    () => oidc.validateIdToken(arrayAud.token, {
      config: arrayAud.config,
      fetchImpl: arrayAud.fetchImpl,
      nonce: 'nonce-1',
      now: arrayAud.now,
    }),
    /audience mismatch/,
  );

  for (const aud of [process.env.OIDC_CLIENT_ID, [process.env.OIDC_CLIENT_ID]]) {
    const wrongAuthorizedParty = idTokenFixture({
      aud,
      azp: 'other-client',
    });
    await assert.rejects(
      () => oidc.validateIdToken(wrongAuthorizedParty.token, {
        config: wrongAuthorizedParty.config,
        fetchImpl: wrongAuthorizedParty.fetchImpl,
        nonce: 'nonce-1',
        now: wrongAuthorizedParty.now,
      }),
      /audience mismatch/,
    );
  }

  const missingSub = idTokenFixture({ sub: '' });
  await assert.rejects(
    () => oidc.validateIdToken(missingSub.token, {
      config: missingSub.config,
      fetchImpl: missingSub.fetchImpl,
      nonce: 'nonce-1',
      now: missingSub.now,
    }),
    /subject is missing/,
  );
});

test('oidc callback rejects state mismatches and provider errors without issuing a session', async () => {
  await withServer(async (port) => {
    const stateCookie = `${oidc.STATE_COOKIE_NAME}=` + oidc.signState({
      state: 'expected-state',
      nonce: 'nonce-1',
      exp: Date.now() + 60000,
    });

    const mismatch = await fetch(`http://127.0.0.1:${port}/auth/oidc/callback?code=code-1&state=other-state`, {
      redirect: 'manual',
      headers: { cookie: stateCookie },
    });
    assert.strictEqual(mismatch.status, 302);
    assert.strictEqual(mismatch.headers.get('location'), '/login.html?oidc=failed');
    assert.doesNotMatch(mismatch.headers.get('set-cookie') || '', /redactwall_session=/);

    const denied = await fetch(`http://127.0.0.1:${port}/auth/oidc/callback?error=access_denied&state=expected-state`, {
      redirect: 'manual',
      headers: { cookie: stateCookie },
    });
    assert.strictEqual(denied.status, 302);
    assert.strictEqual(denied.headers.get('location'), '/login.html?oidc=failed');
    assert.doesNotMatch(denied.headers.get('set-cookie') || '', /redactwall_session=/);

    const audit = db.listAudit(10);
    assert.ok(audit.some((entry) => entry.action === 'OIDC_LOGIN_FAILED' && entry.detail === 'oidc login failed'));
    assert.strictEqual(db.verifyAuditChain().ok, true);
  });
});

test('OIDC routes cap per-IP amplification and emit one audit event for the lock window', async () => {
  await withServer(async (port) => {
    const before = db.listAudit(5000);
    const failedBefore = before.filter((entry) => entry.action === 'OIDC_LOGIN_FAILED').length;
    const limitedBefore = before.filter((entry) => entry.action === 'OIDC_RATE_LIMITED').length;
    const limit = oidc._loginAttemptLimits.maxAttempts;
    for (let index = 0; index < limit; index += 1) {
      const response = await fetch(`http://127.0.0.1:${port}/auth/oidc/callback?error=access_denied&n=${index}`, {
        redirect: 'manual',
      });
      assert.strictEqual(response.status, 302);
    }
    for (let index = 0; index < 5; index += 1) {
      const response = await fetch(`http://127.0.0.1:${port}/auth/oidc/callback?error=access_denied&locked=${index}`, {
        redirect: 'manual',
      });
      assert.strictEqual(response.status, 429);
    }
    const after = db.listAudit(5000);
    assert.strictEqual(after.filter((entry) => entry.action === 'OIDC_LOGIN_FAILED').length - failedBefore, limit);
    assert.strictEqual(after.filter((entry) => entry.action === 'OIDC_RATE_LIMITED').length - limitedBefore, 1);
  });
});

test('oidc public errors stay generic except for operator-safe categories', () => {
  assert.strictEqual(oidc.publicError(new Error('OIDC login is not enabled')), 'oidc login is not enabled');
  assert.strictEqual(oidc.publicError(new Error('OIDC user is not active in SCIM')), 'oidc user is not provisioned');
  assert.strictEqual(oidc.publicError(new Error('OIDC token exchange failed with private details')), 'oidc login failed');
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.REDACTWALL_DB_PATH + suffix); } catch {}
  }
});
