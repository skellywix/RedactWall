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
process.env.SENTINEL_SECRET = 'unit-secret-stable-oidc-000000000000000001';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable-oidc-000000000000001';
process.env.INGEST_API_KEY = 'unit-ingest-key-oidc-00000000000000000001';
process.env.SCIM_BEARER_TOKEN = 'unit-scim-token-oidc-00000000000000000001';
process.env.OIDC_CLIENT_ID = 'promptwall-console';
process.env.OIDC_CLIENT_SECRET = 'oidc-client-secret-00000000000000000001';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-oidc-login-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const db = require('../server/db');
const oidc = require('../server/oidc');
const { listen } = require('./support/listen');

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
  const mac = crypto.createHmac('sha256', process.env.SENTINEL_SECRET).update(body).digest('base64url');
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
    fetchImpl: async () => ({ ok: true, json: async () => ({ keys: [jwk] }) }),
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
  assert.match(stateCookie, /^promptwall_oidc=/);

  const authorize = await fetch(start.headers.get('location'), { redirect: 'manual' });
  assert.strictEqual(authorize.status, 302);
  const callbackUrl = authorize.headers.get('location');
  const callback = await fetch(callbackUrl, {
    redirect: 'manual',
    headers: { cookie: cookie || stateCookie },
  });
  return { callback, stateCookie };
}

test('oidc callback issues a PromptWall session for an active SCIM approver', async () => {
  const issuer = await startIssuer();
  try {
    process.env.OIDC_ISSUER = issuer.url;
    await withServer(async (port) => {
      process.env.OIDC_REDIRECT_URI = `http://127.0.0.1:${port}/auth/oidc/callback`;
      const user = db.saveScimUser({
        userName: 'reviewer@example.test',
        displayName: 'OIDC Reviewer',
        active: true,
      });
      db.saveScimGroup({
        displayName: 'PromptWall Approvers',
        members: [{ value: user.id, display: user.userName }],
      });

      const options = await fetch(`http://127.0.0.1:${port}/api/login-options`);
      assert.deepStrictEqual(await options.json(), {
        oidc: { enabled: true, startUrl: '/auth/oidc/start' },
        defaultAdminCredential: false,
      });

      const { callback } = await followOidcLogin(port);
      assert.strictEqual(callback.status, 302);
      assert.strictEqual(callback.headers.get('location'), '/index.html');
      const sessionCookie = cookiePair(callback.headers.get('set-cookie'));
      assert.match(sessionCookie, /^promptwall_session=/);

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
        displayName: 'Disabled OIDC User',
        active: false,
        role: 'security_admin',
      });

      const { callback } = await followOidcLogin(port);
      assert.strictEqual(callback.status, 302);
      assert.strictEqual(callback.headers.get('location'), '/login.html?oidc=failed');
      assert.doesNotMatch(callback.headers.get('set-cookie') || '', /promptwall_session=/);

      const audit = db.listAudit(10);
      assert.ok(audit.some((entry) => entry.action === 'OIDC_LOGIN_FAILED' && /not provisioned/.test(entry.detail || '')));
      assert.strictEqual(db.verifyAuditChain().ok, true);
    });
  } finally {
    await issuer.close();
  }
});

test('oidc fresh step-up window is bounded by the IdP auth_time claim', () => {
  const now = Date.parse('2026-06-28T12:00:00.000Z');
  const authTime = Math.floor((now - 4 * 60 * 1000) / 1000);
  const extras = oidc.sessionExtrasForClaims({
    sub: 'subject-1',
    auth_time: authTime,
  }, {
    issuer: 'https://login.example.test',
  }, now);

  assert.strictEqual(extras.provider, 'oidc');
  assert.strictEqual(extras.stepUpUntil, authTime * 1000 + oidc.STEP_UP_TTL_MS);
  assert.ok(extras.stepUpUntil < now + oidc.STEP_UP_TTL_MS);
});

test('oidc discovery and state cookies fail closed on mismatches and tampering', async () => {
  await assert.rejects(
    () => oidc.resolvedConfig({
      env: {
        OIDC_ISSUER: 'https://issuer.example.test',
        OIDC_CLIENT_ID: 'promptwall-console',
        OIDC_CLIENT_SECRET: 'secret',
      },
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({
          issuer: 'https://other-issuer.example.test',
          authorization_endpoint: 'https://issuer.example.test/auth',
          token_endpoint: 'https://issuer.example.test/token',
          jwks_uri: 'https://issuer.example.test/jwks',
        }),
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
  assert.strictEqual(oidc.safeReturnTo('https://evil.example/'), '/index.html');
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
    assert.doesNotMatch(mismatch.headers.get('set-cookie') || '', /promptwall_session=/);

    const denied = await fetch(`http://127.0.0.1:${port}/auth/oidc/callback?error=access_denied&state=expected-state`, {
      redirect: 'manual',
      headers: { cookie: stateCookie },
    });
    assert.strictEqual(denied.status, 302);
    assert.strictEqual(denied.headers.get('location'), '/login.html?oidc=failed');
    assert.doesNotMatch(denied.headers.get('set-cookie') || '', /promptwall_session=/);

    const audit = db.listAudit(10);
    assert.ok(audit.some((entry) => entry.action === 'OIDC_LOGIN_FAILED' && entry.detail === 'oidc login failed'));
    assert.strictEqual(db.verifyAuditChain().ok, true);
  });
});

test('oidc public errors stay generic except for operator-safe categories', () => {
  assert.strictEqual(oidc.publicError(new Error('OIDC login is not enabled')), 'oidc login is not enabled');
  assert.strictEqual(oidc.publicError(new Error('OIDC user is not active in SCIM')), 'oidc user is not provisioned');
  assert.strictEqual(oidc.publicError(new Error('OIDC token exchange failed with private details')), 'oidc login failed');
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
