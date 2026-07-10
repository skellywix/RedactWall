'use strict';
/**
 * Minimal SCIM-backed OpenID Connect login for customer-silo installs.
 *
 * The console keeps local break-glass users. OIDC sessions are issued only
 * after a signed ID token maps to an active SCIM user, so role assignment stays
 * tied to the same provisioned identity lifecycle used by policy scopes.
 */
require('./env').loadEnv();
const crypto = require('crypto');
const db = require('./db');
const roles = require('./roles');
const scim = require('./scim');
const auth = require('./auth');
const { assertOidcUrls } = require('./oidc-url');
const { cancelResponseBody, readBoundedJson } = require('../sensors/shared/bounded-response');

const STATE_COOKIE_NAME = 'redactwall_oidc';
const STATE_TTL_MS = 10 * 60 * 1000;
const STEP_UP_TTL_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_SEC = 60;
const PROVIDER_REQUEST_TIMEOUT_MS = 10 * 1000;
const MAX_DISCOVERY_BYTES = 256 * 1024;
const MAX_TOKEN_RESPONSE_BYTES = 128 * 1024;
const MAX_JWKS_BYTES = 512 * 1024;
const MAX_JWKS_KEYS = 64;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
const DISCOVERY_CACHE_TTL_MS = 5 * 60 * 1000;
const LOGIN_ATTEMPT_LIMIT = Math.max(3, Math.min(100, Number(process.env.OIDC_ATTEMPT_LIMIT) || 12));
const LOGIN_ATTEMPT_WINDOW_MS = Math.max(1000, Math.min(60 * 60 * 1000, Number(process.env.OIDC_ATTEMPT_WINDOW_MS) || 60 * 1000));
const MAX_LOGIN_ATTEMPT_KEYS = 10000;
const STRONG_AMR_VALUES = new Set(['mfa']);
const jwksCacheByFetch = new WeakMap();
const discoveryCacheByFetch = new WeakMap();
const loginAttempts = new Map();
// Reuse the stable session secret (env, else the disk-persisted one) instead of
// a per-process random fallback, so in-flight logins survive a restart and every
// instance in a fleet validates the same state-cookie signature.
const STATE_SECRET = process.env.REDACTWALL_SECRET || process.env.PROMPTWALL_SECRET || process.env.SENTINEL_SECRET
  || auth.deriveKey('oidc-state');

function cleanString(value, max = 512) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function configList(value, maxItems = 16) {
  const source = Array.isArray(value) ? value : String(value || '').split(/[\s,]+/);
  return Array.from(new Set(source
    .map((item) => cleanString(item, 256))
    .filter(Boolean)))
    .slice(0, maxItems);
}

function runtimeConfig(cfg, opts = {}) {
  const env = opts.env || process.env;
  return {
    ...(cfg || {}),
    production: (cfg && cfg.production === true) || env.NODE_ENV === 'production',
  };
}

function config(env = process.env) {
  const issuer = cleanString(env.OIDC_ISSUER || env.REDACTWALL_OIDC_ISSUER, 512).replace(/\/+$/, '');
  const clientId = cleanString(env.OIDC_CLIENT_ID || env.REDACTWALL_OIDC_CLIENT_ID, 256);
  const clientSecret = cleanString(env.OIDC_CLIENT_SECRET || env.REDACTWALL_OIDC_CLIENT_SECRET, 2048);
  const redirectUri = cleanString(env.OIDC_REDIRECT_URI || env.REDACTWALL_OIDC_REDIRECT_URI, 1024);
  const authorizationEndpoint = cleanString(env.OIDC_AUTHORIZATION_ENDPOINT || env.REDACTWALL_OIDC_AUTHORIZATION_ENDPOINT, 1024);
  const tokenEndpoint = cleanString(env.OIDC_TOKEN_ENDPOINT || env.REDACTWALL_OIDC_TOKEN_ENDPOINT, 1024);
  const jwksUri = cleanString(env.OIDC_JWKS_URI || env.REDACTWALL_OIDC_JWKS_URI, 1024);
  const scope = cleanString(env.OIDC_SCOPE || env.REDACTWALL_OIDC_SCOPE, 256) || 'openid email profile';
  const stepUpAcrValues = configList(env.OIDC_STEP_UP_ACR_VALUES || env.REDACTWALL_OIDC_STEP_UP_ACR_VALUES);
  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    scope,
    stepUpAcrValues,
    production: env.NODE_ENV === 'production',
    enabled: !!issuer && !!clientId && !!clientSecret && !!redirectUri,
  };
}

function publicOptions(env = process.env) {
  const cfg = config(env);
  return {
    enabled: cfg.enabled,
    startUrl: cfg.enabled ? '/auth/oidc/start' : null,
  };
}

function redirectUriFor(cfg) {
  if (!cfg || !cfg.redirectUri) throw new Error('OIDC redirect URI is required');
  assertOidcUrls(cfg, [['redirectUri', 'redirect URI']]);
  return cfg.redirectUri;
}

function safeProviderError(message) {
  const error = new Error(message);
  error.oidcSafe = true;
  return error;
}

function requestTimeout(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return PROVIDER_REQUEST_TIMEOUT_MS;
  return Math.max(10, Math.min(60 * 1000, Math.floor(parsed)));
}

async function withProviderTimeout(task, options = {}) {
  const controller = new AbortController();
  const externalSignal = options.signal;
  const abort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) throw safeProviderError('OIDC provider request failed');
    externalSignal.addEventListener('abort', abort, { once: true });
  }
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(safeProviderError('OIDC provider request timed out'));
    }, requestTimeout(options.requestTimeoutMs));
  });
  const work = Promise.resolve().then(() => task(controller.signal));
  try {
    return await Promise.race([work, timeout]);
  } catch (error) {
    if (error && error.oidcSafe) throw error;
    throw safeProviderError('OIDC provider request failed');
  } finally {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener('abort', abort);
  }
}

function providerBodyError(error) {
  if (error && error.code === 'REDACTWALL_RESPONSE_TOO_LARGE') {
    return safeProviderError('OIDC provider response exceeded the safe size limit');
  }
  if (error && error.code === 'REDACTWALL_RESPONSE_TIMEOUT') {
    return safeProviderError('OIDC provider response timed out');
  }
  if (error && error.code === 'REDACTWALL_RESPONSE_INVALID_JSON') {
    return safeProviderError('OIDC provider returned invalid JSON');
  }
  if (error && error.code === 'REDACTWALL_RESPONSE_UNSTREAMABLE') {
    return safeProviderError('OIDC provider response body was unavailable');
  }
  return safeProviderError('OIDC provider request failed');
}

async function fetchJson(fetchImpl, url, options = {}) {
  const response = await withProviderTimeout(async (signal) => {
    try {
      return await fetchImpl(url, {
        ...(options.fetchOptions || {}),
        redirect: 'error',
        signal,
      });
    } catch {
      throw safeProviderError('OIDC provider request failed');
    }
  }, options);
  if (!response || !response.ok) {
    await cancelResponseBody(response);
    throw safeProviderError('OIDC provider request failed');
  }
  try {
    const { json } = await readBoundedJson(response, {
      maxBytes: options.maxBytes,
      timeoutMs: requestTimeout(options.responseTimeoutMs ?? options.requestTimeoutMs),
      label: 'OIDC provider response',
    });
    return json;
  } catch (error) {
    throw providerBodyError(error);
  }
}

function boundedDiscoveryTtl(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return DISCOVERY_CACHE_TTL_MS;
  return Math.min(60 * 60 * 1000, Math.floor(parsed));
}

function discoveryCache(fetchImpl) {
  let cache = discoveryCacheByFetch.get(fetchImpl);
  if (!cache) {
    cache = new Map();
    discoveryCacheByFetch.set(fetchImpl, cache);
  }
  return cache;
}

async function discoveryDocument(cfg, fetchImpl, opts = {}) {
  const cache = discoveryCache(fetchImpl);
  const now = Number.isFinite(Number(opts.now)) ? Number(opts.now) : Date.now();
  const cached = cache.get(cfg.issuer);
  if (cached && cached.value && cached.expiresAt > now) return cached.value;
  if (cached && cached.promise) return cached.promise;
  const promise = fetchJson(fetchImpl, `${cfg.issuer}/.well-known/openid-configuration`, {
    maxBytes: MAX_DISCOVERY_BYTES,
    requestTimeoutMs: opts.requestTimeoutMs,
    responseTimeoutMs: opts.responseTimeoutMs,
    signal: opts.signal,
  });
  cache.set(cfg.issuer, { promise, expiresAt: 0 });
  try {
    const value = await promise;
    cache.set(cfg.issuer, { value, expiresAt: now + boundedDiscoveryTtl(opts.discoveryCacheTtlMs) });
    return value;
  } catch (error) {
    cache.delete(cfg.issuer);
    throw error;
  }
}

async function resolvedConfig(opts = {}) {
  const cfg = runtimeConfig(opts.config || config(opts.env), opts);
  if (!cfg.enabled) throw new Error('OIDC login is not enabled');
  assertOidcUrls(cfg, [
    ['issuer', 'issuer'],
    ['redirectUri', 'redirect URI'],
  ]);
  if (cfg.authorizationEndpoint && cfg.tokenEndpoint && cfg.jwksUri) {
    assertOidcUrls(cfg, [
      ['authorizationEndpoint', 'authorization endpoint'],
      ['tokenEndpoint', 'token endpoint'],
      ['jwksUri', 'JWKS URI'],
    ]);
    return cfg;
  }
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('OIDC discovery requires fetch');
  const discovery = await discoveryDocument(cfg, fetchImpl, opts);
  if (cleanString(discovery.issuer).replace(/\/+$/, '') !== cfg.issuer) {
    throw new Error('OIDC discovery issuer mismatch');
  }
  const resolved = {
    ...cfg,
    authorizationEndpoint: cfg.authorizationEndpoint || cleanString(discovery.authorization_endpoint, 1024),
    tokenEndpoint: cfg.tokenEndpoint || cleanString(discovery.token_endpoint, 1024),
    jwksUri: cfg.jwksUri || cleanString(discovery.jwks_uri, 1024),
  };
  assertOidcUrls(resolved, [
    ['authorizationEndpoint', 'authorization endpoint'],
    ['tokenEndpoint', 'token endpoint'],
    ['jwksUri', 'JWKS URI'],
  ]);
  return resolved;
}

function pruneLoginAttempts(now) {
  for (const [key, attempt] of loginAttempts) {
    if (attempt.lockedUntil <= now && now - attempt.startedAt >= LOGIN_ATTEMPT_WINDOW_MS) loginAttempts.delete(key);
  }
  while (loginAttempts.size >= MAX_LOGIN_ATTEMPT_KEYS) loginAttempts.delete(loginAttempts.keys().next().value);
}

function consumeLoginAttempt(client, now = Date.now()) {
  const key = crypto.createHash('sha256').update(cleanString(client, 512) || 'unknown').digest('hex');
  const time = Number.isFinite(Number(now)) ? Number(now) : Date.now();
  pruneLoginAttempts(time);
  let attempt = loginAttempts.get(key);
  if (attempt && attempt.lockedUntil > time) {
    return { allowed: false, newlyLocked: false, retryMs: attempt.lockedUntil - time };
  }
  if (!attempt || time - attempt.startedAt >= LOGIN_ATTEMPT_WINDOW_MS) {
    attempt = { count: 0, startedAt: time, lockedUntil: 0 };
  }
  attempt.count += 1;
  let newlyLocked = false;
  if (attempt.count > LOGIN_ATTEMPT_LIMIT) {
    attempt.lockedUntil = time + LOGIN_ATTEMPT_WINDOW_MS;
    newlyLocked = true;
  }
  loginAttempts.delete(key);
  loginAttempts.set(key, attempt);
  return {
    allowed: !newlyLocked,
    newlyLocked,
    retryMs: newlyLocked ? LOGIN_ATTEMPT_WINDOW_MS : 0,
    remaining: Math.max(0, LOGIN_ATTEMPT_LIMIT - attempt.count),
  };
}

function randomBase64Url(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function signState(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}

function constantTimeEqual(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function readStateCookie(value, now = Date.now()) {
  const token = cleanString(value, 4096);
  const parts = token.split('.');
  if (parts.length !== 2) throw new Error('OIDC state cookie is missing');
  const [body, mac] = parts;
  const expected = crypto.createHmac('sha256', STATE_SECRET).update(body).digest('base64url');
  if (!constantTimeEqual(mac, expected)) throw new Error('OIDC state cookie signature is invalid');
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    throw new Error('OIDC state cookie is invalid');
  }
  if (!payload || !payload.state || !payload.nonce || Number(payload.exp) < now) {
    throw new Error('OIDC state cookie expired');
  }
  return payload;
}

function safeReturnTo(value) {
  const text = cleanString(value, 512);
  if (!text || !text.startsWith('/') || text.startsWith('//') || text.includes('\\')) return '/app/';
  return text;
}

async function buildAuthorizationRedirect(opts = {}) {
  const cfg = await resolvedConfig(opts);
  const redirectUri = redirectUriFor(cfg);
  const requireStepUp = opts.stepUp === true;
  const stepUpAcrValues = configList(cfg.stepUpAcrValues);
  const state = randomBase64Url(24);
  const nonce = randomBase64Url(24);
  const statePayload = {
    state,
    nonce,
    returnTo: safeReturnTo(opts.returnTo),
    requireStepUp,
    exp: Date.now() + STATE_TTL_MS,
  };
  const url = new URL(cfg.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', cfg.scope);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  if (requireStepUp) {
    // max_age=0 + prompt=login asks the provider for fresh authentication.
    // acr_values is operator-configured because assurance identifiers are IdP-
    // specific. The callback still verifies the resulting amr/acr claims before
    // granting RedactWall's privileged step-up window.
    url.searchParams.set('prompt', 'login');
    url.searchParams.set('max_age', '0');
    if (stepUpAcrValues.length) {
      url.searchParams.set('acr_values', stepUpAcrValues.join(' '));
    }
  } else {
    url.searchParams.set('max_age', String(Math.floor(STEP_UP_TTL_MS / 1000)));
  }
  return {
    url: url.toString(),
    cookieValue: signState(statePayload),
    state: statePayload,
    redirectUri,
  };
}

function parseJwt(token) {
  const parts = cleanString(token, 20000).split('.');
  if (parts.length !== 3) throw new Error('OIDC ID token is malformed');
  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new Error('OIDC ID token cannot be decoded');
  }
  return {
    header,
    payload,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: Buffer.from(parts[2], 'base64url'),
  };
}

function audienceMatches(aud, clientId, azp) {
  if (azp != null && azp !== clientId) return false;
  if (typeof aud === 'string') return aud === clientId;
  if (!Array.isArray(aud) || !aud.includes(clientId)) return false;
  return aud.length === 1 || azp === clientId;
}

function jwksCache(fetchImpl) {
  let cache = jwksCacheByFetch.get(fetchImpl);
  if (!cache) {
    cache = new Map();
    jwksCacheByFetch.set(fetchImpl, cache);
  }
  return cache;
}

async function loadJwks(cfg, fetchImpl, opts = {}, forceRefresh = false) {
  const cache = jwksCache(fetchImpl);
  const cached = cache.get(cfg.jwksUri);
  if (!forceRefresh && cached && cached.expiresAt > Date.now()) {
    return { keys: cached.keys, cached: true };
  }
  const jwks = await fetchJson(fetchImpl, cfg.jwksUri, {
    maxBytes: MAX_JWKS_BYTES,
    requestTimeoutMs: opts.requestTimeoutMs,
    responseTimeoutMs: opts.responseTimeoutMs,
    signal: opts.signal,
  });
  const keys = Array.isArray(jwks && jwks.keys) ? jwks.keys : [];
  if (keys.length > MAX_JWKS_KEYS) throw safeProviderError('OIDC JWKS exceeded the safe key-count limit');
  cache.set(cfg.jwksUri, { keys, expiresAt: Date.now() + JWKS_CACHE_TTL_MS });
  return { keys, cached: false };
}

function signingKey(keys, header) {
  return keys.find((candidate) => {
    if (!candidate || candidate.kty !== 'RSA') return false;
    if (candidate.use && candidate.use !== 'sig') return false;
    if (candidate.alg && candidate.alg !== 'RS256') return false;
    return !header.kid || candidate.kid === header.kid;
  });
}

async function jwkForHeader(header, cfg, fetchImpl, opts = {}) {
  if (header.alg !== 'RS256') throw new Error('OIDC ID token must use RS256');
  let result = await loadJwks(cfg, fetchImpl, opts);
  let key = signingKey(result.keys, header);
  // A cached key set may legitimately rotate. Refresh once on a miss, but never
  // cache failures or accept an unbounded provider response.
  if (!key && result.cached) {
    result = await loadJwks(cfg, fetchImpl, opts, true);
    key = signingKey(result.keys, header);
  }
  if (!key) throw new Error('OIDC signing key was not found');
  return key;
}

async function validateIdToken(idToken, opts = {}) {
  const cfg = opts.config ? runtimeConfig(opts.config, opts) : await resolvedConfig(opts);
  assertOidcUrls(cfg, [
    ['issuer', 'issuer'],
    ['jwksUri', 'JWKS URI'],
  ]);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('OIDC ID token validation requires fetch');
  const jwt = parseJwt(idToken);
  const jwk = await jwkForHeader(jwt.header, cfg, fetchImpl, opts);
  const publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.verify('RSA-SHA256', Buffer.from(jwt.signingInput), publicKey, jwt.signature);
  if (!ok) throw new Error('OIDC ID token signature is invalid');

  const nowSec = Math.floor((opts.now || Date.now()) / 1000);
  if (cleanString(jwt.payload.iss).replace(/\/+$/, '') !== cfg.issuer) throw new Error('OIDC issuer mismatch');
  if (!audienceMatches(jwt.payload.aud, cfg.clientId, jwt.payload.azp)) throw new Error('OIDC audience mismatch');
  if (!Number.isFinite(Number(jwt.payload.exp)) || Number(jwt.payload.exp) <= nowSec - MAX_CLOCK_SKEW_SEC) {
    throw new Error('OIDC ID token expired');
  }
  if (jwt.payload.nbf != null && Number(jwt.payload.nbf) > nowSec + MAX_CLOCK_SKEW_SEC) {
    throw new Error('OIDC ID token is not yet valid');
  }
  if (jwt.payload.iat != null && Number(jwt.payload.iat) > nowSec + MAX_CLOCK_SKEW_SEC) {
    throw new Error('OIDC ID token was issued in the future');
  }
  if (cleanString(jwt.payload.nonce, 512) !== cleanString(opts.nonce, 512)) {
    throw new Error('OIDC nonce mismatch');
  }
  if (!cleanString(jwt.payload.sub, 256)) throw new Error('OIDC subject is missing');
  return jwt.payload;
}

async function exchangeCodeForTokens(opts = {}) {
  const cfg = opts.config ? runtimeConfig(opts.config, opts) : await resolvedConfig(opts);
  assertOidcUrls(cfg, [['tokenEndpoint', 'token endpoint']]);
  assertOidcUrls({ ...cfg, redirectUri: opts.redirectUri }, [['redirectUri', 'redirect URI']]);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('OIDC token exchange requires fetch');
  const code = cleanString(opts.code, 4096);
  if (!code) throw new Error('OIDC authorization code is missing');
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: opts.redirectUri,
    client_id: cfg.clientId,
  });
  const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
  const json = await fetchJson(fetchImpl, cfg.tokenEndpoint, {
    maxBytes: MAX_TOKEN_RESPONSE_BYTES,
    requestTimeoutMs: opts.requestTimeoutMs,
    responseTimeoutMs: opts.responseTimeoutMs,
    signal: opts.signal,
    fetchOptions: {
      method: 'POST',
      headers: {
        authorization: `Basic ${basic}`,
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: body.toString(),
    },
  });
  if (!json || !json.id_token) throw new Error('OIDC token response did not include an ID token');
  return json;
}

function scimAccountForClaims(claims = {}) {
  const subject = cleanString(claims.sub, 256);
  if (!subject) throw new Error('OIDC user is not active in SCIM');
  const matches = db.listScimUsers().filter((user) => (
    user.active !== false && cleanString(user.externalId, 256) === subject
  ));
  if (matches.length !== 1) throw new Error('OIDC user is not active in SCIM');
  const user = matches[0];
  const role = roles.normalizeRole(scim.effectiveUserRole(user));
  if (!role) throw new Error('OIDC user is not active in SCIM');
  return { user: user.userName, role, scimUserId: user.id, subject };
}

function sessionExtrasForClaims(claims = {}, cfg = {}, now = Date.now()) {
  const extras = {
    provider: 'oidc',
    idpSubject: cleanString(claims.sub, 256),
    idpIssuer: cleanString(cfg.issuer, 512),
  };
  const amr = configList(claims.amr).map((value) => value.toLowerCase());
  const configuredAcr = configList(cfg.stepUpAcrValues);
  const hasStrongAssurance = amr.some((value) => STRONG_AMR_VALUES.has(value))
    || (!!cleanString(claims.acr, 256) && configuredAcr.includes(cleanString(claims.acr, 256)));
  const authTimeMs = Number(claims.auth_time) * 1000;
  if (hasStrongAssurance
      && Number.isFinite(authTimeMs)
      && authTimeMs <= now + MAX_CLOCK_SKEW_SEC * 1000
      && now - authTimeMs <= STEP_UP_TTL_MS) {
    extras.stepUpUntil = authTimeMs + STEP_UP_TTL_MS;
  }
  return extras;
}

async function handleCallback(opts = {}) {
  const query = opts.query || {};
  if (query.error) throw new Error('OIDC provider returned an error');
  const state = readStateCookie(opts.stateCookie, opts.now || Date.now());
  if (!constantTimeEqual(query.state, state.state)) throw new Error('OIDC state mismatch');
  const cfg = await resolvedConfig(opts);
  const redirectUri = redirectUriFor(cfg);
  const tokens = await exchangeCodeForTokens({
    ...opts,
    config: cfg,
    code: query.code,
    redirectUri,
  });
  const claims = await validateIdToken(tokens.id_token, {
    ...opts,
    config: cfg,
    nonce: state.nonce,
  });
  const account = scimAccountForClaims(claims);
  const sessionExtras = {
    ...sessionExtrasForClaims(claims, cfg, opts.now || Date.now()),
    scimUserId: account.scimUserId,
  };
  if (state.requireStepUp && !sessionExtras.stepUpUntil) {
    throw new Error('OIDC step-up assurance was not satisfied');
  }
  return {
    account,
    claims,
    returnTo: safeReturnTo(state.returnTo),
    sessionExtras,
  };
}

function publicError(err) {
  const message = cleanString(err && err.message, 200);
  if (/not enabled/i.test(message)) return 'oidc login is not enabled';
  if (/not active in SCIM/i.test(message)) return 'oidc user is not provisioned';
  return 'oidc login failed';
}

module.exports = {
  STATE_COOKIE_NAME,
  STATE_TTL_MS,
  STEP_UP_TTL_MS,
  buildAuthorizationRedirect,
  config,
  handleCallback,
  publicError,
  publicOptions,
  readStateCookie,
  redirectUriFor,
  resolvedConfig,
  safeReturnTo,
  scimAccountForClaims,
  sessionExtrasForClaims,
  signState,
  validateIdToken,
  consumeLoginAttempt,
  _resetLoginAttemptsForTest: () => loginAttempts.clear(),
  _loginAttemptLimits: { maxAttempts: LOGIN_ATTEMPT_LIMIT, windowMs: LOGIN_ATTEMPT_WINDOW_MS },
};
