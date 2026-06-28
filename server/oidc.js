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

const STATE_COOKIE_NAME = 'promptwall_oidc';
const STATE_TTL_MS = 10 * 60 * 1000;
const STEP_UP_TTL_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_SEC = 60;
const STATE_SECRET = process.env.SENTINEL_SECRET
  || process.env.PROMPTWALL_SECRET
  || crypto.randomBytes(32).toString('hex');

function cleanString(value, max = 512) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function configured(value) {
  return cleanString(value).length > 0;
}

function config(env = process.env) {
  const issuer = cleanString(env.OIDC_ISSUER || env.PROMPTWALL_OIDC_ISSUER, 512).replace(/\/+$/, '');
  const clientId = cleanString(env.OIDC_CLIENT_ID || env.PROMPTWALL_OIDC_CLIENT_ID, 256);
  const clientSecret = cleanString(env.OIDC_CLIENT_SECRET || env.PROMPTWALL_OIDC_CLIENT_SECRET, 2048);
  const redirectUri = cleanString(env.OIDC_REDIRECT_URI || env.PROMPTWALL_OIDC_REDIRECT_URI, 1024);
  const authorizationEndpoint = cleanString(env.OIDC_AUTHORIZATION_ENDPOINT || env.PROMPTWALL_OIDC_AUTHORIZATION_ENDPOINT, 1024);
  const tokenEndpoint = cleanString(env.OIDC_TOKEN_ENDPOINT || env.PROMPTWALL_OIDC_TOKEN_ENDPOINT, 1024);
  const jwksUri = cleanString(env.OIDC_JWKS_URI || env.PROMPTWALL_OIDC_JWKS_URI, 1024);
  const scope = cleanString(env.OIDC_SCOPE || env.PROMPTWALL_OIDC_SCOPE, 256) || 'openid email profile';
  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
    scope,
    enabled: !!issuer && !!clientId && !!clientSecret,
  };
}

function publicOptions(env = process.env) {
  const cfg = config(env);
  return {
    enabled: cfg.enabled,
    startUrl: cfg.enabled ? '/auth/oidc/start' : null,
  };
}

function originFromRequest(req) {
  const forwardedProto = cleanString(req && req.get && req.get('x-forwarded-proto'), 80).split(',')[0].trim();
  const forwardedHost = cleanString(req && req.get && req.get('x-forwarded-host'), 256).split(',')[0].trim();
  const proto = forwardedProto || (req && req.protocol) || 'http';
  const host = forwardedHost || (req && req.get && req.get('host')) || 'localhost';
  return `${proto}://${host}`;
}

function redirectUriFor(cfg, origin) {
  return cfg.redirectUri || `${origin.replace(/\/+$/, '')}/auth/oidc/callback`;
}

async function fetchJson(fetchImpl, url, options) {
  const res = await fetchImpl(url, options);
  if (!res || !res.ok) throw new Error('OIDC provider request failed');
  return res.json();
}

async function resolvedConfig(opts = {}) {
  const cfg = opts.config || config(opts.env);
  if (!cfg.enabled) throw new Error('OIDC login is not enabled');
  if (cfg.authorizationEndpoint && cfg.tokenEndpoint && cfg.jwksUri) return cfg;
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('OIDC discovery requires fetch');
  const discovery = await fetchJson(fetchImpl, `${cfg.issuer}/.well-known/openid-configuration`);
  if (cleanString(discovery.issuer).replace(/\/+$/, '') !== cfg.issuer) {
    throw new Error('OIDC discovery issuer mismatch');
  }
  return {
    ...cfg,
    authorizationEndpoint: cfg.authorizationEndpoint || cleanString(discovery.authorization_endpoint, 1024),
    tokenEndpoint: cfg.tokenEndpoint || cleanString(discovery.token_endpoint, 1024),
    jwksUri: cfg.jwksUri || cleanString(discovery.jwks_uri, 1024),
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
  if (!text || !text.startsWith('/') || text.startsWith('//') || text.includes('\\')) return '/index.html';
  return text;
}

async function buildAuthorizationRedirect(opts = {}) {
  const cfg = await resolvedConfig(opts);
  const origin = opts.origin || originFromRequest(opts.req);
  const redirectUri = redirectUriFor(cfg, origin);
  const state = randomBase64Url(24);
  const nonce = randomBase64Url(24);
  const statePayload = {
    state,
    nonce,
    returnTo: safeReturnTo(opts.returnTo),
    exp: Date.now() + STATE_TTL_MS,
  };
  const url = new URL(cfg.authorizationEndpoint);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', cfg.clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', cfg.scope);
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);
  url.searchParams.set('max_age', String(Math.floor(STEP_UP_TTL_MS / 1000)));
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
  if (typeof aud === 'string') return aud === clientId;
  if (!Array.isArray(aud) || !aud.includes(clientId)) return false;
  return aud.length === 1 || azp === clientId;
}

async function jwkForHeader(header, cfg, fetchImpl) {
  if (header.alg !== 'RS256') throw new Error('OIDC ID token must use RS256');
  const jwks = await fetchJson(fetchImpl, cfg.jwksUri);
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  const key = keys.find((candidate) => {
    if (!candidate || candidate.kty !== 'RSA') return false;
    if (candidate.use && candidate.use !== 'sig') return false;
    if (candidate.alg && candidate.alg !== 'RS256') return false;
    return !header.kid || candidate.kid === header.kid;
  });
  if (!key) throw new Error('OIDC signing key was not found');
  return key;
}

async function validateIdToken(idToken, opts = {}) {
  const cfg = opts.config || await resolvedConfig(opts);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('OIDC ID token validation requires fetch');
  const jwt = parseJwt(idToken);
  const jwk = await jwkForHeader(jwt.header, cfg, fetchImpl);
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
  const cfg = opts.config || await resolvedConfig(opts);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) throw new Error('OIDC token exchange requires fetch');
  const code = cleanString(opts.code, 4096);
  if (!code) throw new Error('OIDC authorization code is missing');
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: opts.redirectUri,
    client_id: cfg.clientId,
  });
  const basic = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64');
  const res = await fetchImpl(cfg.tokenEndpoint, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basic}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: body.toString(),
  });
  if (!res || !res.ok) throw new Error('OIDC token exchange failed');
  const json = await res.json();
  if (!json || !json.id_token) throw new Error('OIDC token response did not include an ID token');
  return json;
}

function identityCandidates(claims = {}) {
  const values = [
    claims.email,
    claims.preferred_username,
    claims.upn,
    claims.unique_name,
  ].map((value) => cleanString(value, 256).toLowerCase()).filter(Boolean);
  return Array.from(new Set(values));
}

function scimAccountForClaims(claims = {}) {
  for (const candidate of identityCandidates(claims)) {
    const user = db.getScimUserByUserName(candidate);
    if (!user || user.active === false) continue;
    const role = roles.normalizeRole(scim.effectiveUserRole(user));
    if (!role) continue;
    return {
      user: user.userName,
      role,
      scimUserId: user.id,
      subject: cleanString(claims.sub, 256),
    };
  }
  throw new Error('OIDC user is not active in SCIM');
}

function sessionExtrasForClaims(claims = {}, cfg = {}, now = Date.now()) {
  const extras = {
    provider: 'oidc',
    idpSubject: cleanString(claims.sub, 256),
    idpIssuer: cleanString(cfg.issuer, 512),
  };
  const authTimeMs = Number(claims.auth_time) * 1000;
  if (Number.isFinite(authTimeMs) && authTimeMs <= now + MAX_CLOCK_SKEW_SEC * 1000 && now - authTimeMs <= STEP_UP_TTL_MS) {
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
  const origin = opts.origin || originFromRequest(opts.req);
  const redirectUri = redirectUriFor(cfg, origin);
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
  return {
    account: scimAccountForClaims(claims),
    claims,
    returnTo: safeReturnTo(state.returnTo),
    sessionExtras: sessionExtrasForClaims(claims, cfg, opts.now || Date.now()),
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
};
