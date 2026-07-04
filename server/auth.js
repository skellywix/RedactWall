'use strict';
/**
 * Session auth for the Security Admin console.
 * - Password is salted+hashed (scrypt). Default creds are dev-only and must be
 *   overridden via env (ADMIN_USER / ADMIN_PASSWORD) before any real use.
 * - Session = HMAC-signed cookie. The signing secret is STABLE: env
 *   SENTINEL_SECRET in production, else a generated secret persisted to disk so
 *   sessions survive a restart on one host. (Multi-instance deployments must set
 *   SENTINEL_SECRET so every instance shares it — logged at startup.)
 * - Brute-force defense: per user+IP attempt throttling with temporary lockout.
 */
require('./env').loadEnv();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const roles = require('./roles');

const DATA_DIR = path.join(__dirname, '..', 'data');

function resolveSecret(opts = {}) {
  const env = opts.env || process.env;
  const fsImpl = opts.fs || fs;
  const dataDir = opts.dataDir || DATA_DIR;
  const randomBytes = opts.randomBytes || crypto.randomBytes;
  if (env.SENTINEL_SECRET) return { secret: env.SENTINEL_SECRET, source: 'env' };
  try {
    const f = path.join(dataDir, '.session-secret');
    if (fsImpl.existsSync(f)) { const v = fsImpl.readFileSync(f, 'utf8').trim(); if (v) return { secret: v, source: 'file' }; }
    if (!fsImpl.existsSync(dataDir)) fsImpl.mkdirSync(dataDir, { recursive: true });
    const sec = randomBytes(32).toString('hex');
    fsImpl.writeFileSync(f, sec, { mode: 0o600 });
    return { secret: sec, source: 'generated' };
  } catch (e) {
    return { secret: randomBytes(32).toString('hex'), source: 'ephemeral' };
  }
}
const { secret: SECRET, source: SECRET_SOURCE } = resolveSecret();

const DEFAULT_ADMIN_PASSWORD = 'ChangeMe!2026';
const ADMIN_USER = String(process.env.ADMIN_USER || 'admin').trim() || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || DEFAULT_ADMIN_PASSWORD;
const ADMIN_TOTP_SECRET = String(process.env.ADMIN_TOTP_SECRET || '').trim();
const APPROVER_USER = String(process.env.APPROVER_USER || '').trim();
const APPROVER_PASSWORD = process.env.APPROVER_PASSWORD || '';
const AUDITOR_USER = String(process.env.AUDITOR_USER || '').trim();
const AUDITOR_PASSWORD = process.env.AUDITOR_PASSWORD || '';
const APPROVER_DISTINCT = !!APPROVER_USER && APPROVER_USER !== ADMIN_USER;
const AUDITOR_DISTINCT = !!AUDITOR_USER && AUDITOR_USER !== ADMIN_USER && AUDITOR_USER !== APPROVER_USER;
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8h
const SESSION_COOKIE_NAME = 'promptwall_session';
const LEGACY_SESSION_COOKIE_NAME = 'sentinel_session';
const TOTP_STEP_MS = 30 * 1000;
const TOTP_WINDOW = Number(process.env.ADMIN_TOTP_WINDOW || 1);

function buildAccount(user, password, role) {
  if (!user || !password) return null;
  const salt = crypto.randomBytes(16);
  return {
    user,
    role,
    salt,
    hash: crypto.scryptSync(password, salt, 32),
  };
}

const ACCOUNTS = [
  buildAccount(ADMIN_USER, ADMIN_PASSWORD, roles.SECURITY_ADMIN),
  APPROVER_DISTINCT ? buildAccount(APPROVER_USER, APPROVER_PASSWORD, roles.APPROVER) : null,
  AUDITOR_DISTINCT ? buildAccount(AUDITOR_USER, AUDITOR_PASSWORD, roles.AUDITOR) : null,
].filter(Boolean);

function findAccount(user) {
  return ACCOUNTS.find((account) => account.user === user) || null;
}

function authenticate(user, password) {
  const account = findAccount(user);
  if (!account) return null;
  let h;
  try { h = crypto.scryptSync(password || '', account.salt, 32); } catch { return null; }
  if (!crypto.timingSafeEqual(h, account.hash)) return null;
  return { user: account.user, role: account.role };
}

function verifyPassword(user, password) {
  return !!authenticate(user, password);
}

function normalizeTotpSecret(secret) {
  return String(secret || '').replace(/[\s=-]/g, '').toUpperCase();
}

function decodeBase32(secret) {
  const normalized = normalizeTotpSecret(secret);
  if (!normalized || /[^A-Z2-7]/.test(normalized)) return null;
  let bits = 0;
  let value = 0;
  const bytes = [];
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  for (const char of normalized) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

const ADMIN_TOTP_KEY = decodeBase32(ADMIN_TOTP_SECRET);

function hotp(key, counter) {
  if (counter < 0) return '';
  const msg = Buffer.alloc(8);
  let n = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    msg[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = h[h.length - 1] & 0x0f;
  const bin = ((h[offset] & 0x7f) << 24)
    | ((h[offset + 1] & 0xff) << 16)
    | ((h[offset + 2] & 0xff) << 8)
    | (h[offset + 3] & 0xff);
  return String(bin % 1000000).padStart(6, '0');
}

function safeCodeEqual(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function totpCode(secret = ADMIN_TOTP_SECRET, now = Date.now()) {
  const key = decodeBase32(secret);
  if (!key || key.length < 10) return null;
  return hotp(key, Math.floor(Number(now) / TOTP_STEP_MS));
}

function verifyTotpCode(code, now = Date.now()) {
  if (!ADMIN_TOTP_SECRET || !ADMIN_TOTP_KEY || ADMIN_TOTP_KEY.length < 10) return false;
  const submitted = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(submitted)) return false;
  const window = Math.max(0, Math.min(3, Number.isFinite(TOTP_WINDOW) ? Math.floor(TOTP_WINDOW) : 1));
  const counter = Math.floor(Number(now) / TOTP_STEP_MS);
  for (let offset = -window; offset <= window; offset += 1) {
    if (safeCodeEqual(hotp(ADMIN_TOTP_KEY, counter + offset), submitted)) return true;
  }
  return false;
}

// ---- brute-force throttling --------------------------------------------------
const MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 7);
const WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || 15 * 60 * 1000);
const attempts = new Map(); // key -> { count, first, lockedUntil }

function loginStatus(key) {
  const a = attempts.get(key);
  if (a && a.lockedUntil && Date.now() < a.lockedUntil) return { locked: true, retryMs: a.lockedUntil - Date.now() };
  return { locked: false };
}
function registerFail(key) {
  const now = Date.now();
  let a = attempts.get(key);
  if (!a || now - a.first > WINDOW_MS) a = { count: 0, first: now, lockedUntil: 0 };
  a.count += 1;
  if (a.count >= MAX_ATTEMPTS) a.lockedUntil = now + WINDOW_MS;
  attempts.set(key, a);
  return { locked: !!a.lockedUntil, remaining: Math.max(0, MAX_ATTEMPTS - a.count) };
}
function registerSuccess(key) { attempts.delete(key); }

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${mac}`;
}
function verify(token) {
  if (!token || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (mac.length !== expect.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    if (!payload.user) return null;
    if (!payload.role && payload.user === ADMIN_USER) payload.role = roles.SECURITY_ADMIN;
    const role = roles.normalizeRole(payload.role);
    if (!role) return null;
    payload.role = role;
    if (payload.provider !== 'oidc') {
      delete payload.provider;
      delete payload.idpSubject;
      delete payload.idpIssuer;
      delete payload.stepUpUntil;
    } else {
      payload.idpSubject = String(payload.idpSubject || '').slice(0, 256);
      payload.idpIssuer = String(payload.idpIssuer || '').slice(0, 512);
      payload.stepUpUntil = Number(payload.stepUpUntil) || 0;
    }
    return payload;
  } catch { return null; }
}
function sessionExtras(extras = {}) {
  if (!extras || extras.provider !== 'oidc') return {};
  return {
    provider: 'oidc',
    idpSubject: String(extras.idpSubject || '').slice(0, 256),
    idpIssuer: String(extras.idpIssuer || '').slice(0, 512),
    stepUpUntil: Number(extras.stepUpUntil) || 0,
  };
}
function createSession(user, role = roles.SECURITY_ADMIN, extras = {}) {
  return sign({
    user,
    role,
    ...sessionExtras(extras),
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_MS,
  });
}

function oidcStepUpSatisfied(session = {}, now = Date.now()) {
  return session.provider === 'oidc' && Number(session.stepUpUntil) > now;
}

function createCsrfToken(sessionToken) {
  if (!sessionToken) return null;
  return crypto.createHmac('sha256', SECRET).update('csrf:' + sessionToken).digest('base64url');
}

function verifyCsrfToken(sessionToken, token) {
  const expected = createCsrfToken(sessionToken);
  if (!expected || !token) return false;
  const a = Buffer.from(String(token));
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sessionTokenFromRequest(req) {
  const cookies = (req && req.cookies) || {};
  return cookies[SESSION_COOKIE_NAME] || cookies[LEGACY_SESSION_COOKIE_NAME] || '';
}

function requireAuth(req, res, next) {
  const session = verify(sessionTokenFromRequest(req));
  if (!session) {
    if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'unauthenticated' });
    return res.redirect('/login.html');
  }
  req.user = session;
  next();
}

function requireRole(...roles) {
  const allowed = new Set(roles);
  return (req, res, next) => {
    const role = req.user && req.user.role;
    if (!allowed.has(role)) return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

/**
 * Derive a purpose-scoped key from the stable session secret so other modules
 * can sign artifacts (e.g. safe-to-send receipts) without touching the raw
 * secret. Same namespace + same SENTINEL_SECRET => same key across restarts.
 */
function deriveKey(namespace) {
  return crypto.createHash('sha256').update(String(namespace) + ':' + SECRET).digest();
}

function requireCsrf(req, res, next) {
  const method = String(req.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return next();
  const sessionToken = sessionTokenFromRequest(req);
  const token = req.get('x-csrf-token');
  if (!verifyCsrfToken(sessionToken, token)) return res.status(403).json({ error: 'invalid csrf token' });
  next();
}

module.exports = {
  authenticate, verifyPassword, verifyTotpCode, totpCode, createSession, verify, oidcStepUpSatisfied, createCsrfToken, verifyCsrfToken, sessionTokenFromRequest, requireAuth, requireRole, requireCsrf, deriveKey,
  loginStatus, registerFail, registerSuccess,
  ADMIN_USER, ADMIN_PASSWORD_IS_DEFAULT: ADMIN_PASSWORD === DEFAULT_ADMIN_PASSWORD,
  ADMIN_MFA_REQUIRED: !!ADMIN_TOTP_SECRET,
  ADMIN_MFA_CONFIGURED: !!ADMIN_TOTP_KEY && ADMIN_TOTP_KEY.length >= 10,
  APPROVER_ENABLED: APPROVER_DISTINCT && ACCOUNTS.some((account) => account.role === roles.APPROVER),
  AUDITOR_ENABLED: AUDITOR_DISTINCT && ACCOUNTS.some((account) => account.role === roles.AUDITOR),
  SECRET_SOURCE, SECRET_IS_STABLE: SECRET_SOURCE === 'env' || SECRET_SOURCE === 'file',
  SESSION_COOKIE_NAME, LEGACY_SESSION_COOKIE_NAME,
  _internal: { resolveSecret },
};
