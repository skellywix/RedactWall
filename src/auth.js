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

const DATA_DIR = path.join(__dirname, '..', 'data');

function resolveSecret() {
  if (process.env.SENTINEL_SECRET) return { secret: process.env.SENTINEL_SECRET, source: 'env' };
  try {
    const f = path.join(DATA_DIR, '.session-secret');
    if (fs.existsSync(f)) { const v = fs.readFileSync(f, 'utf8').trim(); if (v) return { secret: v, source: 'file' }; }
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const sec = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(f, sec, { mode: 0o600 });
    return { secret: sec, source: 'generated' };
  } catch (e) {
    return { secret: crypto.randomBytes(32).toString('hex'), source: 'ephemeral' };
  }
}
const { secret: SECRET, source: SECRET_SOURCE } = resolveSecret();

const DEFAULT_ADMIN_PASSWORD = 'ChangeMe!2026';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || DEFAULT_ADMIN_PASSWORD;
const AUDITOR_USER = process.env.AUDITOR_USER || '';
const AUDITOR_PASSWORD = process.env.AUDITOR_PASSWORD || '';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8h

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
  buildAccount(ADMIN_USER, ADMIN_PASSWORD, 'security_admin'),
  buildAccount(AUDITOR_USER, AUDITOR_PASSWORD, 'auditor'),
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
    return payload;
  } catch { return null; }
}
function createSession(user, role = 'security_admin') {
  return sign({ user, role, iat: Date.now(), exp: Date.now() + SESSION_TTL_MS });
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

function requireAuth(req, res, next) {
  const session = verify(req.cookies && req.cookies.sentinel_session);
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

function requireCsrf(req, res, next) {
  const method = String(req.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return next();
  const sessionToken = req.cookies && req.cookies.sentinel_session;
  const token = req.get('x-csrf-token');
  if (!verifyCsrfToken(sessionToken, token)) return res.status(403).json({ error: 'invalid csrf token' });
  next();
}

module.exports = {
  authenticate, verifyPassword, createSession, verify, createCsrfToken, verifyCsrfToken, requireAuth, requireRole, requireCsrf,
  loginStatus, registerFail, registerSuccess,
  ADMIN_USER, ADMIN_PASSWORD_IS_DEFAULT: ADMIN_PASSWORD === DEFAULT_ADMIN_PASSWORD,
  AUDITOR_ENABLED: !!findAccount(AUDITOR_USER),
  SECRET_SOURCE, SECRET_IS_STABLE: SECRET_SOURCE === 'env' || SECRET_SOURCE === 'file',
};
