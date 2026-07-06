'use strict';
/**
 * Signed local handoff events for future native endpoint interceptors.
 *
 * A native collector can write one small JSON event per attempted desktop-AI
 * file upload. The endpoint agent validates the event, reads the referenced
 * local file, and keeps the event itself free of file bytes or prompt text.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { withEnvAliases } = require('../../server/env');

const EVENT_VERSION = 1;
const MAX_EVENT_BYTES = 16 * 1024;
const DEFAULT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_HANDOFF_DIR = path.join(os.tmpdir(), 'redactwall-native-handoff');
const DISALLOWED_EVENT_KEYS = new Set([
  'body',
  'bytes',
  'content',
  'contentBase64',
  'contentbase64',
  'content_base64',
  'fileBytes',
  'filebytes',
  'file_bytes',
  'prompt',
  'raw',
  'rawText',
  'rawtext',
  'raw_text',
  'text',
]);
const ALLOWED_EVENT_KEYS = new Set([
  'version',
  'id',
  'createdAt',
  'operation',
  'filePath',
  'destination',
  'user',
  'nonce',
  'signature',
]);
const ALLOWED_DESTINATION_KEYS = new Set([
  'app',
  'name',
  'process',
  'url',
]);

function defaultHandoffDir(env = process.env) {
  const resolved = withEnvAliases(env);
  return resolved.ENDPOINT_AGENT_HANDOFF_DIR || DEFAULT_HANDOFF_DIR;
}

function configuredHandoffSecret(opts = {}) {
  const env = withEnvAliases(process.env);
  const value = Object.prototype.hasOwnProperty.call(opts, 'secret')
    ? opts.secret
    : env.ENDPOINT_AGENT_HANDOFF_SECRET;
  return typeof value === 'string' ? value.trim() : '';
}

function boundedString(value, fallback, max) {
  if (typeof value !== 'string') return fallback;
  const clean = value.replace(/[\r\n\t]/g, ' ').trim();
  return clean ? clean.slice(0, max) : fallback;
}

function normalizedEventKey(key) {
  return String(key || '').replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

function assertNoPayloadKeys(value, prefix = 'event') {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (DISALLOWED_EVENT_KEYS.has(key) || DISALLOWED_EVENT_KEYS.has(normalizedEventKey(key))) {
      throw new Error(`native handoff ${prefix}.${key} is not allowed`);
    }
    if (child && typeof child === 'object') {
      assertNoPayloadKeys(child, `${prefix}.${key}`);
    }
  }
}

function assertAllowedKeys(value, allowed, prefix) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return;
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new Error(`native handoff ${prefix}.${key} is not allowed`);
    }
  }
}

function assertAllowedEventShape(event) {
  assertAllowedKeys(event, ALLOWED_EVENT_KEYS, 'event');
  const destination = event.destination;
  if (destination && typeof destination === 'object') {
    if (Array.isArray(destination)) {
      throw new Error('native handoff event.destination is not allowed');
    }
    assertAllowedKeys(destination, ALLOWED_DESTINATION_KEYS, 'event.destination');
  }
}

function normalizeDestination(destination) {
  if (typeof destination === 'string') {
    // Emit the same {app,process,url} shape as the object path so canonicalEvent
    // is stable whether it runs on a raw or already-normalized event; otherwise a
    // signature computed over a string destination never re-validates.
    return { app: boundedString(destination, 'desktop-ai-app', 80), process: '', url: '' };
  }
  const src = destination && typeof destination === 'object' ? destination : {};
  return {
    app: boundedString(src.app || src.name, 'desktop-ai-app', 80),
    process: boundedString(src.process, '', 80),
    url: boundedString(src.url, '', 200),
  };
}

function publicDestination(destination) {
  const normalized = normalizeDestination(destination);
  return normalized.app || 'desktop-ai-app';
}

function normalizeEvent(event, opts = {}) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    throw new Error('native handoff event must be a JSON object');
  }
  assertNoPayloadKeys(event);
  assertAllowedEventShape(event);
  if (event.version !== EVENT_VERSION) {
    throw new Error('native handoff version is unsupported');
  }
  const operation = boundedString(event.operation, 'upload', 32);
  if (operation !== 'upload') {
    throw new Error('native handoff operation is unsupported');
  }
  const filePath = boundedString(event.filePath, '', 1024);
  if (/^\\\\/.test(filePath)) {
    throw new Error('native handoff filePath must be a local path');
  }
  if (!filePath || !(path.isAbsolute(filePath) || path.win32.isAbsolute(filePath))) {
    throw new Error('native handoff filePath must be absolute');
  }
  const createdAt = boundedString(event.createdAt, '', 64);
  const createdMs = Date.parse(createdAt);
  if (!Number.isFinite(createdMs)) {
    throw new Error('native handoff createdAt is invalid');
  }
  const nowMs = opts.now instanceof Date ? opts.now.getTime() : Date.now();
  const ttlMs = Number.isFinite(Number(opts.ttlMs)) ? Number(opts.ttlMs) : DEFAULT_TTL_MS;
  if (Math.abs(nowMs - createdMs) > ttlMs) {
    throw new Error('native handoff event is outside the allowed time window');
  }
  return {
    version: EVENT_VERSION,
    id: boundedString(event.id, crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'), 120),
    createdAt: new Date(createdMs).toISOString(),
    operation,
    filePath,
    destination: normalizeDestination(event.destination),
    user: boundedString(event.user, '', 160),
    nonce: boundedString(event.nonce, '', 160),
  };
}

function canonicalEvent(event) {
  const normalized = normalizeEvent(event, {
    ttlMs: Number.MAX_SAFE_INTEGER,
    now: new Date(event.createdAt || Date.now()),
  });
  return JSON.stringify({
    version: normalized.version,
    id: normalized.id,
    createdAt: normalized.createdAt,
    operation: normalized.operation,
    filePath: normalized.filePath,
    destination: normalized.destination,
    user: normalized.user,
    nonce: normalized.nonce,
  });
}

function signatureFor(event, secret) {
  const key = typeof secret === 'string' ? secret.trim() : '';
  if (key.length < 32) throw new Error('native handoff secret must be at least 32 characters');
  return crypto.createHmac('sha256', key).update(canonicalEvent(event)).digest('hex');
}

function timingSafeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (!/^[0-9a-f]{64}$/i.test(left) || !/^[0-9a-f]{64}$/i.test(right)) return false;
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function signHandoffEvent(event, secret) {
  const normalized = normalizeEvent(event, {
    ttlMs: Number.MAX_SAFE_INTEGER,
    now: new Date(event.createdAt || Date.now()),
  });
  return { ...normalized, signature: signatureFor(normalized, secret) };
}

function validateHandoffEvent(event, opts = {}) {
  const secret = configuredHandoffSecret(opts);
  if (!secret) throw new Error('native handoff secret is not configured');
  const normalized = normalizeEvent(event, opts);
  const expected = signatureFor(normalized, secret);
  if (!timingSafeEqualHex(expected, event.signature)) {
    throw new Error('native handoff signature is invalid');
  }
  return normalized;
}

function readHandoffFile(file, opts = {}) {
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error('native handoff path is not a file');
  if (stat.size > MAX_EVENT_BYTES) throw new Error('native handoff event is too large');
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  return validateHandoffEvent(parsed, opts);
}

module.exports = {
  EVENT_VERSION,
  MAX_EVENT_BYTES,
  DEFAULT_TTL_MS,
  defaultHandoffDir,
  configuredHandoffSecret,
  publicDestination,
  signatureFor,
  signHandoffEvent,
  validateHandoffEvent,
  readHandoffFile,
};
