'use strict';
/**
 * At-rest encryption for the one piece of cleartext RedactWall must
 * sometimes retain: the raw prompt of an item HELD for admin approval.
 *
 * Everything else stored (redacted prompt, masked findings, categories) is
 * already non-sensitive. The raw prompt is only kept when a human has to review
 * it, and only ever in sealed form. AES-256-GCM gives confidentiality +
 * tamper-detection (the auth tag).
 *
 * Key: REDACTWALL_DATA_KEY (preferred) or derived from REDACTWALL_SECRET. Both must
 * be STABLE across restarts for sealed data to remain readable — set them in
 * any real deployment. With neither set, encryption is OFF and raw retention is
 * refused (seal() returns null), so we never write cleartext member data by
 * accident.
 *
 * Rotation: set REDACTWALL_DATA_KEY to the NEW key and REDACTWALL_DATA_KEY_PREVIOUS
 * to the OLD one, then run `node scripts/rotate-data-key.js` to reseal stored
 * tokens under the new key. open() falls back to the previous key, so sealed
 * data stays readable mid-rotation. The token format deliberately stays
 * `enc:v1:<iv>:<tag>:<ct>` with NO embedded key id: rotation is
 * open-with-previous + reseal-with-current, so the 3-field parse never changes
 * and records sealed before this feature keep working unmodified.
 */
require('./env').loadEnv();
const crypto = require('crypto');

const KEY_SRC = process.env.REDACTWALL_DATA_KEY || process.env.REDACTWALL_SECRET || '';
const PREVIOUS_KEY_SRC = process.env.REDACTWALL_DATA_KEY_PREVIOUS || process.env.PROMPTWALL_DATA_KEY_PREVIOUS || process.env.SENTINEL_DATA_KEY_PREVIOUS || '';
const ENABLED = KEY_SRC.length > 0;

// Keep the original namespace so renamed deployments can still open retained
// approval records sealed before the RedactWall rebrand. The previous key MUST
// use the same derivation, or rotation could never open pre-rotation tokens.
function deriveKey(src) {
  return crypto.createHash('sha256').update('redactwall:data-key:v1:' + src).digest();
}

const KEY = ENABLED ? deriveKey(KEY_SRC) : null;
const PREVIOUS_KEY = PREVIOUS_KEY_SRC ? deriveKey(PREVIOUS_KEY_SRC) : null;
const PREFIX = 'enc:v1:';

/** Encrypt a string under an explicit derived key. */
function sealWithKey(key, plaintext) {
  const s = typeof plaintext === 'string' ? plaintext : String(plaintext == null ? '' : plaintext);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + iv.toString('base64') + ':' + tag.toString('base64') + ':' + ct.toString('base64');
}

/**
 * Encrypt a string for storage. Returns an `enc:v1:...` token, or null when no
 * key is configured (caller must then NOT persist the raw value).
 */
function seal(plaintext) {
  if (!ENABLED) return null;
  return sealWithKey(KEY, plaintext);
}

/** True if a stored value is a sealed token. */
function isSealed(v) { return typeof v === 'string' && v.startsWith(PREFIX); }

/** Decrypt a sealed token under an explicit derived key; null on any failure. */
function openWithKey(key, token) {
  try {
    const [, , ivb, tagb, ctb] = token.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivb, 'base64'));
    decipher.setAuthTag(Buffer.from(tagb, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(ctb, 'base64')), decipher.final()]).toString('utf8');
  } catch { return null; }
}

/**
 * Decrypt a sealed token. Tries the current key, then the previous key when
 * REDACTWALL_DATA_KEY_PREVIOUS is set (mid-rotation). Returns the plaintext, or
 * null if it can't be opened (no key, wrong key, or tampered ciphertext).
 * Non-sealed input is returned as-is so legacy/plaintext rows keep working
 * during migration.
 */
function open(token) {
  if (!isSealed(token)) return token;
  if (!ENABLED) return null;
  const current = openWithKey(KEY, token);
  if (current !== null) return current;
  return PREVIOUS_KEY ? openWithKey(PREVIOUS_KEY, token) : null;
}

/**
 * True when a token opens ONLY with the previous key, i.e. it is still sealed
 * under the pre-rotation key and must be resealed before the previous key is
 * retired. False for non-sealed values, current-key tokens, unreadable tokens,
 * or when no previous key is configured.
 */
function needsReseal(token) {
  if (!isSealed(token) || !ENABLED || !PREVIOUS_KEY) return false;
  if (openWithKey(KEY, token) !== null) return false;
  return openWithKey(PREVIOUS_KEY, token) !== null;
}

/** Rotation posture for status surfaces and the rotate-data-key CLI. */
function rotationStatus() {
  return { enabled: ENABLED, previousKeyConfigured: PREVIOUS_KEY !== null };
}

module.exports = { seal, open, isSealed, needsReseal, rotationStatus, ENABLED };
