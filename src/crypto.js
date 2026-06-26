'use strict';
/**
 * At-rest encryption for the one piece of cleartext PromptSentinel must
 * sometimes retain: the raw prompt of an item HELD for admin approval.
 *
 * Everything else stored (redacted prompt, masked findings, categories) is
 * already non-sensitive. The raw prompt is only kept when a human has to review
 * it, and only ever in sealed form. AES-256-GCM gives confidentiality +
 * tamper-detection (the auth tag).
 *
 * Key: SENTINEL_DATA_KEY (preferred) or derived from SENTINEL_SECRET. Both must
 * be STABLE across restarts for sealed data to remain readable — set them in
 * any real deployment. With neither set, encryption is OFF and raw retention is
 * refused (seal() returns null), so we never write cleartext member data by
 * accident.
 */
const crypto = require('crypto');

const KEY_SRC = process.env.SENTINEL_DATA_KEY || process.env.SENTINEL_SECRET || '';
const ENABLED = KEY_SRC.length > 0;
const KEY = ENABLED ? crypto.createHash('sha256').update('promptsentinel:data-key:v1:' + KEY_SRC).digest() : null;
const PREFIX = 'enc:v1:';

/**
 * Encrypt a string for storage. Returns an `enc:v1:...` token, or null when no
 * key is configured (caller must then NOT persist the raw value).
 */
function seal(plaintext) {
  if (!ENABLED) return null;
  const s = typeof plaintext === 'string' ? plaintext : String(plaintext == null ? '' : plaintext);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(s, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return PREFIX + iv.toString('base64') + ':' + tag.toString('base64') + ':' + ct.toString('base64');
}

/** True if a stored value is a sealed token. */
function isSealed(v) { return typeof v === 'string' && v.startsWith(PREFIX); }

/**
 * Decrypt a sealed token. Returns the plaintext, or null if it can't be opened
 * (no key, wrong key, or tampered ciphertext). Non-sealed input is returned
 * as-is so legacy/plaintext rows keep working during migration.
 */
function open(token) {
  if (!isSealed(token)) return token;
  if (!ENABLED) return null;
  try {
    const [, , ivb, tagb, ctb] = token.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, Buffer.from(ivb, 'base64'));
    decipher.setAuthTag(Buffer.from(tagb, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(ctb, 'base64')), decipher.final()]).toString('utf8');
  } catch { return null; }
}

module.exports = { seal, open, isSealed, ENABLED };
