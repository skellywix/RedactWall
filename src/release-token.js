'use strict';

const crypto = require('crypto');

const HASH_HEX = /^[a-f0-9]{64}$/i;

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function issueReleaseToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  return { token, hash: tokenHash(token) };
}

function timingSafeHexEqual(a, b) {
  const leftText = String(a || '');
  const rightText = String(b || '');
  if (!HASH_HEX.test(leftText) || !HASH_HEX.test(rightText)) return false;
  const left = Buffer.from(leftText, 'hex');
  const right = Buffer.from(rightText, 'hex');
  return crypto.timingSafeEqual(left, right);
}

function verifyReleaseToken(query, suppliedToken) {
  if (!query || !query._releaseTokenHash) return true;
  if (!suppliedToken) return false;
  return timingSafeHexEqual(query._releaseTokenHash, tokenHash(suppliedToken));
}

module.exports = { issueReleaseToken, tokenHash, verifyReleaseToken };
