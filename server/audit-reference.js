'use strict';

const crypto = require('crypto');
const auth = require('./auth');

const KEY = auth.deriveKey('redactwall:audit-reference:v1');

function opaqueReference(kind, value) {
  const prefix = String(kind || 'ref').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 24) || 'ref';
  const digest = crypto.createHmac('sha256', KEY)
    .update(`${prefix}:${String(value == null ? '' : value).trim()}`)
    .digest('base64url')
    .slice(0, 24);
  return `${prefix}_${digest}`;
}

module.exports = { opaqueReference };
