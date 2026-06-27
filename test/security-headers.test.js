'use strict';
/** Server must ship baseline browser security headers and hardened cookies. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const server = fs.readFileSync(path.join(__dirname, '..', 'server/app.js'), 'utf8');

test('server disables framework fingerprinting and sets security headers', () => {
  assert.match(server, /app\.disable\('x-powered-by'\)/);
  assert.match(server, /const helmet = require\('helmet'\)/);
  assert.match(server, /app\.use\(helmet\(\{/);
  assert.match(server, /scriptSrc: \["'self'"\]/);
  assert.doesNotMatch(server, /scriptSrc: \["'self'", "'unsafe-inline'"\]/);
  assert.match(server, /frameAncestors: \["'none'"\]/);
  assert.match(server, /frameguard: \{ action: 'deny' \}/);
  assert.match(server, /referrerPolicy: \{ policy: 'no-referrer' \}/);
  assert.match(server, /Permissions-Policy/);
});

test('admin session cookie uses strict same-site and httpOnly attributes', () => {
  assert.match(server, /const SESSION_COOKIE_OPTIONS = \{/);
  assert.match(server, /httpOnly: true/);
  assert.match(server, /sameSite: 'strict'/);
  assert.match(server, /path: '\/'/);
  assert.match(server, /res\.cookie\('sentinel_session', token, SESSION_COOKIE_OPTIONS\)/);
  assert.match(server, /res\.clearCookie\('sentinel_session', \{/);
});
