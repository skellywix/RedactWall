'use strict';
/** Server must ship baseline browser security headers and hardened cookies. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

test('server disables framework fingerprinting and sets security headers', () => {
  assert.match(server, /app\.disable\('x-powered-by'\)/);
  for (const header of [
    'Content-Security-Policy',
    'Referrer-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
  ]) {
    assert.ok(server.includes(header), header);
  }
  assert.match(server, /frame-ancestors 'none'/);
  assert.match(server, /X-Frame-Options': 'DENY'/);
  assert.match(server, /X-Content-Type-Options': 'nosniff'/);
});

test('admin session cookie uses strict same-site and httpOnly attributes', () => {
  assert.match(server, /const SESSION_COOKIE_OPTIONS = \{/);
  assert.match(server, /httpOnly: true/);
  assert.match(server, /sameSite: 'strict'/);
  assert.match(server, /path: '\/'/);
  assert.match(server, /res\.cookie\('sentinel_session', token, SESSION_COOKIE_OPTIONS\)/);
  assert.match(server, /res\.clearCookie\('sentinel_session', \{/);
});
