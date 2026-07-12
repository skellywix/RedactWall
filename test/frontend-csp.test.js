'use strict';
/** Frontend assets must stay compatible with script-src 'self'. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const loginHtml = fs.readFileSync(path.join(root, 'server', 'public', 'login.html'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'server', 'public', 'login.js'), 'utf8');
const authResponseJs = fs.readFileSync(path.join(root, 'server', 'public', 'auth-response.js'), 'utf8');
const inviteHtml = fs.readFileSync(path.join(root, 'server', 'public', 'accept-invite.html'), 'utf8');
const inviteJs = fs.readFileSync(path.join(root, 'server', 'public', 'accept-invite.js'), 'utf8');
const authCss = fs.readFileSync(path.join(root, 'server', 'public', 'auth-surface.css'), 'utf8');
const consoleHtml = fs.readFileSync(path.join(root, 'console', 'index.html'), 'utf8');

// A <script> that carries inline code (a body, not just a src= reference) would
// require script-src 'unsafe-inline'; only external/module src scripts are safe.
const INLINE_SCRIPT_WITH_CODE = /<script(?![^>]*\bsrc=)[^>]*>\s*\S/i;
// Inline event handlers (onclick=, onload=, ...) also require 'unsafe-inline'.
const INLINE_EVENT_HANDLER = /<[^>]+\son[a-z]+\s*=\s*["']/i;

test('login page loads an external script with no inline script or handlers', () => {
  assert.match(loginHtml, /<script src="\/auth-response\.js" defer><\/script>/);
  assert.match(loginHtml, /<script src="\/login\.js" defer><\/script>/);
  assert.ok(loginHtml.indexOf('/auth-response.js') < loginHtml.indexOf('/login.js'));
  assert.match(loginHtml, /<link rel="stylesheet" href="\/auth-surface\.css" \/>/);
  assert.doesNotMatch(loginHtml, INLINE_SCRIPT_WITH_CODE);
  assert.doesNotMatch(loginHtml, INLINE_EVENT_HANDLER);
});

test('invitation page shares the external auth surface with no inline script or handlers', () => {
  assert.match(inviteHtml, /<script src="\/auth-response\.js" defer><\/script>/);
  assert.match(inviteHtml, /<script src="\/accept-invite\.js" defer><\/script>/);
  assert.ok(inviteHtml.indexOf('/auth-response.js') < inviteHtml.indexOf('/accept-invite.js'));
  assert.match(inviteHtml, /<link rel="stylesheet" href="\/auth-surface\.css" \/>/);
  assert.doesNotMatch(inviteHtml, INLINE_SCRIPT_WITH_CODE);
  assert.doesNotMatch(inviteHtml, INLINE_EVENT_HANDLER);
  assert.doesNotMatch(authCss, /url\s*\(/i);
});

test('console template loads a module bundle with no inline script or handlers', () => {
  assert.match(consoleHtml, /<script type="module"[^>]*\ssrc="\/src\/main\.tsx"><\/script>/);
  assert.doesNotMatch(consoleHtml, INLINE_SCRIPT_WITH_CODE);
  assert.doesNotMatch(consoleHtml, INLINE_EVENT_HANDLER);
});

test('login page sends an optional authenticator or recovery code', () => {
  assert.match(loginHtml, /id="otp"/);
  assert.match(loginHtml, /autocomplete="one-time-code"/);
  assert.match(loginHtml, /maxlength="11"/);
  assert.doesNotMatch(loginHtml, /id="otp"[^>]*inputmode="numeric"/);
  assert.match(loginJs, /const otpInput = document\.getElementById\('otp'\)/);
  assert.match(loginJs, /otp: otpInput\.value/);
  assert.match(loginJs, /mfaRequired/);
  assert.match(loginJs, /boundedResponse\?\.readJson/);
  assert.match(inviteJs, /boundedResponse\?\.readJson/);
  assert.doesNotMatch(loginJs, /\.json\s*\(/);
  assert.doesNotMatch(inviteJs, /\.json\s*\(/);
  assert.match(authResponseJs, /DEFAULT_MAX_BYTES = 16 \* 1024/);
});

test('public frontend files avoid known mojibake after asset extraction', () => {
  for (const [name, text] of Object.entries({ loginHtml, loginJs, authResponseJs, inviteHtml, inviteJs, authCss, consoleHtml })) {
    assert.doesNotMatch(text, /[âÂÃ�]/, name);
  }
});
