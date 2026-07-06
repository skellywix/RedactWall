'use strict';
/** Frontend assets must stay compatible with script-src 'self'. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const loginHtml = fs.readFileSync(path.join(root, 'server', 'public', 'login.html'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'server', 'public', 'login.js'), 'utf8');
const consoleHtml = fs.readFileSync(path.join(root, 'console', 'index.html'), 'utf8');

// A <script> that carries inline code (a body, not just a src= reference) would
// require script-src 'unsafe-inline'; only external/module src scripts are safe.
const INLINE_SCRIPT_WITH_CODE = /<script(?![^>]*\bsrc=)[^>]*>\s*\S/i;
// Inline event handlers (onclick=, onload=, ...) also require 'unsafe-inline'.
const INLINE_EVENT_HANDLER = /<[^>]+\son[a-z]+\s*=\s*["']/i;

test('login page loads an external script with no inline script or handlers', () => {
  assert.match(loginHtml, /<script src="\/login\.js" defer><\/script>/);
  assert.doesNotMatch(loginHtml, INLINE_SCRIPT_WITH_CODE);
  assert.doesNotMatch(loginHtml, INLINE_EVENT_HANDLER);
});

test('console template loads a module bundle with no inline script or handlers', () => {
  assert.match(consoleHtml, /<script type="module"[^>]*\ssrc="\/src\/main\.tsx"><\/script>/);
  assert.doesNotMatch(consoleHtml, INLINE_SCRIPT_WITH_CODE);
  assert.doesNotMatch(consoleHtml, INLINE_EVENT_HANDLER);
});

test('login page sends optional authenticator code', () => {
  assert.match(loginHtml, /id="otp"/);
  assert.match(loginHtml, /autocomplete="one-time-code"/);
  assert.match(loginJs, /const otpInput = document\.getElementById\('otp'\)/);
  assert.match(loginJs, /otp: otpInput\.value/);
  assert.match(loginJs, /mfaRequired/);
});

test('public frontend files avoid known mojibake after asset extraction', () => {
  for (const [name, text] of Object.entries({ loginHtml, loginJs, consoleHtml })) {
    assert.doesNotMatch(text, /[âÂÃ�]/, name);
  }
});
