'use strict';
/** Frontend assets must stay compatible with script-src 'self'. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dashboardHtml = fs.readFileSync(path.join(root, 'server', 'public', 'index.html'), 'utf8');
const loginHtml = fs.readFileSync(path.join(root, 'server', 'public', 'login.html'), 'utf8');
const dashboardJs = fs.readFileSync(path.join(root, 'server', 'public', 'dashboard.js'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'server', 'public', 'login.js'), 'utf8');

test('admin pages load external scripts instead of inline scripts', () => {
  assert.match(dashboardHtml, /<script src="\/dashboard\.js" defer><\/script>/);
  assert.match(loginHtml, /<script src="\/login\.js" defer><\/script>/);
  assert.doesNotMatch(dashboardHtml, /<script>\s*\S/);
  assert.doesNotMatch(loginHtml, /<script>\s*\S/);
});

test('login page sends optional authenticator code', () => {
  assert.match(loginHtml, /id="otp"/);
  assert.match(loginHtml, /autocomplete="one-time-code"/);
  assert.match(loginJs, /const otpInput = document\.getElementById\('otp'\)/);
  assert.match(loginJs, /otp: otpInput\.value/);
  assert.match(loginJs, /mfaRequired/);
});

test('console app bundle loads module scripts instead of inline scripts', (t) => {
  const appIndexPath = path.join(root, 'server', 'public', 'app', 'index.html');
  if (!fs.existsSync(appIndexPath)) {
    t.skip('console bundle not built (npm run console:build)');
    return;
  }
  const appHtml = fs.readFileSync(appIndexPath, 'utf8');
  assert.match(appHtml, /<script type="module"[^>]* src="\/app\/assets\//);
  assert.doesNotMatch(appHtml, /<script>\s*\S/);
  assert.doesNotMatch(appHtml, /<script type="module">\s*\S/);
});

test('public frontend files avoid known mojibake after asset extraction', () => {
  for (const [name, text] of Object.entries({ dashboardHtml, loginHtml, dashboardJs, loginJs })) {
    assert.doesNotMatch(text, /[âÂÃ�]/, name);
  }
});
