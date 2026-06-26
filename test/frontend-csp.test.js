'use strict';
/** Frontend assets must stay compatible with script-src 'self'. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dashboardHtml = fs.readFileSync(path.join(root, 'public', 'index.html'), 'utf8');
const loginHtml = fs.readFileSync(path.join(root, 'public', 'login.html'), 'utf8');
const dashboardJs = fs.readFileSync(path.join(root, 'public', 'dashboard.js'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'public', 'login.js'), 'utf8');

test('admin pages load external scripts instead of inline scripts', () => {
  assert.match(dashboardHtml, /<script src="\/dashboard\.js" defer><\/script>/);
  assert.match(loginHtml, /<script src="\/login\.js" defer><\/script>/);
  assert.doesNotMatch(dashboardHtml, /<script>\s*\S/);
  assert.doesNotMatch(loginHtml, /<script>\s*\S/);
});

test('public frontend files avoid known mojibake after asset extraction', () => {
  for (const [name, text] of Object.entries({ dashboardHtml, loginHtml, dashboardJs, loginJs })) {
    assert.doesNotMatch(text, /[âÂÃ�]/, name);
  }
});
