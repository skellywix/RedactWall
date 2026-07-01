'use strict';
/** CI and local review gates should enforce the same release-critical checks. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const ci = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');

test('local review gate runs generated docs, release-critical tests, and all browser E2E specs', () => {
  const reviewCi = pkg.scripts['review:ci'];
  assert.match(reviewCi, /git diff --check/);
  assert.match(reviewCi, /npm run docs:demo-guide:check/);
  assert.match(reviewCi, /npm run ai-domains:check/);
  assert.match(reviewCi, /npm test/);
  assert.match(reviewCi, /npm run test:browser/);
  assert.match(reviewCi, /npm run sync-check/);
  assert.match(reviewCi, /npm run eval/);
  assert.doesNotMatch(reviewCi, /npm run test:admin-console\b/, 'full local gate must not skip browser-extension E2E');
});

test('GitHub CI keeps the generated docs and browser E2E gates in the protected workflow', () => {
  assert.match(ci, /npm audit --omit=dev/);
  assert.match(ci, /npm run docs:demo-guide:check/);
  assert.match(ci, /npm run sync-check/);
  assert.match(ci, /npm run ai-domains:check/);
  assert.match(ci, /npm test/);
  assert.match(ci, /npm run test:browser/);
  assert.match(ci, /node scripts\/eval-detect\.js --ci/);
  assert.match(ci, /git diff --exit-code -- config\/policy\.json/);
  assert.match(ci, /docker build -t promptwall:ci \./);
  assert.doesNotMatch(ci, /npm run test:admin-console\b/, 'protected CI should run the full browser suite');
});

test('release packaging and install-check commands remain available', () => {
  for (const script of [
    'package:extension',
    'release:extension:check',
    'package:endpoint-agent',
    'package:mcp-guard',
    'endpoint:check',
    'mcp:check',
  ]) {
    assert.ok(pkg.scripts[script], script);
  }
});
