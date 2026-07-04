'use strict';
/** outboundHttpsUrl: only clean https URLs survive; everything else -> ''. */
const test = require('node:test');
const assert = require('node:assert');
const { outboundHttpsUrl } = require('../server/url-policy');

test('accepts a plain https URL and normalizes it', () => {
  assert.strictEqual(outboundHttpsUrl('https://hooks.example.test/webhook'), 'https://hooks.example.test/webhook');
});

test('strips the fragment but keeps path and query', () => {
  assert.strictEqual(
    outboundHttpsUrl('https://siem.example.test/ingest?token=abc#section'),
    'https://siem.example.test/ingest?token=abc',
  );
});

test('trims surrounding whitespace before parsing', () => {
  assert.strictEqual(outboundHttpsUrl('  https://example.test/x  '), 'https://example.test/x');
});

test('rejects non-https schemes', () => {
  assert.strictEqual(outboundHttpsUrl('http://example.test/x'), '');
  assert.strictEqual(outboundHttpsUrl('ftp://example.test/x'), '');
  assert.strictEqual(outboundHttpsUrl('javascript:alert(1)'), '');
});

test('rejects URLs carrying embedded credentials (SSRF/credential leak guard)', () => {
  assert.strictEqual(outboundHttpsUrl('https://user@example.test/x'), '');
  assert.strictEqual(outboundHttpsUrl('https://user:pass@example.test/x'), '');
});

test('rejects empty, non-string, and unparseable values', () => {
  assert.strictEqual(outboundHttpsUrl(''), '');
  assert.strictEqual(outboundHttpsUrl('   '), '');
  assert.strictEqual(outboundHttpsUrl(null), '');
  assert.strictEqual(outboundHttpsUrl(undefined), '');
  assert.strictEqual(outboundHttpsUrl(12345), '');
  assert.strictEqual(outboundHttpsUrl('not a url'), '');
});
