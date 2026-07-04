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

test('blocks loopback and link-local hosts (SSRF / cloud-metadata guard)', () => {
  assert.strictEqual(outboundHttpsUrl('https://169.254.169.254/latest/meta-data/'), '', 'cloud metadata endpoint');
  assert.strictEqual(outboundHttpsUrl('https://127.0.0.1/x'), '', 'ipv4 loopback');
  assert.strictEqual(outboundHttpsUrl('https://localhost/x'), '', 'localhost');
  assert.strictEqual(outboundHttpsUrl('https://[::1]/x'), '', 'ipv6 loopback');
  assert.strictEqual(outboundHttpsUrl('https://[::ffff:127.0.0.1]/x'), '', 'ipv4-mapped ipv6 loopback');
  assert.strictEqual(outboundHttpsUrl('https://[fe80::1]/x'), '', 'ipv6 link-local');
  assert.strictEqual(outboundHttpsUrl('https://0.0.0.0/x'), '', 'unspecified address');
});

test('still allows RFC1918 private hosts (on-prem SIEM/webhook target)', () => {
  // This is a self-hosted product; internal SIEM/webhooks legitimately live on
  // private networks, so private ranges must not be blanket-blocked.
  assert.strictEqual(outboundHttpsUrl('https://10.20.30.40/hec'), 'https://10.20.30.40/hec');
  assert.strictEqual(outboundHttpsUrl('https://192.168.1.5/webhook'), 'https://192.168.1.5/webhook');
});

test('rejects empty, non-string, and unparseable values', () => {
  assert.strictEqual(outboundHttpsUrl(''), '');
  assert.strictEqual(outboundHttpsUrl('   '), '');
  assert.strictEqual(outboundHttpsUrl(null), '');
  assert.strictEqual(outboundHttpsUrl(undefined), '');
  assert.strictEqual(outboundHttpsUrl(12345), '');
  assert.strictEqual(outboundHttpsUrl('not a url'), '');
});
