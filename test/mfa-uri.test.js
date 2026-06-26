'use strict';
/** MFA enrollment URI helper stays explicit and validates the configured seed. */
const test = require('node:test');
const assert = require('node:assert');
const {
  normalizeBase32,
  otpauthUri,
  parseArgs,
  validateSecret,
} = require('../scripts/mfa-uri');

test('normalizes and validates base32 totp secrets', () => {
  assert.strictEqual(normalizeBase32('jbsw y3dp-ehpk3pxp='), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(validateSecret('jbsw y3dp-ehpk3pxp='), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(validateSecret('short'), null);
  assert.strictEqual(validateSecret('not-valid-*'), null);
});

test('builds a standard otpauth uri for authenticator enrollment', () => {
  const uri = new URL(otpauthUri({
    secret: 'jbsw y3dp-ehpk3pxp=',
    account: 'alice@example.test',
    issuer: 'PromptSentinel Demo',
  }));

  assert.strictEqual(uri.protocol, 'otpauth:');
  assert.strictEqual(uri.hostname, 'totp');
  assert.strictEqual(decodeURIComponent(uri.pathname), '/PromptSentinel Demo:alice@example.test');
  assert.strictEqual(uri.searchParams.get('secret'), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(uri.searchParams.get('issuer'), 'PromptSentinel Demo');
  assert.strictEqual(uri.searchParams.get('algorithm'), 'SHA1');
  assert.strictEqual(uri.searchParams.get('digits'), '6');
  assert.strictEqual(uri.searchParams.get('period'), '30');
});

test('rejects invalid enrollment secrets and parses cli options', () => {
  assert.throws(() => otpauthUri({ secret: 'bad-*' }), /ADMIN_TOTP_SECRET/);
  const opts = parseArgs(['--env', 'pilot.env', '--issuer', 'Pilot CU', '--account', 'admin@pilot.test']);
  assert.match(opts.envPath, /pilot\.env$/);
  assert.strictEqual(opts.issuer, 'Pilot CU');
  assert.strictEqual(opts.account, 'admin@pilot.test');
});
