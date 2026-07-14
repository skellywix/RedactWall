'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const trust = require('../scripts/check-license-trust-anchor');

test('release trust check rejects the repository placeholder', () => {
  assert.throws(() => trust.check([], {}), /placeholder/);
});

test('release trust check accepts a bounded direct Ed25519 public-key file', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-trust-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'license-root-public.pem');
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(target, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  const status = trust.check(['--public-key-file', target], {});
  assert.strictEqual(status.ok, true);
  assert.strictEqual(status.ed25519, true);
});

test('release trust check reads one direct single-link handle', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-trust-link-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const target = path.join(root, 'license-root-public.pem');
  const alias = path.join(root, 'license-root-public-copy.pem');
  const { publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(target, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  fs.linkSync(target, alias);
  assert.throws(() => trust.readPublicKeyFile(target), /single-link/);
  const source = trust.readPublicKeyFile.toString();
  assert.match(source, /openSync/);
  assert.match(source, /O_NOFOLLOW/);
  assert.match(source, /fstatSync/);
  assert.match(source, /readFileSync\(descriptor/);
});
