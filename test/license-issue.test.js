'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { main } = require('../scripts/license-issue');
const license = require('../server/license');
const privatePaths = require('../server/private-path');

function writePrivateKey(file, key) {
  fs.writeFileSync(file, key.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  privatePaths.securePrivatePath(file, {
    directory: false,
    label: 'test offline signing key',
    ownerLabel: 'test offline signing key',
  });
}

function withDirectoryFsyncEio(callback) {
  const original = fs.fsyncSync;
  fs.fsyncSync = (fd) => {
    if (fs.fstatSync(fd).isDirectory()) {
      const error = new Error('synthetic license directory fsync EIO');
      error.code = 'EIO';
      throw error;
    }
    return original(fd);
  };
  try { return callback(); } finally { fs.fsyncSync = original; }
}

test('keypair initialization is exclusive and never overwrites or leaves a partial pair', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-keypair-'));
  const keyDir = path.join(tmp, 'offline-keys');
  const io = { log() {}, error() {} };
  try {
    const firstExitCodes = [];
    main(['--init-keypair', keyDir], { console: io, setExitCode: (code) => firstExitCodes.push(code) });
    assert.deepStrictEqual(firstExitCodes, []);
    const privatePath = path.join(keyDir, 'license-signing-key.pem');
    const publicPath = path.join(keyDir, 'license-signing-pub.pem');
    const beforePrivate = fs.readFileSync(privatePath);
    const beforePublic = fs.readFileSync(publicPath);
    privatePaths.assertPrivatePath(keyDir, { directory: true, label: 'offline key directory' });
    privatePaths.assertPrivatePath(privatePath, { directory: false, label: 'offline private key' });
    privatePaths.assertPrivatePath(publicPath, { directory: false, label: 'offline public key' });
    assert.strictEqual(
      crypto.createPublicKey(crypto.createPrivateKey(beforePrivate)).export({ type: 'spki', format: 'pem' }).toString(),
      beforePublic.toString(),
    );

    const errors = [];
    const secondExitCodes = [];
    main(['--init-keypair', keyDir], {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => secondExitCodes.push(code),
    });
    assert.deepStrictEqual(secondExitCodes, [1]);
    assert.ok(errors.some((message) => /refusing to overwrite/.test(message)));
    assert.deepStrictEqual(fs.readFileSync(privatePath), beforePrivate);
    assert.deepStrictEqual(fs.readFileSync(publicPath), beforePublic);
    assert.deepStrictEqual(fs.readdirSync(keyDir).sort(), ['license-signing-key.pem', 'license-signing-pub.pem']);

    const partialDir = path.join(tmp, 'partial');
    fs.mkdirSync(partialDir);
    const sentinel = Buffer.from('existing-public-key');
    fs.writeFileSync(path.join(partialDir, 'license-signing-pub.pem'), sentinel);
    const partialExitCodes = [];
    main(['--init-keypair', partialDir], { console: io, setExitCode: (code) => partialExitCodes.push(code) });
    assert.deepStrictEqual(partialExitCodes, [1]);
    assert.strictEqual(fs.existsSync(path.join(partialDir, 'license-signing-key.pem')), false);
    assert.deepStrictEqual(fs.readFileSync(path.join(partialDir, 'license-signing-pub.pem')), sentinel);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('license issuer refuses to create an unbound customer license', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-issue-'));
  const keyPath = path.join(tmp, 'private.pem');
  const outPath = path.join(tmp, 'redactwall.lic');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  writePrivateKey(keyPath, privateKey);
  const errors = [];
  const exitCodes = [];

  try {
    main([
      '--key', keyPath,
      '--plan', 'standard',
      '--seats', '25',
      '--expires', '2027-01-01',
      '--out', outPath,
    ], {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => exitCodes.push(code),
    });

    assert.deepStrictEqual(exitCodes, [1]);
    assert.ok(errors.some((message) => message.includes('--customer-id')));
    assert.strictEqual(fs.existsSync(outPath), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('license issuer refuses an invalid customer id before writing output', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-issue-invalid-'));
  const keyPath = path.join(tmp, 'private.pem');
  const outPath = path.join(tmp, 'redactwall.lic');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  writePrivateKey(keyPath, privateKey);
  const errors = [];
  const exitCodes = [];

  try {
    main([
      '--key', keyPath,
      '--customer-id', 'billing@example.test',
      '--plan', 'standard',
      '--seats', '25',
      '--expires', '2027-01-01',
      '--out', outPath,
    ], {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => exitCodes.push(code),
    });

    assert.deepStrictEqual(exitCodes, [1]);
    assert.ok(errors.some((message) => message.includes('--customer-id')));
    assert.strictEqual(fs.existsSync(outPath), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('license issuer writes a verifiable customer-bound license', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-issue-ok-'));
  const keyPath = path.join(tmp, 'private.pem');
  const outPath = path.join(tmp, 'redactwall.lic');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  writePrivateKey(keyPath, privateKey);
  const errors = [];
  const exitCodes = [];

  try {
    main([
      '--key', keyPath,
      '--customer', 'Test Credit Union',
      '--customer-id', 'cu-bound',
      '--plan', 'standard',
      '--seats', '25',
      '--expires', '2027-01-01',
      '--out', outPath,
    ], {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => exitCodes.push(code),
    });

    assert.deepStrictEqual(errors, []);
    assert.deepStrictEqual(exitCodes, []);
    const verified = license.verifyLicenseText(fs.readFileSync(outPath, 'utf8'), {
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      expectedCustomerId: 'cu-bound',
    });
    assert.strictEqual(verified.ok, true);
    assert.strictEqual(verified.payload.customerId, 'cu-bound');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('license output cannot clobber the signing key or an existing file without force', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-no-clobber-'));
  const keyPath = path.join(tmp, 'private.pem');
  const outPath = path.join(tmp, 'redactwall.lic');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const privateBytes = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  fs.writeFileSync(keyPath, privateBytes, { mode: 0o600 });
  privatePaths.securePrivatePath(keyPath, {
    directory: false,
    label: 'test offline signing key',
    ownerLabel: 'test offline signing key',
  });
  const baseArgs = [
    '--key', keyPath,
    '--customer', 'No Clobber Credit Union',
    '--customer-id', 'cu-no-clobber',
    '--plan', 'standard',
    '--seats', '25',
    '--expires', '2027-01-01',
  ];
  const invoke = (args) => {
    const errors = [];
    const exitCodes = [];
    main(args, {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => exitCodes.push(code),
    });
    return { errors, exitCodes };
  };

  try {
    const samePath = invoke([...baseArgs, '--out', keyPath]);
    assert.deepStrictEqual(samePath.exitCodes, [1]);
    assert.ok(samePath.errors.some((message) => /must not be the signing key path/.test(message)));
    assert.deepStrictEqual(fs.readFileSync(keyPath), privateBytes);

    const sentinel = Buffer.from('existing-license-output');
    fs.writeFileSync(outPath, sentinel);
    const collision = invoke([...baseArgs, '--out', outPath]);
    assert.deepStrictEqual(collision.exitCodes, [1]);
    assert.deepStrictEqual(fs.readFileSync(outPath), sentinel);

    const forced = invoke([...baseArgs, '--out', outPath, '--force']);
    assert.deepStrictEqual(forced.exitCodes, []);
    assert.notDeepStrictEqual(fs.readFileSync(outPath), sentinel);
    assert.deepStrictEqual(fs.readFileSync(keyPath), privateBytes);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('keypair initialization rejects directory-fsync EIO without leaving a partial identity', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-keypair-durable-'));
  const keyDir = path.join(tmp, 'offline-keys');
  const errors = [];
  const exitCodes = [];
  try {
    withDirectoryFsyncEio(() => main(['--init-keypair', keyDir], {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => exitCodes.push(code),
    }));
    assert.deepStrictEqual(exitCodes, [1]);
    assert.ok(errors.some((message) => /directory fsync EIO/.test(message)));
    assert.deepStrictEqual(fs.existsSync(keyDir) ? fs.readdirSync(keyDir) : [], []);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('forced license publication rejects directory-fsync EIO and restores exact prior bytes', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-license-output-durable-'));
  const keyPath = path.join(tmp, 'private.pem');
  const outPath = path.join(tmp, 'redactwall.lic');
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  writePrivateKey(keyPath, privateKey);
  const baseline = Buffer.from('exact-prior-license\r\n');
  fs.writeFileSync(outPath, baseline, { mode: 0o600 });
  const errors = [];
  const exitCodes = [];
  try {
    withDirectoryFsyncEio(() => main([
      '--key', keyPath,
      '--customer', 'Durability Credit Union',
      '--customer-id', 'cu-durability',
      '--plan', 'standard',
      '--seats', '25',
      '--expires', '2027-01-01',
      '--out', outPath,
      '--force',
    ], {
      console: { log() {}, error: (message) => errors.push(String(message)) },
      setExitCode: (code) => exitCodes.push(code),
    }));
    assert.deepStrictEqual(exitCodes, [1]);
    assert.ok(errors.some((message) => /directory fsync EIO/.test(message)));
    assert.deepStrictEqual(fs.readFileSync(outPath), baseline);
    assert.deepStrictEqual(fs.readdirSync(tmp).sort(), ['private.pem', 'redactwall.lic']);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
