'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const privatePaths = require('../server/private-path');
const policyBundle = require('../server/policy-bundle');
const fileMutationLock = require('../server/file-mutation-lock');

function tempFile(t, label, body = 'private material') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `redactwall-${label}-`));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'material');
  fs.writeFileSync(file, body, { mode: 0o600 });
  return file;
}

function exactAcl(target, principal = 'TEST\\policy-user') {
  return [
    `${target} ${principal}:(F)`,
    '          NT AUTHORITY\\SYSTEM:(F)',
    'Successfully processed 1 files',
  ].join('\r\n');
}

test('shared Windows private-path hardening resets, grants, and verifies only owner plus LocalSystem', (t) => {
  const file = tempFile(t, 'private-acl');
  const calls = [];
  privatePaths.securePrivatePath(file, {
    platform: 'win32',
    directory: false,
    principal: 'TEST\\policy-user',
    label: 'policy material',
    spawn(command, args, options) {
      calls.push({ command, args, options });
      return args.length === 1
        ? { status: 0, stdout: exactAcl(file) }
        : { status: 0, stdout: 'processed 1 file' };
    },
  });
  assert.deepStrictEqual(calls.map((call) => call.command), ['icacls.exe', 'icacls.exe', 'icacls.exe']);
  assert.deepStrictEqual(calls[0].args, [file, '/reset', '/q']);
  assert.deepStrictEqual(calls[1].args, [
    file, '/inheritance:r', '/grant:r', 'TEST\\policy-user:(F)', '*S-1-5-18:(F)', '/q',
  ]);
  assert.deepStrictEqual(calls[2].args, [file]);
  assert.ok(calls.every((call) => call.options.windowsHide === true));
});

test('shared Windows ACL verification fails closed on inherited or extra principals', (t) => {
  const file = tempFile(t, 'private-acl-broad');
  const broad = exactAcl(file).replace(
    'Successfully processed 1 files',
    '          BUILTIN\\Users:(RX)\r\nSuccessfully processed 1 files',
  );
  assert.throws(() => privatePaths.assertPrivatePath(file, {
    platform: 'win32',
    directory: false,
    principal: 'TEST\\policy-user',
    label: 'policy material',
    spawn() { return { status: 0, stdout: broad }; },
  }), /ACL verification failed/);
  assert.strictEqual(privatePaths.privateAclListing(
    exactAcl(file).replace('(F)', '(I)(F)'),
    'TEST\\policy-user',
  ), false);
  assert.strictEqual(privatePaths.privateAclListing(
    exactAcl(file).replace('(F)', '(DENY)(F)'),
    'TEST\\policy-user',
  ), false);
});

test('shared Windows ACL verification rejects an exact DACL with a foreign descriptor owner', (t) => {
  const file = tempFile(t, 'private-acl-foreign-owner');
  assert.throws(() => privatePaths.assertPrivatePath(file, {
    platform: 'win32',
    directory: false,
    principal: 'TEST\\policy-user',
    label: 'policy material',
    ownerIdentity: {
      processSid: 'S-1-5-21-100-200-300-1001',
      ownerSid: 'S-1-5-21-100-200-300-1002',
    },
    spawn() { return { status: 0, stdout: exactAcl(file) }; },
  }), /owner verification failed/);
});

test('policy signing-key initialization uses the shared verified Windows ACL contract', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-policy-key-acl-'));
  const privateLockRoot = `${dir}-locks`;
  t.after(() => {
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(privateLockRoot, { recursive: true, force: true });
  });
  const keyFile = path.join(dir, '.policy-bundle-key.pem');
  const lockPath = fileMutationLock.lockPathFor(keyFile);
  const privatePathSecurity = {
    platform: 'win32',
    principal: 'TEST\\policy-user',
    privateLockRoot,
  };
  const directoryLockPath = fileMutationLock.lockPathFor(
    privatePaths.privateDirectoryLockTarget(dir, privatePathSecurity),
  );
  const calls = [];
  let directorySecured = false;
  let directoryHardenedUnderLock = false;
  let keyPublishedUnderBothLocks = false;
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    if (args[0] === dir && args.includes('/grant:r')) {
      directoryHardenedUnderLock = !fs.existsSync(lockPath) && fs.existsSync(directoryLockPath);
      directorySecured = true;
    }
    if (/\.tmp$/.test(args[0]) && args.includes('/grant:r')) {
      keyPublishedUnderBothLocks = fs.existsSync(lockPath) && fs.existsSync(directoryLockPath);
    }
    const broad = exactAcl(args[0]).replace(
      'Successfully processed 1 files',
      '          BUILTIN\\Users:(R)\r\nSuccessfully processed 1 files',
    );
    return args.length === 1
      ? { status: 0, stdout: args[0] === dir && !directorySecured ? broad : exactAcl(args[0]) }
      : { status: 0, stdout: 'processed 1 file' };
  };
  policyBundle._resetForTest();
  const publicKey = policyBundle.publicKeyPem({
    keyFile,
    reload: true,
    privatePathSecurity: {
      ...privatePathSecurity,
      spawn,
    },
  });
  assert.match(publicKey, /BEGIN PUBLIC KEY/);
  assert.strictEqual(directoryHardenedUnderLock, true);
  assert.strictEqual(keyPublishedUnderBothLocks, true);
  assert.strictEqual(fs.existsSync(lockPath), false);
  assert.strictEqual(fs.existsSync(directoryLockPath), false);
  assert.ok(calls.some((call) => call.args[0] === keyFile && call.args.includes('/grant:r')));
  assert.ok(calls.some((call) => call.args.length === 1 && call.args[0] === keyFile));
  assert.ok(calls.every((call) => call.command === 'icacls.exe' && call.options.windowsHide === true));
});

test('policy signing key rejects attacker bytes planted during directory ACL hardening', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-policy-key-preseed-'));
  const dir = path.join(root, 'data');
  const keyFile = path.join(dir, '.policy-bundle-key.pem');
  const principal = 'TEST\\policy-user';
  const attackerKey = crypto.generateKeyPairSync('ed25519').privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  });
  let directorySecured = false;
  let planted = false;
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const options = {
    keyFile,
    reload: true,
    privatePathSecurity: {
      platform: 'win32',
      principal,
      privateLockRoot: path.join(root, 'locks'),
      spawn(command, args) {
        if (args[0] === dir && args.includes('/reset')) {
          fs.writeFileSync(keyFile, attackerKey, { mode: 0o600 });
          planted = true;
        }
        if (args[0] === dir && args.includes('/grant:r')) directorySecured = true;
        const exact = exactAcl(args[0], principal);
        const broad = exact.replace(
          'Successfully processed 1 files',
          '          BUILTIN\\Users:(R)\r\nSuccessfully processed 1 files',
        );
        return args.length === 1
          ? { status: 0, stdout: args[0] === dir && !directorySecured ? broad : exact }
          : { status: 0, stdout: 'processed 1 file' };
      },
    },
  };
  policyBundle._resetForTest();
  assert.throws(() => policyBundle.publicKeyPem(options), /before its permissions were trusted/);
  assert.strictEqual(planted, true);
  assert.deepStrictEqual(fs.readFileSync(keyFile), Buffer.from(attackerKey));
  assert.strictEqual(fs.existsSync(fileMutationLock.lockPathFor(keyFile)), false);
  policyBundle._resetForTest();
  assert.throws(
    () => policyBundle.publicKeyPem(options),
    /before its permissions were trusted/,
    'a restart must not accept the planted signing identity after the directory was hardened',
  );
  assert.deepStrictEqual(fs.readFileSync(keyFile), Buffer.from(attackerKey));
});

test('bounded handle reads reject a file that grows during the read', (t) => {
  const file = tempFile(t, 'private-grow', '0123456789abcdef');
  let grew = false;
  const fsImpl = {
    ...fs,
    readSync(fd, buffer, offset, length, position) {
      if (!grew) {
        grew = true;
        fs.appendFileSync(file, 'x'.repeat(64));
      }
      return fs.readSync(fd, buffer, offset, length, position);
    },
  };
  assert.throws(() => privatePaths.readBoundedRegularFile(file, {
    fs: fsImpl,
    maxBytes: 32,
    label: 'bounded policy file',
  }), /size limit|changed while reading/);
});

test('bounded handle reads reject path-to-handle identity swaps', (t) => {
  const file = tempFile(t, 'private-swap', 'trusted-public-key');
  const replacement = path.join(path.dirname(file), 'replacement');
  fs.writeFileSync(replacement, 'attacker-public-key', { mode: 0o600 });
  const fsImpl = {
    ...fs,
    openSync(target, flags, mode) {
      return fs.openSync(target === file ? replacement : target, flags, mode);
    },
  };
  assert.throws(() => privatePaths.readBoundedRegularFile(file, {
    fs: fsImpl,
    maxBytes: 1024,
    label: 'policy public-key file',
  }), /changed while opening/);
});
