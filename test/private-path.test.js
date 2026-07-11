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
const TEST_OWNER_IDENTITY = Object.freeze({
  processSid: 'S-1-5-21-100-200-300-1001',
  ownerSid: 'S-1-5-21-100-200-300-1001',
});

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
    ownerIdentity: TEST_OWNER_IDENTITY,
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

test('trusted-parent file protection converts inherited ACEs and verifies the exact contract', (t) => {
  const file = tempFile(t, 'private-inherited-acl');
  const calls = [];
  assert.strictEqual(privatePaths.protectInheritedPrivateFile(file, {
    platform: 'win32',
    principal: 'TEST\\policy-user',
    ownerIdentity: TEST_OWNER_IDENTITY,
    label: 'inherited policy material',
    spawn(command, args) {
      calls.push({ command, args });
      return args.length === 1
        ? { status: 0, stdout: exactAcl(file) }
        : { status: 0, stdout: 'processed 1 file' };
    },
  }), file);
  assert.deepStrictEqual(calls, [
    { command: 'icacls.exe', args: [file, '/setowner', 'TEST\\policy-user', '/q'] },
    { command: 'icacls.exe', args: [file, '/inheritance:d', '/q'] },
    { command: 'icacls.exe', args: [file] },
  ]);
});

test('trusted-parent file protection rejects copied inherited ACEs that are not private', (t) => {
  const file = tempFile(t, 'private-inherited-broad');
  const broad = exactAcl(file).replace(
    'Successfully processed 1 files',
    '          BUILTIN\\Users:(RX)\r\nSuccessfully processed 1 files',
  );
  assert.throws(() => privatePaths.protectInheritedPrivateFile(file, {
    platform: 'win32',
    principal: 'TEST\\policy-user',
    ownerIdentity: TEST_OWNER_IDENTITY,
    label: 'inherited policy material',
    spawn(_command, args) {
      return args.length === 1
        ? { status: 0, stdout: broad }
        : { status: 0, stdout: 'processed 1 file' };
    },
  }), /ACL verification failed/);
});

test('real Windows trusted-parent publication produces a protected private file', {
  skip: process.platform !== 'win32' && 'Windows ACL inheritance is Windows-specific',
}, (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-private-inheritance-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  privatePaths.withPrivateDirectoryMutationLockSync(directory, () => {
    const file = path.join(directory, 'material');
    fs.writeFileSync(file, 'private material', { flag: 'wx', mode: 0o600 });
    privatePaths.protectInheritedPrivateFile(file, { label: 'inherited private material' });
    assert.doesNotThrow(() => privatePaths.assertPrivatePath(file, {
      label: 'inherited private material',
    }));
  }, {
    directory: true,
    label: 'private inheritance directory',
    ownerLabel: 'private inheritance directory',
  });
});

test('durable publication restores exact prior bytes when final verification fails', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-private-publish-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, 'state.json');
  const staged = path.join(directory, '.state.json.staged');
  fs.writeFileSync(target, 'exact prior bytes');
  fs.writeFileSync(staged, 'untrusted replacement');
  assert.throws(() => privatePaths.publishFileDurably(staged, target, {
    verifyPublished(file) {
      assert.strictEqual(fs.readFileSync(file, 'utf8'), 'untrusted replacement');
      throw new Error('synthetic final verification failure');
    },
  }), /synthetic final verification failure/);
  assert.strictEqual(fs.readFileSync(target, 'utf8'), 'exact prior bytes');
  assert.strictEqual(fs.existsSync(staged), false);
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
    ownerIdentity: TEST_OWNER_IDENTITY,
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
  }), /ACL verification failed/);
});

test('shared Windows ACL verification rejects descriptor drift during inspection', (t) => {
  const file = tempFile(t, 'private-acl-drift');
  let stats = 0;
  const fsImpl = {
    ...fs,
    lstatSync(target) {
      const stat = fs.lstatSync(target);
      stats += 1;
      if (stats === 1) return stat;
      const changed = Object.create(stat);
      Object.defineProperty(changed, 'ctimeMs', { value: stat.ctimeMs + stats });
      return changed;
    },
  };
  assert.throws(() => privatePaths.assertPrivatePath(file, {
    fs: fsImpl,
    platform: 'win32',
    directory: false,
    principal: 'TEST\\policy-user',
    ownerIdentity: TEST_OWNER_IDENTITY,
    label: 'policy material',
    spawn() { return { status: 0, stdout: exactAcl(file) }; },
  }), /changed during Windows security verification/);
});

test('shared Windows directory verification tolerates entry churn only after equal security snapshots', (t) => {
  const directory = path.dirname(tempFile(t, 'private-directory-churn'));
  let stats = 0;
  const fsImpl = {
    ...fs,
    lstatSync(target) {
      const stat = fs.lstatSync(target);
      stats += 1;
      const changed = Object.create(stat);
      Object.defineProperty(changed, 'ctimeMs', { value: stat.ctimeMs + stats });
      return changed;
    },
  };
  assert.strictEqual(privatePaths.assertPrivatePath(directory, {
    fs: fsImpl,
    platform: 'win32',
    directory: true,
    principal: 'TEST\\policy-user',
    ownerIdentity: TEST_OWNER_IDENTITY,
    label: 'policy directory',
    spawn() { return { status: 0, stdout: exactAcl(directory) }; },
  }), directory);
  assert.ok(stats >= 3, 'security was sampled twice before entry churn was accepted');
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
    ownerIdentity: TEST_OWNER_IDENTITY,
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
      ownerIdentity: TEST_OWNER_IDENTITY,
      privateLockRoot: path.join(root, 'locks'),
      spawn(command, args) {
        if (args[0] === dir && args.includes('/setowner')) {
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
