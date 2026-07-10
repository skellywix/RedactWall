'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { openAuditAnchor } = require('../../server/audit-anchor');

const directory = path.resolve(process.env.AUDIT_DIRECTORY);
const privateLockRoot = path.resolve(process.env.PRIVATE_LOCK_ROOT);
const coordination = path.resolve(process.env.COORDINATION_DIRECTORY);
const workerId = String(process.env.WORKER_ID || process.pid);
const principal = 'TEST\\audit-owner';
const sleepBuffer = new Int32Array(new SharedArrayBuffer(4));

function sleep(milliseconds) {
  Atomics.wait(sleepBuffer, 0, 0, milliseconds);
}

function markerFor(prefix, target) {
  const digest = crypto.createHash('sha256').update(path.resolve(target).toLowerCase()).digest('hex');
  return path.join(coordination, `${prefix}-${digest}`);
}

function exactAcl(target) {
  let inheritance = '';
  try { inheritance = fs.lstatSync(target).isDirectory() ? '(OI)(CI)' : ''; } catch {}
  return [
    `${target} ${principal}:${inheritance}(F)`,
    `          NT AUTHORITY\\SYSTEM:${inheritance}(F)`,
    'Successfully processed 1 files',
  ].join('\r\n');
}

function broadAcl(target) {
  return exactAcl(target).replace(
    'Successfully processed 1 files',
    '          BUILTIN\\Users:(RX)\r\nSuccessfully processed 1 files',
  );
}

function simulatedIcacls(command, args) {
  if (command !== 'icacls.exe') return { status: 1, stderr: 'unexpected command' };
  const target = path.resolve(args[0]);
  if (args.length === 1) {
    return {
      status: 0,
      stdout: fs.existsSync(markerFor('secured', target)) ? exactAcl(target) : broadAcl(target),
    };
  }
  if (args.includes('/reset') && target === directory) {
    const active = path.join(coordination, `active-${workerId}`);
    fs.writeFileSync(active, String(process.pid), { flag: 'wx' });
    try {
      sleep(300);
      const overlaps = fs.readdirSync(coordination).filter((name) => name.startsWith('active-')).length;
      if (overlaps > 1) return { status: 1, stderr: 'simulated overlapping audit ACL reset' };
    } finally {
      fs.rmSync(active, { force: true });
    }
  }
  if (args.includes('/grant:r')) fs.writeFileSync(markerFor('secured', target), 'secured');
  return { status: 0, stdout: 'Successfully processed 1 files' };
}

fs.writeFileSync(path.join(coordination, `ready-${workerId}`), String(process.pid), { flag: 'wx' });
const go = path.join(coordination, 'go');
const deadline = Date.now() + 15_000;
while (!fs.existsSync(go)) {
  if (Date.now() >= deadline) throw new Error('audit anchor worker start barrier timed out');
  sleep(10);
}

const anchor = openAuditAnchor({
  directory,
  allowBootstrap: true,
  env: {},
  privatePathSecurity: {
    platform: 'win32',
    principal,
    privateLockRoot,
    spawn: simulatedIcacls,
  },
});
const state = fs.readFileSync(anchor.paths.statePath);
process.stdout.write(crypto.createHash('sha256').update(state).digest('hex'));
