'use strict';
/** Safe GitHub updater workflow. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const updater = require('../server/updater');

function git(cwd, args) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function initRepo(cwd) {
  fs.mkdirSync(cwd, { recursive: true });
  try {
    git(cwd, ['init', '-b', 'main']);
  } catch {
    git(cwd, ['init']);
    git(cwd, ['checkout', '-b', 'main']);
  }
  git(cwd, ['config', 'user.email', 'test@example.test']);
  git(cwd, ['config', 'user.name', 'PromptWall Test']);
}

function commitFile(cwd, file, content, message) {
  fs.writeFileSync(path.join(cwd, file), content);
  git(cwd, ['add', file]);
  git(cwd, ['commit', '-m', message]);
}

function makeRemoteFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-updater-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const source = path.join(root, 'source');
  const remote = path.join(root, 'remote.git');
  const app = path.join(root, 'app');

  initRepo(source);
  commitFile(source, 'version.txt', 'one\n', 'initial');
  git(root, ['init', '--bare', remote]);
  git(source, ['remote', 'add', 'origin', remote]);
  git(source, ['push', '-u', 'origin', 'main']);
  git(root, ['clone', remote, app]);
  git(app, ['checkout', 'main']);

  process.env.PROMPTWALL_UPDATE_STATE_PATH = path.join(root, 'update-state.json');
  process.env.PROMPTWALL_UPDATE_CONFIG_PATH = path.join(root, 'update-settings.json');
  process.env.PROMPTWALL_UPDATE_DATA_ROOT = root;

  return { root, source, remote, app };
}

function testConfig() {
  return {
    remoteName: 'origin',
    branch: 'main',
    installMode: 'skip',
    restartCommand: '',
    restartAfterUpdate: false,
  };
}

function fakeBackup() {
  return {
    ok: true,
    file: 'sentinel-backup.db',
    manifestFile: 'sentinel-backup.db.manifest.json',
    bytes: 12,
    backupSha256: 'abc123',
    auditIntegrity: { ok: true, count: 0 },
  };
}

test('updater fast-forwards a clean checkout after backup', async (t) => {
  const fixture = makeRemoteFixture(t);
  const config = testConfig();
  commitFile(fixture.source, 'version.txt', 'two\n', 'update');
  git(fixture.source, ['push']);

  const check = await updater.checkForUpdates({
    repoRoot: fixture.app,
    config,
    allowLocalRemote: true,
  });
  assert.strictEqual(check.updateAvailable, true);
  assert.strictEqual(check.behind, 1);

  const result = await updater.applyUpdate({
    repoRoot: fixture.app,
    config,
    allowLocalRemote: true,
    confirmBackup: true,
    createBackup: async () => fakeBackup(),
  });

  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.updated, true);
  assert.strictEqual(fs.readFileSync(path.join(fixture.app, 'version.txt'), 'utf8').replace(/\r\n/g, '\n'), 'two\n');
  assert.match(git(fixture.app, ['status', '--porcelain']), /^$/);
});

test('updater refuses to update a dirty source tree', async (t) => {
  const fixture = makeRemoteFixture(t);
  const config = testConfig();
  commitFile(fixture.source, 'version.txt', 'two\n', 'update');
  git(fixture.source, ['push']);
  fs.writeFileSync(path.join(fixture.app, 'local-change.txt'), 'operator edit\n');

  await assert.rejects(
    updater.applyUpdate({
      repoRoot: fixture.app,
      config,
      allowLocalRemote: true,
      confirmBackup: true,
      createBackup: async () => fakeBackup(),
    }),
    /source tree has local changes/,
  );

  assert.strictEqual(fs.readFileSync(path.join(fixture.app, 'version.txt'), 'utf8').replace(/\r\n/g, '\n'), 'one\n');
});

test('updater refuses to check out updates from a different configured branch', async (t) => {
  const fixture = makeRemoteFixture(t);
  const config = testConfig();
  git(fixture.app, ['checkout', '-b', 'staging']);

  await assert.rejects(
    updater.checkForUpdates({
      repoRoot: fixture.app,
      config,
      allowLocalRemote: true,
    }),
    /checked-out branch staging does not match configured update branch main/,
  );
});

test('updater recognizes only GitHub remotes for production API use', () => {
  assert.strictEqual(updater._internal.githubRemoteInfo('https://github.com/skellywix/promptwall.git').ok, true);
  assert.strictEqual(updater._internal.githubRemoteInfo('git@github.com:skellywix/promptwall.git').ok, true);
  assert.strictEqual(updater._internal.githubRemoteInfo('https://example.com/skellywix/promptwall.git').ok, false);
  assert.strictEqual(updater._internal.githubRemoteInfo('C:/repos/promptwall.git').ok, false);
});

test('updater redacts credentialed URLs from public command errors', () => {
  const text = updater._internal.redactCommandText(
    "fatal: Authentication failed for 'https://ghp_secret-token@github.com/acme/promptwall.git/'",
  );
  assert.match(text, /https:\/\/redacted@github\.com\/acme\/promptwall\.git/);
  assert.doesNotMatch(text, /ghp_secret-token/);
});

test('backend restart execution requires a host opt-in', () => {
  const previous = process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
  delete process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
  try {
    assert.throws(
      () => updater.scheduleRestart({ restartCommand: 'node -v' }, { restartDelayMs: 1 }),
      /backend restart command execution is disabled/,
    );
  } finally {
    if (previous === undefined) delete process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
    else process.env.PROMPTWALL_UPDATE_RESTART_ENABLED = previous;
  }
});
