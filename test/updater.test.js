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

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return predicate();
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

test('updater marks restart scheduled after a fast-forward when host opt-in is enabled', async (t) => {
  const fixture = makeRemoteFixture(t);
  const previousEnabled = process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
  const previousCommand = process.env.PROMPTWALL_UPDATE_RESTART_COMMAND;
  try {
    process.env.PROMPTWALL_UPDATE_RESTART_ENABLED = 'true';
    process.env.PROMPTWALL_UPDATE_RESTART_COMMAND = 'node -v';
    commitFile(fixture.source, 'version.txt', 'two\n', 'update');
    git(fixture.source, ['push']);

    const result = await updater.applyUpdate({
      repoRoot: fixture.app,
      config: {
        ...testConfig(),
        restartAfterUpdate: true,
      },
      allowLocalRemote: true,
      confirmBackup: true,
      createBackup: async () => fakeBackup(),
      restartDelayMs: 60 * 60 * 1000,
    });

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.updated, true);
    assert.strictEqual(result.restartScheduled, true);
    assert.strictEqual(result.state.autoRestartRequested, true);
  } finally {
    if (previousEnabled === undefined) delete process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
    else process.env.PROMPTWALL_UPDATE_RESTART_ENABLED = previousEnabled;
    if (previousCommand === undefined) delete process.env.PROMPTWALL_UPDATE_RESTART_COMMAND;
    else process.env.PROMPTWALL_UPDATE_RESTART_COMMAND = previousCommand;
  }
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

test('updater reports already-current checkouts without taking a backup', async (t) => {
  const fixture = makeRemoteFixture(t);
  let backups = 0;

  const result = await updater.applyUpdate({
    repoRoot: fixture.app,
    config: testConfig(),
    allowLocalRemote: true,
    confirmBackup: true,
    createBackup: async () => {
      backups += 1;
      return fakeBackup();
    },
  });

  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.updated, false);
  assert.strictEqual(result.state.status, 'up-to-date');
  assert.strictEqual(result.state.restartRequired, false);
  assert.strictEqual(backups, 0);
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

test('updater refuses production checks from non-GitHub remotes', async (t) => {
  const fixture = makeRemoteFixture(t);

  await assert.rejects(
    updater.checkForUpdates({
      repoRoot: fixture.app,
      config: testConfig(),
    }),
    /updates require an existing GitHub remote/
  );
});

test('updater recognizes only GitHub remotes for production API use', () => {
  assert.strictEqual(updater._internal.githubRemoteInfo('https://github.com/skellywix/promptwall.git').ok, true);
  assert.strictEqual(updater._internal.githubRemoteInfo('git@github.com:skellywix/promptwall.git').ok, true);
  assert.strictEqual(updater._internal.githubRemoteInfo('https://example.com/skellywix/promptwall.git').ok, false);
  assert.strictEqual(updater._internal.githubRemoteInfo('C:/repos/promptwall.git').ok, false);
});

test('updater install and backup helpers keep commands explicit and injectable', async () => {
  assert.match(updater._internal.npmExecutable(), /^npm(\.cmd)?$/);

  const installCalls = [];
  const install = await updater._internal.runInstall({ installMode: 'npm-ci' }, {
    repoRoot: path.join(os.tmpdir(), 'promptwall-install-root'),
    npmExecutable: 'npm-test',
    runCommand: async (file, args, opts) => {
      installCalls.push({ file, args, opts });
    },
  });
  assert.deepStrictEqual(install, { skipped: false, command: 'npm-test ci' });
  assert.strictEqual(installCalls[0].file, 'npm-test');
  assert.deepStrictEqual(installCalls[0].args, ['ci']);
  assert.strictEqual(installCalls[0].opts.publicError, 'dependency install failed');

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-updater-backup-'));
  try {
    let captured = null;
    const backup = await updater._internal.createBackup(testConfig(), {
      dataRoot: root,
      dbModule: {
        _dbPath: path.join(root, 'sentinel.db'),
        verifyAuditChain: () => ({ ok: true, count: 0 }),
      },
      backupStore: {
        createBackup: async (opts) => {
          captured = opts;
          return { ok: true, file: 'backup.db' };
        },
      },
    });
    assert.deepStrictEqual(backup, { ok: true, file: 'backup.db' });
    assert.strictEqual(captured.outDir, path.join(root, 'backups', 'updates'));
    assert.strictEqual(captured.dbModule._dbPath, path.join(root, 'sentinel.db'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('updater rejects unsafe config values before writing settings', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-updater-config-'));
  const opts = { dataRoot: root };
  try {
    assert.throws(
      () => updater.saveConfig({ ...testConfig(), remoteName: '-origin' }, opts),
      /invalid remote name/
    );
    assert.throws(
      () => updater.saveConfig({ ...testConfig(), branch: 'main/../prod' }, opts),
      /invalid branch name/
    );
    assert.throws(
      () => updater.saveConfig({ ...testConfig(), restartCommand: 'powershell.exe; Remove-Item data' }, opts),
      /restart command contains unsupported characters/
    );
    assert.strictEqual(fs.existsSync(path.join(root, 'update-settings.json')), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('updater falls back safely when saved settings JSON is corrupt', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-updater-corrupt-config-'));
  const previousConfigPath = process.env.PROMPTWALL_UPDATE_CONFIG_PATH;
  try {
    process.env.PROMPTWALL_UPDATE_CONFIG_PATH = path.join(root, 'update-settings.json');
    fs.writeFileSync(process.env.PROMPTWALL_UPDATE_CONFIG_PATH, '{not-json');

    const config = updater.loadConfig({ dataRoot: root });

    assert.strictEqual(config.remoteName, 'origin');
    assert.strictEqual(config.branch, 'main');
    assert.strictEqual(config.installMode, 'npm-ci-omit-dev');
  } finally {
    if (previousConfigPath === undefined) delete process.env.PROMPTWALL_UPDATE_CONFIG_PATH;
    else process.env.PROMPTWALL_UPDATE_CONFIG_PATH = previousConfigPath;
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('updater redacts credentialed URLs from public command errors', () => {
  const text = updater._internal.redactCommandText(
    "fatal: Authentication failed for 'https://ghp_secret-token@github.com/acme/promptwall.git/'",
  );
  assert.match(text, /https:\/\/redacted@github\.com\/acme\/promptwall\.git/);
  assert.doesNotMatch(text, /ghp_secret-token/);
  assert.strictEqual(
    updater._internal.redactRemoteUrl('not a url //oauth-token@example.test/private/repo.git'),
    'not a url //redacted@example.test/private/repo.git'
  );
});

test('updater command failures are public, bounded, and credential-redacted', async () => {
  await assert.rejects(
    updater._internal.runCommand(process.execPath, ['-e', `
      console.error('https://ghp_secret-token@github.com/acme/promptwall.git');
      console.error('x'.repeat(7000));
      process.exit(3);
    `], {
      publicError: 'controlled failure',
    }),
    (err) => {
      assert.strictEqual(err.publicMessage, 'controlled failure');
      assert.strictEqual(err.result.code, 3);
      assert.ok(err.result.stderr.length <= 6005);
      assert.ok(!updater.publicError(err).includes('ghp_secret-token'));
      return true;
    }
  );

  await assert.rejects(
    updater._internal.runCommand(process.execPath, ['-e', 'process.exit(2)']),
    (err) => {
      assert.match(err.publicMessage, /node(\.exe)? failed/i);
      return true;
    }
  );
});

test('updater status returns sanitized repo errors instead of throwing', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-updater-status-'));
  try {
    const report = await updater.status({
      repoRoot: root,
      dataRoot: root,
      dbModule: {
        _dbPath: path.join(root, 'sentinel.db'),
        verifyAuditChain: () => ({ ok: true, count: 0 }),
      },
    });

    assert.strictEqual(report.ok, false);
    assert.strictEqual(report.repo, null);
    assert.match(report.error, /git rev-parse failed|not a git repository/i);
    assert.strictEqual(report.safety.sourceTreeClean, false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('updater status reports existing non-GitHub remotes as a production safety error', async (t) => {
  const fixture = makeRemoteFixture(t);
  const report = await updater.status({
    repoRoot: fixture.app,
    dataRoot: fixture.root,
    dbModule: {
      _dbPath: path.join(fixture.root, 'sentinel.db'),
      verifyAuditChain: () => ({ ok: true, count: 0 }),
    },
  });

  assert.strictEqual(report.ok, false);
  assert.notStrictEqual(report.repo, null);
  assert.strictEqual(report.repo.remoteIsGithub, false);
  assert.match(report.error, /updates require an existing GitHub remote/);
});

test('updater schedules an opt-in restart and records the command result', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-updater-restart-'));
  const previousEnabled = process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
  const previousCommand = process.env.PROMPTWALL_UPDATE_RESTART_COMMAND;
  const previousState = process.env.PROMPTWALL_UPDATE_STATE_PATH;
  try {
    process.env.PROMPTWALL_UPDATE_RESTART_ENABLED = 'true';
    process.env.PROMPTWALL_UPDATE_RESTART_COMMAND = 'node -v';
    process.env.PROMPTWALL_UPDATE_STATE_PATH = path.join(root, 'update-state.json');

    const scheduled = updater.scheduleRestart({ restartCommand: 'ignored-command' }, {
      dataRoot: root,
      restartDelayMs: 1,
      repoRoot: root,
    });
    assert.strictEqual(scheduled.scheduled, true);
    assert.strictEqual(scheduled.state.status, 'restart-scheduled');

    const state = await waitFor(() => {
      try {
        const current = JSON.parse(fs.readFileSync(process.env.PROMPTWALL_UPDATE_STATE_PATH, 'utf8'));
        return current.status === 'restart-command-ran' ? current : null;
      } catch {
        return null;
      }
    });

    assert.strictEqual(state.status, 'restart-command-ran');
    assert.strictEqual(state.restartRequired, false);
    assert.deepStrictEqual(updater._internal.parseRestartCommand('node -v'), { file: 'node', args: ['-v'] });
    assert.throws(() => updater._internal.parseRestartCommand(''), /restart command is not configured/);
  } finally {
    if (previousEnabled === undefined) delete process.env.PROMPTWALL_UPDATE_RESTART_ENABLED;
    else process.env.PROMPTWALL_UPDATE_RESTART_ENABLED = previousEnabled;
    if (previousCommand === undefined) delete process.env.PROMPTWALL_UPDATE_RESTART_COMMAND;
    else process.env.PROMPTWALL_UPDATE_RESTART_COMMAND = previousCommand;
    if (previousState === undefined) delete process.env.PROMPTWALL_UPDATE_STATE_PATH;
    else process.env.PROMPTWALL_UPDATE_STATE_PATH = previousState;
    fs.rmSync(root, { recursive: true, force: true });
  }
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
