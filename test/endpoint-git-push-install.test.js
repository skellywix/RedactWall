'use strict';
/** Git push guard installer writes a managed hook without embedding secrets. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');

const root = path.join(__dirname, '..');

// Committing runs this suite from inside a git hook, where git exports
// repo-pinning variables (GIT_DIR, GIT_INDEX_FILE, ...). Without scrubbing
// them, the pilot repository's git operations act on the parent repo.
const localGitEnvironmentVariables = Object.freeze([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_COUNT', 'GIT_OBJECT_DIRECTORY', 'GIT_DIR', 'GIT_WORK_TREE',
  'GIT_IMPLICIT_WORK_TREE', 'GIT_GRAFT_FILE', 'GIT_INDEX_FILE',
  'GIT_NO_REPLACE_OBJECTS', 'GIT_REPLACE_REF_BASE', 'GIT_PREFIX',
  'GIT_INTERNAL_SUPER_PREFIX', 'GIT_SHALLOW_FILE', 'GIT_COMMON_DIR',
]);

function isolatedGitEnvironment(environment = process.env) {
  const env = { ...environment };
  for (const variable of localGitEnvironmentVariables) delete env[variable];
  return env;
}

function tempDir(t, prefix = 'ps-git-push-install-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function hasCommand(command, args = ['--version']) {
  try {
    execFileSync(command, args, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function hasPowerShell() {
  try {
    execFileSync('powershell.exe', ['-NoProfile', '-Command', '$PSVersionTable.PSVersion | Out-Null'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function runPowerShell(args, opts = {}) {
  const result = spawnSync('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', ...args], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    env: isolatedGitEnvironment(),
    ...opts,
  });
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || `powershell exited ${result.status}`).trim());
  }
  return result;
}

test('install and uninstall git push guard hook in a pilot repository', (t) => {
  if (process.platform !== 'win32') t.skip('PowerShell hook installer smoke is Windows-only');
  if (!hasCommand('git')) t.skip('git is not available');
  if (!hasPowerShell()) t.skip('powershell.exe is not available');

  const dir = tempDir(t);
  const repo = path.join(dir, 'repo');
  const configPath = path.join(dir, 'endpoint-agent.env');
  fs.mkdirSync(repo, { recursive: true });
  fs.writeFileSync(configPath, 'INGEST_API_KEY=unit-key\n');
  execFileSync('git', ['init'], { cwd: repo, stdio: 'ignore', env: isolatedGitEnvironment() });

  runPowerShell([
    '-File', path.join(root, 'scripts', 'install-git-push-guard.ps1'),
    '-RepoPath', repo,
    '-InstallRoot', root,
    '-ConfigPath', configPath,
    '-AllowedHost', 'github.com',
  ]);

  const hookPath = path.join(repo, '.git', 'hooks', 'pre-push');
  const hook = fs.readFileSync(hookPath, 'utf8');
  assert.strictEqual(hook.charCodeAt(0), '#'.charCodeAt(0));
  assert.match(hook, /RedactWall Git Push Guard/);
  assert.match(hook, /git-push-guard\.js/);
  assert.match(hook, /REDACTWALL_ENV_PATH/);
  assert.match(hook, /--pre-push/);
  assert.match(hook, /--allowed-host 'github\.com'/);
  assert.match(hook, /--remote-url "\$2" \\\r?\n\s+--allowed-host 'github\.com'/);
  assert.ok(!hook.includes('INGEST_API_KEY'));
  assert.ok(!hook.includes('ENDPOINT_AGENT_HANDOFF_SECRET'));
  assert.ok(!hook.includes('unit-key'));
  assert.ok(!hook.includes('contentBase64'));

  runPowerShell([
    '-File', path.join(root, 'scripts', 'uninstall-git-push-guard.ps1'),
    '-RepoPath', repo,
  ]);
  assert.strictEqual(fs.existsSync(hookPath), false);
});

test('installer refuses to overwrite unmanaged pre-push hook without force', (t) => {
  if (process.platform !== 'win32') t.skip('PowerShell hook installer smoke is Windows-only');
  if (!hasCommand('git')) t.skip('git is not available');
  if (!hasPowerShell()) t.skip('powershell.exe is not available');

  const dir = tempDir(t);
  const repo = path.join(dir, 'repo');
  fs.mkdirSync(repo, { recursive: true });
  execFileSync('git', ['init'], { cwd: repo, stdio: 'ignore', env: isolatedGitEnvironment() });
  const hookPath = path.join(repo, '.git', 'hooks', 'pre-push');
  fs.writeFileSync(hookPath, '#!/bin/sh\necho existing\n');

  const result = spawnSync('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', path.join(root, 'scripts', 'install-git-push-guard.ps1'),
    '-RepoPath', repo,
    '-InstallRoot', root,
  ], { cwd: root, encoding: 'utf8', windowsHide: true, env: isolatedGitEnvironment() });

  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr + result.stdout, /pre-push hook already exists/);
  assert.strictEqual(fs.readFileSync(hookPath, 'utf8'), '#!/bin/sh\necho existing\n');
});
