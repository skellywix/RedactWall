'use strict';
/** Scheduled examiner evidence-pack task must be deployable and secret-free. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const install = fs.readFileSync(path.join(root, 'scripts', 'install-evidence-pack-task.ps1'), 'utf8');
const run = fs.readFileSync(path.join(root, 'scripts', 'run-evidence-pack.ps1'), 'utf8');
const deployment = fs.readFileSync(path.join(root, 'docs', 'DEPLOYMENT.md'), 'utf8');
const technician = fs.readFileSync(path.join(root, 'docs', 'TECHNICIAN_DEPLOYMENT_GUIDE.md'), 'utf8');
const taskDoc = fs.readFileSync(path.join(root, 'docs', 'EVIDENCE_PACK_TASK.md'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

test('package exposes a Windows scheduled-task installer for examiner packs', () => {
  assert.strictEqual(
    pkg.scripts['evidence:pack:install-task'],
    'powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/install-evidence-pack-task.ps1',
  );
});

test('installer registers a limited scheduled task around the evidence-pack runner', () => {
  assert.match(install, /Register-ScheduledTask/);
  assert.match(install, /New-ScheduledTaskAction/);
  assert.match(install, /run-evidence-pack\.ps1/);
  assert.match(install, /RedactWall Examiner Evidence Pack/);
  assert.match(install, /New-ScheduledTaskTrigger -Weekly -WeeksInterval 13/);
  assert.match(install, /New-ScheduledTaskPrincipal[\s\S]+-LogonType Interactive[\s\S]+-RunLevel Limited/);
  assert.match(install, /Register-ScheduledTask[\s\S]+-Principal \$principal/);
  assert.match(install, /config\\evidence-schedule\.json/);
  assert.match(install, /Evidence schedule config not found/);
  assert.match(install, /RedactWall\\logs\\evidence-pack\.log/);
});

test('runner invokes scheduled evidence export from the repo without passing secrets', () => {
  assert.match(run, /npm\.cmd/);
  assert.match(run, /IsPathRooted\(\$ConfigPath\)/);
  assert.match(run, /Evidence schedule config not found/);
  assert.match(run, /run evidence:pack:scheduled -- \$resolvedConfig/);
  assert.match(run, /Push-Location \$repoRoot/);
  assert.match(run, /\*>> \$LogPath/);
  assert.match(run, /exit \$exitCode/);
  const combined = `${install}\n${run}`;
  assert.doesNotMatch(combined, /REDACTWALL_SECRET/);
  assert.doesNotMatch(combined, /REDACTWALL_DATA_KEY/);
  assert.doesNotMatch(combined, /INGEST_API_KEY/);
  assert.doesNotMatch(combined, /SMTP_PASS/);
});

test('deployment docs include install, log, and secret-free evidence guidance', () => {
  for (const doc of [deployment, technician, taskDoc]) {
    assert.match(doc, /evidence:pack:install-task/);
    assert.match(doc, /config[\\/]evidence-schedule\.json/);
    assert.match(doc, /evidence-pack\.log/);
    assert.match(doc, /raw prompt bodies/);
  }
});
