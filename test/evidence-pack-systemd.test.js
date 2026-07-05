'use strict';
/** Linux evidence-pack scheduler should be deployable without secret-bearing units. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const install = fs.readFileSync(path.join(root, 'scripts', 'install-evidence-pack-systemd.sh'), 'utf8');
const run = fs.readFileSync(path.join(root, 'scripts', 'run-evidence-pack.sh'), 'utf8');
const taskDoc = fs.readFileSync(path.join(root, 'docs', 'EVIDENCE_PACK_TASK.md'), 'utf8');
const deployment = fs.readFileSync(path.join(root, 'docs', 'DEPLOYMENT.md'), 'utf8');
const technician = fs.readFileSync(path.join(root, 'docs', 'TECHNICIAN_DEPLOYMENT_GUIDE.md'), 'utf8');
const aws = fs.readFileSync(path.join(root, 'docs', 'AWS_SAAS_DEPLOYMENT.md'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

test('package exposes Linux systemd evidence-pack install and run commands', () => {
  assert.strictEqual(pkg.scripts['evidence:pack:run-linux'], 'bash scripts/run-evidence-pack.sh');
  assert.strictEqual(pkg.scripts['evidence:pack:install-systemd'], 'bash scripts/install-evidence-pack-systemd.sh');
});

test('systemd installer creates a persistent timer and secret-free env file', () => {
  assert.match(install, /OnCalendar=\$ON_CALENDAR/);
  assert.match(install, /Persistent=true/);
  assert.match(install, /RandomizedDelaySec=\$RANDOMIZED_DELAY/);
  assert.match(install, /EnvironmentFile=\$ENV_FILE/);
  assert.match(install, /ExecStart=\$INSTALL_BIN/);
  assert.match(install, /after_units="network-online\.target docker\.service"/);
  assert.match(install, /After=\$after_units/);
  assert.match(install, /systemctl enable --now "\$SERVICE_NAME\.timer"/);
  assert.match(install, /REDACTWALL_EVIDENCE_MODE=/);
  assert.match(install, /REDACTWALL_EVIDENCE_CONFIG=/);
  assert.match(install, /REDACTWALL_EVIDENCE_CONTAINER=/);
  assert.match(install, /\/data\/evidence-schedule\.json/);
  assert.match(install, /config\/evidence-schedule\.json/);
  assert.doesNotMatch(install, /REDACTWALL_SECRET/);
  assert.doesNotMatch(install, /REDACTWALL_DATA_KEY/);
  assert.doesNotMatch(install, /INGEST_API_KEY/);
  assert.doesNotMatch(install, /SMTP_PASS/);
});

test('Linux runner supports npm and Docker modes without logging prompt content', () => {
  assert.match(run, /MODE="\$\{REDACTWALL_EVIDENCE_MODE:-npm\}"/);
  assert.match(run, /npm run evidence:pack:scheduled -- "\$resolved_config"/);
  assert.match(run, /docker exec "\$CONTAINER_NAME" npm run evidence:pack:scheduled -- "\$CONFIG_PATH"/);
  assert.match(run, /Evidence schedule config not found/);
  assert.match(run, /Scheduled evidence pack completed/);
  assert.doesNotMatch(run, /rawPrompt|redactedPrompt|prompt body/i);
});

test('docs cover Windows and Linux scheduled evidence pack operations', () => {
  for (const doc of [taskDoc, deployment, technician]) {
    assert.match(doc, /evidence:pack:install-systemd/);
    assert.match(doc, /evidence-pack\.log/);
    assert.match(doc, /raw prompt bodies/);
  }
  assert.match(aws, /redactwall-evidence-pack\.timer/);
  assert.match(aws, /evidence-pack\.log/);
  assert.match(aws, /raw prompt bodies/);
  assert.match(taskDoc, /Task Scheduler/);
  assert.match(taskDoc, /systemd/);
  assert.match(taskDoc, /\/data\/evidence-schedule\.json/);
});
