'use strict';
/** Windows endpoint-agent install scripts should be pilot-safe. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const install = fs.readFileSync(path.join(root, 'scripts', 'install-endpoint-agent.ps1'), 'utf8');
const run = fs.readFileSync(path.join(root, 'scripts', 'run-endpoint-agent.ps1'), 'utf8');
const uninstall = fs.readFileSync(path.join(root, 'scripts', 'uninstall-endpoint-agent.ps1'), 'utf8');
const deployment = fs.readFileSync(path.join(root, 'docs', 'DEPLOYMENT.md'), 'utf8');

test('installer registers a restarting scheduled task without putting the ingest key in task args', () => {
  assert.match(install, /Register-ScheduledTask/);
  assert.match(install, /New-ScheduledTaskTrigger -AtLogOn/);
  assert.match(install, /New-ScheduledTaskSettingsSet -RestartCount 3/);
  assert.match(install, /New-ScheduledTaskPrincipal[\s\S]+-LogonType Interactive[\s\S]+-RunLevel LeastPrivilege/);
  assert.match(install, /Register-ScheduledTask[\s\S]+-Principal \$principal/);
  assert.match(install, /INGEST_API_KEY=\$IngestKey/);
  assert.match(install, /\$env:LOCALAPPDATA\\PromptWall/);
  assert.match(install, /BUILTIN\\Administrators/);
  assert.match(install, /ENDPOINT_AGENT_HANDOFF_SECRET=\$HandoffSecret/);
  assert.doesNotMatch(install, /"-IngestKey"/);
  assert.doesNotMatch(install, /\$IngestKey[\s\S]{0,120}\$taskArgs/);
  assert.doesNotMatch(install, /"-HandoffSecret"/);
  assert.doesNotMatch(install, /\$HandoffSecret[\s\S]{0,120}\$taskArgs/);
});

test('runner loads endpoint config through SENTINEL_ENV_PATH and starts the agent', () => {
  assert.match(run, /\$env:SENTINEL_ENV_PATH = \$config/);
  assert.match(run, /sensors\\endpoint-agent\\agent\.js/);
  assert.match(run, /\*>> \$LogPath/);
});

test('uninstaller removes task and can remove endpoint config', () => {
  assert.match(uninstall, /Unregister-ScheduledTask/);
  assert.match(uninstall, /\$RemoveConfig/);
  assert.match(uninstall, /endpoint-agent\.env/);
});

test('deployment docs include endpoint task install and uninstall flow', () => {
  assert.match(deployment, /install-endpoint-agent\.ps1/);
  assert.match(deployment, /uninstall-endpoint-agent\.ps1/);
  assert.match(deployment, /PromptWallEndpointAgent/);
  assert.match(deployment, /%LOCALAPPDATA%\\PromptWall\\endpoint-agent\.env/);
  assert.match(deployment, /ENDPOINT_AGENT_HANDOFF_SECRET/);
});
