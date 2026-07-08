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
const clipboardInstall = fs.readFileSync(path.join(root, 'scripts', 'install-clipboard-guard.ps1'), 'utf8');
const clipboardRun = fs.readFileSync(path.join(root, 'scripts', 'run-clipboard-guard.ps1'), 'utf8');
const clipboardUninstall = fs.readFileSync(path.join(root, 'scripts', 'uninstall-clipboard-guard.ps1'), 'utf8');
const desktopInstall = fs.readFileSync(path.join(root, 'scripts', 'install-desktop-collector.ps1'), 'utf8');
const desktopRun = fs.readFileSync(path.join(root, 'scripts', 'run-desktop-collector.ps1'), 'utf8');
const desktopUninstall = fs.readFileSync(path.join(root, 'scripts', 'uninstall-desktop-collector.ps1'), 'utf8');
const deployment = fs.readFileSync(path.join(root, 'docs', 'deployment', 'DEPLOYMENT.md'), 'utf8');

test('installer registers a restarting scheduled task without putting the ingest key in task args', () => {
  assert.match(install, /Register-ScheduledTask/);
  assert.match(install, /New-ScheduledTaskTrigger -AtLogOn/);
  assert.match(install, /New-ScheduledTaskSettingsSet -RestartCount 3/);
  assert.match(install, /New-ScheduledTaskPrincipal[\s\S]+-LogonType Interactive[\s\S]+-RunLevel Limited/);
  assert.match(install, /Register-ScheduledTask[\s\S]+-Principal \$principal/);
  assert.match(install, /Install-EndpointStartupShortcut/);
  assert.match(install, /Start-EndpointFallbackProcess/);
  assert.match(install, /Scheduled task registration was denied/);
  assert.match(install, /INGEST_API_KEY=\$IngestKey/);
  assert.match(install, /\[Alias\("SentinelUrl"\)\]/);
  assert.match(install, /\[string\]\$RedactWallUrl = "http:\/\/localhost:4000"/);
  assert.match(install, /REDACTWALL_URL=\$RedactWallUrl/);
  assert.match(install, /\$env:LOCALAPPDATA\\RedactWall/);
  assert.match(install, /BUILTIN\\Administrators/);
  assert.match(install, /ENDPOINT_AGENT_HANDOFF_SECRET=\$HandoffSecret/);
  assert.match(install, /InstallDesktopCollector/);
  assert.match(install, /InstallClipboardGuard/);
  assert.match(install, /ClipboardGuardClearOnBlock/);
  assert.match(install, /ClipboardGuardShortcutName/);
  assert.match(install, /DesktopCollectorKeyName/);
  assert.match(install, /ENDPOINT_AGENT_DESKTOP_DESTINATION=\$DesktopCollectorDestination/);
  assert.match(install, /install-desktop-collector\.ps1/);
  assert.match(install, /install-clipboard-guard\.ps1/);
  assert.match(install, /InstallDesktopCollector requires HandoffSecret/);
  assert.match(install, /Set-Acl -LiteralPath \$handoffRoot/);
  assert.doesNotMatch(install, /"-IngestKey"/);
  assert.doesNotMatch(install, /\$IngestKey[\s\S]{0,120}\$taskArgs/);
  assert.doesNotMatch(install, /"-HandoffSecret"/);
  assert.doesNotMatch(install, /\$HandoffSecret[\s\S]{0,120}\$taskArgs/);
});

test('runner loads endpoint config through REDACTWALL_ENV_PATH and starts the agent', () => {
  assert.match(run, /\$env:REDACTWALL_ENV_PATH = \$config/);
  assert.match(run, /Remove-Item Env:\\PROMPTWALL_ENV_PATH/);
  assert.match(run, /Remove-Item Env:\\SENTINEL_ENV_PATH/);
  assert.doesNotMatch(run, /\$env:(?:PROMPTWALL|SENTINEL)_ENV_PATH = \$config/);
  assert.match(run, /sensors\\endpoint-agent\\agent\.js/);
  assert.match(run, /\*>> \$LogPath/);
});

test('desktop collector shell action is per-user and secret-free', () => {
  assert.match(desktopInstall, /HKEY_CURRENT_USER\\Software\\Classes\\\*\\shell/);
  assert.match(desktopInstall, /endpoint-agent\.env/);
  assert.match(desktopInstall, /ENDPOINT_AGENT_HANDOFF_DIR/);
  assert.match(desktopInstall, /REDACTWALL_ENDPOINT_AGENT_HANDOFF_DIR/);
  assert.match(desktopInstall, /ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.match(desktopInstall, /REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.match(desktopInstall, /MultiSelectModel/);
  assert.match(desktopInstall, /Player/);
  assert.ok(desktopInstall.includes('%1'));
  assert.match(desktopInstall, /run-desktop-collector\.ps1/);
  assert.doesNotMatch(desktopInstall, /"-HandoffSecret"/);
  assert.doesNotMatch(desktopInstall, /INGEST_API_KEY=\$IngestKey/);
  assert.match(desktopRun, /\$env:REDACTWALL_ENV_PATH = \$config/);
  assert.match(desktopRun, /Remove-Item Env:\\PROMPTWALL_ENV_PATH/);
  assert.match(desktopRun, /Remove-Item Env:\\SENTINEL_ENV_PATH/);
  assert.doesNotMatch(desktopRun, /\$env:(?:PROMPTWALL|SENTINEL)_ENV_PATH = \$config/);
  assert.match(desktopRun, /\[string\[\]\]\$FilePath/);
  assert.match(desktopRun, /foreach \(\$file in \$FilePath\)/);
  assert.match(desktopRun, /protected-upload\.js/);
  assert.match(desktopRun, /if \(\$Destination\)/);
  assert.match(desktopRun, /--wait/);
  assert.match(desktopRun, /--json/);
  assert.match(desktopRun, /\$collectorOutput = & \$node\.Source @collectorArgs 2>&1/);
  assert.match(desktopRun, /\$exitCode = \$LASTEXITCODE/);
  assert.match(desktopRun, /\$collectorOutput \| Out-File -Append/);
  assert.match(desktopRun, /exit \$exitCode/);
  assert.match(desktopUninstall, /HKEY_CURRENT_USER\\Software\\Classes\\\*\\shell/);
});

test('clipboard guard shortcut is per-user and secret-free', () => {
  assert.match(clipboardInstall, /WScript\.Shell/);
  assert.match(clipboardInstall, /GetFolderPath\("Programs"\)/);
  assert.match(clipboardInstall, /RedactWall Clipboard Guard/);
  assert.match(clipboardInstall, /run-clipboard-guard\.ps1/);
  assert.match(clipboardInstall, /WindowStyle = 7/);
  assert.match(clipboardInstall, /DesktopShortcut/);
  assert.match(clipboardInstall, /HotKey/);
  assert.match(clipboardInstall, /Assert-SafeShortcutName/);
  assert.match(clipboardInstall, /Assert-SafeShortcutArgument/);
  assert.doesNotMatch(clipboardInstall, /INGEST_API_KEY|ENDPOINT_AGENT_HANDOFF_SECRET|"-IngestKey"|"-HandoffSecret"/);
  assert.match(clipboardRun, /\$env:REDACTWALL_ENV_PATH = \$config/);
  assert.match(clipboardRun, /Remove-Item Env:\\PROMPTWALL_ENV_PATH/);
  assert.match(clipboardRun, /Remove-Item Env:\\SENTINEL_ENV_PATH/);
  assert.doesNotMatch(clipboardRun, /\$env:(?:PROMPTWALL|SENTINEL)_ENV_PATH = \$config/);
  assert.match(clipboardRun, /clipboard-guard\.js/);
  assert.match(clipboardRun, /--clear-on-block/);
  assert.match(clipboardRun, /\$guardOutput \| Out-File -Append/);
  assert.doesNotMatch(clipboardRun, /Get-Clipboard|Set-Clipboard|contentBase64/);
  assert.match(clipboardUninstall, /RedactWall Clipboard Guard/);
  assert.match(clipboardUninstall, /GetFolderPath\("Programs"\)/);
});

test('uninstaller removes task and can remove endpoint config', () => {
  assert.match(uninstall, /Stop-ScheduledTask/);
  assert.match(uninstall, /Unregister-ScheduledTask/);
  assert.match(uninstall, /endpoint-agent\.pid/);
  assert.match(uninstall, /GetFolderPath\("Startup"\)/);
  assert.ok(uninstall.includes("sensors[\\\\/]endpoint-agent[\\\\/]agent\\.js"));
  assert.match(uninstall, /\$RemoveConfig/);
  assert.match(uninstall, /\$RemoveDesktopCollector/);
  assert.match(uninstall, /\$RemoveClipboardGuard/);
  assert.match(uninstall, /uninstall-desktop-collector\.ps1/);
  assert.match(uninstall, /uninstall-clipboard-guard\.ps1/);
  assert.match(uninstall, /endpoint-agent\.env/);
});

test('deployment docs include endpoint task install and uninstall flow', () => {
  assert.match(deployment, /install-endpoint-agent\.ps1/);
  assert.match(deployment, /-RedactWallUrl "https:\/\/redactwall\.example\.com"/);
  assert.match(deployment, /install-desktop-collector\.ps1/);
  assert.match(deployment, /install-clipboard-guard\.ps1/);
  assert.match(deployment, /RedactWall Protected Upload/);
  assert.match(deployment, /RedactWall Clipboard Guard/);
  assert.match(deployment, /uninstall-endpoint-agent\.ps1/);
  assert.match(deployment, /clipboard-guard\.log/);
  assert.match(deployment, /desktop-collector\.log/);
  assert.match(deployment, /RedactWallEndpointAgent/);
  assert.match(deployment, /%LOCALAPPDATA%\\RedactWall\\endpoint-agent\.env/);
  assert.match(deployment, /ENDPOINT_AGENT_HANDOFF_SECRET/);
  assert.match(deployment, /npm run endpoint:check/);
  assert.match(deployment, /\/api\/v1\/heartbeat/);
});
