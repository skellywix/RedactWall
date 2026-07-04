param(
  [string]$TaskName = 'PromptWall Evidence Store Backup',
  [string]$TaskPath = '\PromptWall\',
  [ValidateSet('Daily', 'Weekly')]
  [string]$Cadence = 'Daily',
  [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
  [string]$DayOfWeek = 'Sunday',
  [string]$At = '2:00 AM',
  [string]$ProjectDir,
  [string]$BackupDir,
  [ValidateRange(1, 3650)]
  [int]$RetentionDays = 30,
  [string]$LogPath,
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
  Write-Host "Removed scheduled task: $TaskPath$TaskName"
  return
}

if ([string]::IsNullOrWhiteSpace($ProjectDir)) {
  $ProjectDir = Join-Path $PSScriptRoot '..'
}

$repoRoot = (Resolve-Path -LiteralPath $ProjectDir).Path

if ([string]::IsNullOrWhiteSpace($BackupDir)) {
  $BackupDir = Join-Path $repoRoot 'backups'
}

if (-not [System.IO.Path]::IsPathRooted($BackupDir)) {
  $BackupDir = Join-Path $repoRoot $BackupDir
}

New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
$resolvedBackupDir = (Resolve-Path -LiteralPath $BackupDir).Path

if ([string]::IsNullOrWhiteSpace($LogPath)) {
  $LogPath = Join-Path $env:LOCALAPPDATA 'PromptWall\logs\backup.log'
}

$logDir = Split-Path -Parent $LogPath
if (-not [string]::IsNullOrWhiteSpace($logDir)) {
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$triggerTime = [DateTime]::Parse($At)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# The backup manifest is prompt-free; the .db backup stays inside $BackupDir.
# Prune backups (and their manifests) older than the retention window only
# after a successful backup so a failing backup never eats older good copies.
$backupCommand = (
  "Set-Location -LiteralPath '$repoRoot'; " +
  "npm run backup -- --out '$resolvedBackupDir' *>> '$LogPath'; " +
  "if (`$LASTEXITCODE -ne 0) { exit `$LASTEXITCODE }; " +
  "Get-ChildItem -LiteralPath '$resolvedBackupDir' -File -Filter 'sentinel-*' | " +
  "Where-Object { `$_.LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) } | Remove-Item -Force"
)

$argumentParts = @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-Command', ('"' + $backupCommand + '"')
)

$action = New-ScheduledTaskAction `
  -Execute $powerShell `
  -Argument ($argumentParts -join ' ') `
  -WorkingDirectory $repoRoot

switch ($Cadence) {
  'Daily' {
    $trigger = New-ScheduledTaskTrigger -Daily -At $triggerTime
  }
  'Weekly' {
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $triggerTime
  }
}

$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$principal = New-ScheduledTaskPrincipal `
  -UserId $currentUser `
  -LogonType Interactive `
  -RunLevel Limited

Register-ScheduledTask `
  -TaskName $TaskName `
  -TaskPath $TaskPath `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Principal $principal `
  -Description 'Back up the PromptWall SQLite evidence store and prune backups older than the retention window.' `
  -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
$info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath

Write-Host "Registered scheduled task: $($task.TaskPath)$($task.TaskName)"
Write-Host "Cadence: $Cadence"
Write-Host "Trigger: $($trigger.StartBoundary)"
Write-Host "Backup dir: $resolvedBackupDir"
Write-Host "Retention: $RetentionDays day(s)"
Write-Host "Next run: $($info.NextRunTime)"
Write-Host "Log: $LogPath"
Write-Host "Uninstall: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-backup-task.ps1 -Uninstall"
