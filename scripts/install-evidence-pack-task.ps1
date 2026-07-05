param(
  [string]$TaskName = 'RedactWall Examiner Evidence Pack',
  [string]$TaskPath = '\RedactWall\',
  [ValidateSet('Daily', 'Weekly', 'Quarterly')]
  [string]$Cadence = 'Quarterly',
  [ValidateSet('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')]
  [string]$DayOfWeek = 'Sunday',
  [string]$At = '11:00 PM',
  [string]$ProjectDir,
  [string]$ConfigPath,
  [string]$LogPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ProjectDir)) {
  $ProjectDir = Join-Path $PSScriptRoot '..'
}

$repoRoot = (Resolve-Path -LiteralPath $ProjectDir).Path
$runner = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot 'run-evidence-pack.ps1')).Path

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
  $ConfigPath = Join-Path $repoRoot 'config\evidence-schedule.json'
}

if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
  $ConfigPath = Join-Path $repoRoot $ConfigPath
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "Evidence schedule config not found: $ConfigPath. Copy config\evidence-schedule.example.json to config\evidence-schedule.json and set the output folder before installing the scheduled task."
}

$resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path

if ([string]::IsNullOrWhiteSpace($LogPath)) {
  $LogPath = Join-Path $env:LOCALAPPDATA 'RedactWall\logs\evidence-pack.log'
}

$logDir = Split-Path -Parent $LogPath
if (-not [string]::IsNullOrWhiteSpace($logDir)) {
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$triggerTime = [DateTime]::Parse($At)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$argumentParts = @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-File', ('"' + $runner + '"'),
  '-ProjectDir', ('"' + $repoRoot + '"'),
  '-ConfigPath', ('"' + $resolvedConfig + '"'),
  '-LogPath', ('"' + $LogPath + '"')
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
  'Quarterly' {
    $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 13 -DaysOfWeek $DayOfWeek -At $triggerTime
  }
}

$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Hours 2)
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
  -Description 'Generate sanitized RedactWall examiner evidence packs from the configured schedule file.' `
  -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
$info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath

Write-Host "Registered scheduled task: $($task.TaskPath)$($task.TaskName)"
Write-Host "Cadence: $Cadence"
Write-Host "Trigger: $($trigger.StartBoundary)"
Write-Host "Config: $resolvedConfig"
Write-Host "Next run: $($info.NextRunTime)"
Write-Host "Log: $LogPath"
