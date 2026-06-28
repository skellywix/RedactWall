param(
  [string]$TaskName = 'PromptWall Documentation Sync',
  [string]$TaskPath = '\PromptWall\',
  [string]$At = '9:00 AM',
  [string]$SyncScript = $(Join-Path $PSScriptRoot 'sync-docs.ps1')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$resolvedScript = Resolve-Path -LiteralPath $SyncScript
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$logPath = Join-Path $env:LOCALAPPDATA 'PromptWall\logs\docs-sync.log'
$powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$triggerTime = [DateTime]::Parse($At)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

$argumentParts = @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-File', ('"' + $resolvedScript + '"'),
  '-LogPath', ('"' + $logPath + '"')
)

$action = New-ScheduledTaskAction `
  -Execute $powerShell `
  -Argument ($argumentParts -join ' ') `
  -WorkingDirectory $repoRoot

$trigger = New-ScheduledTaskTrigger -Daily -At $triggerTime
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
  -Description 'Refresh PromptWall generated documentation, commit tracked docs, push to GitHub, and verify local/upstream parity.' `
  -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
$info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath

Write-Host "Registered scheduled task: $($task.TaskPath)$($task.TaskName)"
Write-Host "Trigger: daily at $($trigger.StartBoundary)"
Write-Host "Next run: $($info.NextRunTime)"
Write-Host "Log: $logPath"
