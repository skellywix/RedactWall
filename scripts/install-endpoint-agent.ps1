param(
  [string]$TaskName = "PromptWallEndpointAgent",
  [string]$SentinelUrl = "http://localhost:4000",
  [Parameter(Mandatory = $true)]
  [string]$IngestKey,
  [string]$WatchDir = "$env:USERPROFILE\PromptWallWatch",
  [string]$HandoffDir = "$env:LOCALAPPDATA\PromptWall\native-handoff",
  [string]$HandoffSecret = "",
  [string]$ConfigDir = "$env:LOCALAPPDATA\PromptWall",
  [string]$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
  [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is required on PATH before installing the endpoint agent."
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$runner = Join-Path $repo "scripts\run-endpoint-agent.ps1"
if (-not (Test-Path -LiteralPath $runner)) {
  throw "Endpoint runner not found: $runner"
}

$configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
$watchRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WatchDir)
$handoffRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HandoffDir)
$logDir = Join-Path $configRoot "logs"
$configPath = Join-Path $configRoot "endpoint-agent.env"
$logPath = Join-Path $logDir "endpoint-agent.log"

New-Item -ItemType Directory -Force -Path $configRoot, $watchRoot, $logDir | Out-Null
if ($HandoffSecret) {
  if ($HandoffSecret.Trim().Length -lt 32) {
    throw "HandoffSecret must be at least 32 characters when native handoff is enabled."
  }
  New-Item -ItemType Directory -Force -Path $handoffRoot | Out-Null
}

if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -and -not $Force) {
  throw "Scheduled task $TaskName already exists. Re-run with -Force to replace it."
}

$configLines = @(
  "# PromptWall endpoint agent local config",
  "SENTINEL_URL=$SentinelUrl",
  "INGEST_API_KEY=$IngestKey",
  "ENDPOINT_AGENT_WATCH_DIR=$watchRoot",
  "SENTINEL_REQUEST_TIMEOUT_MS=10000"
)
if ($HandoffSecret) {
  $configLines += "ENDPOINT_AGENT_HANDOFF_DIR=$handoffRoot"
  $configLines += "ENDPOINT_AGENT_HANDOFF_SECRET=$HandoffSecret"
}
$configLines | Set-Content -LiteralPath $configPath -Encoding utf8

$acl = Get-Acl -LiteralPath $configPath
$acl.SetAccessRuleProtection($true, $false)
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRule($rule) | Out-Null }
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")))
Set-Acl -LiteralPath $configPath -AclObject $acl

if ($Force) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

$taskArgs = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-File", "`"$runner`"",
  "-RepoRoot", "`"$repo`"",
  "-ConfigPath", "`"$configPath`"",
  "-LogPath", "`"$logPath`""
) -join " "

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel LeastPrivilege
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "PromptWall endpoint file sensor" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "Installed $TaskName"
Write-Host "Watch directory: $watchRoot"
if ($HandoffSecret) { Write-Host "Native handoff directory: $handoffRoot" }
Write-Host "Config file: $configPath"
Write-Host "Log file: $logPath"
