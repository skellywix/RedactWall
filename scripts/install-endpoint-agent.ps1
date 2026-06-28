param(
  [string]$TaskName = "PromptWallEndpointAgent",
  [string]$SentinelUrl = "http://localhost:4000",
  [Parameter(Mandatory = $true)]
  [string]$IngestKey,
  [string]$WatchDir = "$env:USERPROFILE\PromptWallWatch",
  [string]$HandoffDir = "$env:LOCALAPPDATA\PromptWall\native-handoff",
  [string]$HandoffSecret = "",
  [switch]$InstallDesktopCollector,
  [string]$DesktopCollectorDestination = "Desktop AI",
  [string]$DesktopCollectorMenuName = "PromptWall Protected Upload",
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
} elseif ($InstallDesktopCollector) {
  throw "InstallDesktopCollector requires HandoffSecret so protected uploads can be signed."
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
if ($HandoffSecret) {
  $handoffAcl = Get-Acl -LiteralPath $handoffRoot
  $handoffAcl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($handoffAcl.Access)) { $handoffAcl.RemoveAccessRule($rule) | Out-Null }
  $handoffAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
  $handoffAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
  $handoffAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
  Set-Acl -LiteralPath $handoffRoot -AclObject $handoffAcl
}

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

if ($InstallDesktopCollector) {
  $collectorInstaller = Join-Path $repo "scripts\install-desktop-collector.ps1"
  if (-not (Test-Path -LiteralPath $collectorInstaller)) {
    throw "Desktop collector installer not found: $collectorInstaller"
  }
  & $collectorInstaller `
    -ConfigDir $configRoot `
    -RepoRoot $repo `
    -Destination $DesktopCollectorDestination `
    -MenuName $DesktopCollectorMenuName `
    -Force:$Force.IsPresent
}

Write-Host "Installed $TaskName"
Write-Host "Watch directory: $watchRoot"
if ($HandoffSecret) { Write-Host "Native handoff directory: $handoffRoot" }
if ($InstallDesktopCollector) { Write-Host "Desktop collector: $DesktopCollectorMenuName" }
Write-Host "Config file: $configPath"
Write-Host "Log file: $logPath"
