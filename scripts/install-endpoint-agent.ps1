param(
  [string]$TaskName = "RedactWallEndpointAgent",
  [Alias("SentinelUrl")]
  [string]$RedactWallUrl = "http://localhost:4000",
  [Parameter(Mandatory = $true)]
  [string]$IngestKey,
  [string]$WatchDir = "$env:USERPROFILE\RedactWallWatch",
  [string]$HandoffDir = "$env:LOCALAPPDATA\RedactWall\native-handoff",
  [string]$HandoffSecret = "",
  [switch]$InstallDesktopCollector,
  [string]$DesktopCollectorDestination = "",
  [string]$DesktopCollectorMenuName = "RedactWall Protected Upload",
  [string]$DesktopCollectorKeyName = "RedactWallProtectedUpload",
  [switch]$InstallClipboardGuard,
  [switch]$ClipboardGuardClearOnBlock,
  [string]$ClipboardGuardDestination = "",
  [string]$ClipboardGuardShortcutName = "RedactWall Clipboard Guard",
  [switch]$ClipboardGuardDesktopShortcut,
  [string]$ConfigDir = "$env:LOCALAPPDATA\RedactWall",
  [string]$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
  [string]$OcrCommand = "",
  [switch]$SkipOcr,
  [switch]$DisableAppFileFlow,
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
$pidPath = Join-Path $configRoot "endpoint-agent.pid"

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
  "# RedactWall endpoint agent local config",
  "REDACTWALL_URL=$RedactWallUrl",
  "INGEST_API_KEY=$IngestKey",
  "ENDPOINT_AGENT_WATCH_DIR=$watchRoot",
  "REDACTWALL_REQUEST_TIMEOUT_MS=10000"
)
if ($HandoffSecret) {
  $configLines += "ENDPOINT_AGENT_HANDOFF_DIR=$handoffRoot"
  $configLines += "ENDPOINT_AGENT_HANDOFF_SECRET=$HandoffSecret"
}
if ($DesktopCollectorDestination) {
  $configLines += "ENDPOINT_AGENT_DESKTOP_DESTINATION=$DesktopCollectorDestination"
}
$resolvedOcrCommand = $OcrCommand
if (-not $resolvedOcrCommand -and -not $SkipOcr) {
  $tesseract = Get-Command tesseract -ErrorAction SilentlyContinue
  if ($tesseract) {
    $resolvedOcrCommand = $tesseract.Source
  } else {
    foreach ($candidate in @(
      (Join-Path $env:ProgramFiles "Tesseract-OCR\tesseract.exe"),
      (Join-Path $env:LOCALAPPDATA "Programs\Tesseract-OCR\tesseract.exe")
    )) {
      if ($candidate -and (Test-Path -LiteralPath $candidate)) { $resolvedOcrCommand = $candidate; break }
    }
  }
}
if ($resolvedOcrCommand) {
  $configLines += "ENDPOINT_AGENT_OCR_COMMAND=$resolvedOcrCommand"
}
if (-not $DisableAppFileFlow) {
  $configLines += "ENDPOINT_AGENT_APP_FLOW=1"
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
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath("Startup")) "$TaskName.lnk") -Force -ErrorAction SilentlyContinue
}

$taskArgs = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-File", "`"$runner`"",
  "-RepoRoot", "`"$repo`"",
  "-ConfigPath", "`"$configPath`"",
  "-LogPath", "`"$logPath`""
) -join " "

function Install-EndpointStartupShortcut {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ShortcutName,

    [Parameter(Mandatory = $true)]
    [string]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory
  )

  $startupDir = [Environment]::GetFolderPath("Startup")
  New-Item -ItemType Directory -Force -Path $startupDir | Out-Null
  $shortcutPath = Join-Path $startupDir "$ShortcutName.lnk"
  $shell = New-Object -ComObject WScript.Shell
  $shortcut = $shell.CreateShortcut($shortcutPath)
  $shortcut.TargetPath = "powershell.exe"
  $shortcut.Arguments = $Arguments
  $shortcut.WorkingDirectory = $WorkingDirectory
  $shortcut.WindowStyle = 7
  $shortcut.Description = "RedactWall endpoint file sensor"
  $shortcut.Save()
  return $shortcutPath
}

function Start-EndpointFallbackProcess {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [Parameter(Mandatory = $true)]
    [string]$LogPath,

    [Parameter(Mandatory = $true)]
    [string]$PidPath
  )

  $node = Get-Command node -ErrorAction Stop
  $agent = Join-Path $RepoRoot "sensors\endpoint-agent\agent.js"
  $errLog = Join-Path (Split-Path -Parent $LogPath) "endpoint-agent.err.log"
  $previousEnvPath = $env:REDACTWALL_ENV_PATH
  $previousPromptWallEnvPath = $env:PROMPTWALL_ENV_PATH
  $previousSentinelEnvPath = $env:SENTINEL_ENV_PATH
  $env:REDACTWALL_ENV_PATH = $ConfigPath
  Remove-Item Env:\PROMPTWALL_ENV_PATH -ErrorAction SilentlyContinue
  Remove-Item Env:\SENTINEL_ENV_PATH -ErrorAction SilentlyContinue
  try {
    $proc = Start-Process -FilePath $node.Source -ArgumentList "`"$agent`"" -WorkingDirectory $RepoRoot -WindowStyle Hidden -RedirectStandardOutput $LogPath -RedirectStandardError $errLog -PassThru
  } finally {
    if ($null -eq $previousEnvPath) { Remove-Item Env:\REDACTWALL_ENV_PATH -ErrorAction SilentlyContinue }
    else { $env:REDACTWALL_ENV_PATH = $previousEnvPath }
    if ($null -eq $previousPromptWallEnvPath) { Remove-Item Env:\PROMPTWALL_ENV_PATH -ErrorAction SilentlyContinue }
    else { $env:PROMPTWALL_ENV_PATH = $previousPromptWallEnvPath }
    if ($null -eq $previousSentinelEnvPath) { Remove-Item Env:\SENTINEL_ENV_PATH -ErrorAction SilentlyContinue }
    else { $env:SENTINEL_ENV_PATH = $previousSentinelEnvPath }
  }
  Set-Content -LiteralPath $PidPath -Encoding ascii -Value ([string]$proc.Id)
  return $proc
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$startupMode = "scheduled task"
try {
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "RedactWall endpoint file sensor" | Out-Null
  Start-ScheduledTask -TaskName $TaskName
} catch {
  if ($_.Exception.Message -notmatch "Access is denied|0x80070005") {
    throw
  }
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  $shortcutPath = Install-EndpointStartupShortcut -ShortcutName $TaskName -Arguments $taskArgs -WorkingDirectory $repo
  Start-EndpointFallbackProcess -RepoRoot $repo -ConfigPath $configPath -LogPath $logPath -PidPath $pidPath | Out-Null
  $startupMode = "startup shortcut"
  Write-Warning "Scheduled task registration was denied. Installed a per-user Startup shortcut instead: $shortcutPath"
}

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
    -KeyName $DesktopCollectorKeyName `
    -Force:$Force.IsPresent
}

if ($InstallClipboardGuard) {
  $clipboardInstaller = Join-Path $repo "scripts\install-clipboard-guard.ps1"
  if (-not (Test-Path -LiteralPath $clipboardInstaller)) {
    throw "Clipboard guard installer not found: $clipboardInstaller"
  }
  $clipboardDestination = $ClipboardGuardDestination
  if (-not $clipboardDestination) {
    $clipboardDestination = $DesktopCollectorDestination
  }
  & $clipboardInstaller `
    -ConfigDir $configRoot `
    -RepoRoot $repo `
    -Destination $clipboardDestination `
    -ShortcutName $ClipboardGuardShortcutName `
    -ClearOnBlock:$ClipboardGuardClearOnBlock.IsPresent `
    -DesktopShortcut:$ClipboardGuardDesktopShortcut.IsPresent `
    -Force:$Force.IsPresent
}

Write-Host "Installed $TaskName"
Write-Host "Startup mode: $startupMode"
Write-Host "Watch directory: $watchRoot"
if ($HandoffSecret) { Write-Host "Native handoff directory: $handoffRoot" }
if ($InstallDesktopCollector) { Write-Host "Desktop collector: $DesktopCollectorMenuName" }
if ($InstallClipboardGuard) { Write-Host "Clipboard guard shortcut: $ClipboardGuardShortcutName" }
if ($resolvedOcrCommand) { Write-Host "OCR engine: $resolvedOcrCommand" }
else { Write-Host "OCR engine: not found (images stay ocr_required; install tesseract and re-run, or pass -OcrCommand)" }
if (-not $DisableAppFileFlow) { Write-Host "App file-flow: enabled (guarded folders under $watchRoot\AI Apps)" }
Write-Host "Config file: $configPath"
Write-Host "Log file: $logPath"
