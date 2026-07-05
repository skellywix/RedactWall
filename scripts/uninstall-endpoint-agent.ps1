param(
  [string]$TaskName = "RedactWallEndpointAgent",
  [string]$ConfigDir = "$env:LOCALAPPDATA\RedactWall",
  [switch]$RemoveDesktopCollector,
  [string]$DesktopCollectorKeyName = "RedactWallProtectedUpload",
  [switch]$RemoveClipboardGuard,
  [string]$ClipboardGuardShortcutName = "RedactWall Clipboard Guard",
  [switch]$ClipboardGuardDesktopShortcut,
  [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"

$configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
$pidPath = Join-Path $configRoot "endpoint-agent.pid"

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath("Startup")) "$TaskName.lnk") -Force -ErrorAction SilentlyContinue

if (Test-Path -LiteralPath $pidPath) {
  $pidText = (Get-Content -LiteralPath $pidPath -ErrorAction SilentlyContinue | Select-Object -First 1)
  if ($pidText -match '^\d+$') {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pidText" -ErrorAction SilentlyContinue
    if ($process -and $process.CommandLine -match 'sensors[\\/]endpoint-agent[\\/]agent\.js') {
      Stop-Process -Id ([int]$pidText) -Force -ErrorAction SilentlyContinue
    }
  }
  Remove-Item -LiteralPath $pidPath -Force -ErrorAction SilentlyContinue
}

if ($RemoveDesktopCollector) {
  $collectorUninstaller = Join-Path $PSScriptRoot "uninstall-desktop-collector.ps1"
  if (Test-Path -LiteralPath $collectorUninstaller) {
    & $collectorUninstaller -KeyName $DesktopCollectorKeyName
  }
}

if ($RemoveClipboardGuard) {
  $clipboardUninstaller = Join-Path $PSScriptRoot "uninstall-clipboard-guard.ps1"
  if (Test-Path -LiteralPath $clipboardUninstaller) {
    & $clipboardUninstaller -ShortcutName $ClipboardGuardShortcutName -DesktopShortcut:$ClipboardGuardDesktopShortcut.IsPresent
  }
}

if ($RemoveConfig) {
  Remove-Item -LiteralPath (Join-Path $configRoot "endpoint-agent.env") -Force -ErrorAction SilentlyContinue
}

Write-Host "Uninstalled $TaskName"
