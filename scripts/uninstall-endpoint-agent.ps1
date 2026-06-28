param(
  [string]$TaskName = "PromptWallEndpointAgent",
  [string]$ConfigDir = "$env:LOCALAPPDATA\PromptWall",
  [switch]$RemoveDesktopCollector,
  [string]$DesktopCollectorKeyName = "PromptWallProtectedUpload",
  [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

if ($RemoveDesktopCollector) {
  $collectorUninstaller = Join-Path $PSScriptRoot "uninstall-desktop-collector.ps1"
  if (Test-Path -LiteralPath $collectorUninstaller) {
    & $collectorUninstaller -KeyName $DesktopCollectorKeyName
  }
}

if ($RemoveConfig) {
  $configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
  Remove-Item -LiteralPath (Join-Path $configRoot "endpoint-agent.env") -Force -ErrorAction SilentlyContinue
}

Write-Host "Uninstalled $TaskName"
