param(
  [string]$TaskName = "PromptWallEndpointAgent",
  [string]$ConfigDir = "$env:LOCALAPPDATA\PromptWall",
  [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

if ($RemoveConfig) {
  $configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
  Remove-Item -LiteralPath (Join-Path $configRoot "endpoint-agent.env") -Force -ErrorAction SilentlyContinue
}

Write-Host "Uninstalled $TaskName"
