param(
  [string]$TaskName = "PromptSentinelEndpointAgent",
  [string]$ConfigDir = "$env:LOCALAPPDATA\PromptSentinel",
  [switch]$RemoveConfig
)

$ErrorActionPreference = "Stop"

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

if ($RemoveConfig) {
  $configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
  Remove-Item -LiteralPath (Join-Path $configRoot "endpoint-agent.env") -Force -ErrorAction SilentlyContinue
}

Write-Host "Uninstalled $TaskName"
