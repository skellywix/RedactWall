param(
  [Parameter(Mandatory = $true)]
  [string]$RepoRoot,

  [Parameter(Mandatory = $true)]
  [string]$ConfigPath,

  [string]$LogPath = "$env:LOCALAPPDATA\PromptSentinel\logs\endpoint-agent.log"
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$logDir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$node = Get-Command node -ErrorAction Stop
$env:SENTINEL_ENV_PATH = $config
Set-Location -LiteralPath $repo

try {
  & $node.Source (Join-Path $repo "endpoint-agent\agent.js") *>> $LogPath
  exit $LASTEXITCODE
} catch {
  "$(Get-Date -Format o) endpoint agent runner failed: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 -FilePath $LogPath
  exit 1
}
