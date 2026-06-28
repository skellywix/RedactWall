param(
  [Parameter(Mandatory = $true)]
  [string]$RepoRoot,

  [Parameter(Mandatory = $true)]
  [string]$ConfigPath,

  [Parameter(Mandatory = $true)]
  [string[]]$FilePath,

  [string]$Destination = "",
  [string]$User = "",
  [string]$LogPath = "$env:LOCALAPPDATA\PromptWall\logs\desktop-collector.log",
  [int]$TimeoutMs = 30000
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$collector = Join-Path $repo "sensors\endpoint-agent\collectors\protected-upload.js"
if (-not (Test-Path -LiteralPath $collector)) {
  throw "PromptWall desktop collector not found: $collector"
}

$logDir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$node = Get-Command node -ErrorAction Stop
$env:PROMPTWALL_ENV_PATH = $config
Remove-Item Env:\SENTINEL_ENV_PATH -ErrorAction SilentlyContinue
Set-Location -LiteralPath $repo

$collectorArgs = @($collector)
foreach ($file in $FilePath) {
  $collectorArgs += @("--file", $file)
}
$collectorArgs += @(
  "--env", $config,
  "--wait",
  "--timeout-ms", [string]$TimeoutMs,
  "--json"
)
if ($Destination) {
  $collectorArgs += @("--destination", $Destination)
}
if ($User) {
  $collectorArgs += @("--user", $User)
}

try {
  "$(Get-Date -Format o) protected upload requested" | Out-File -Append -Encoding utf8 -FilePath $LogPath
  $collectorOutput = & $node.Source @collectorArgs 2>&1
  $exitCode = $LASTEXITCODE
  $collectorOutput | Out-File -Append -Encoding utf8 -FilePath $LogPath
  exit $exitCode
} catch {
  "$(Get-Date -Format o) desktop collector failed: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 -FilePath $LogPath
  exit 1
}
