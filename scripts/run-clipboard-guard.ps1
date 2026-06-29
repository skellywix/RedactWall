param(
  [Parameter(Mandatory = $true)]
  [string]$RepoRoot,

  [Parameter(Mandatory = $true)]
  [string]$ConfigPath,

  [string]$Destination = "",
  [string]$User = "",
  [string]$LogPath = "$env:LOCALAPPDATA\PromptWall\logs\clipboard-guard.log",
  [int]$MaxChars = 200000,
  [switch]$ClearOnBlock
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$guard = Join-Path $repo "sensors\endpoint-agent\collectors\clipboard-guard.js"
if (-not (Test-Path -LiteralPath $guard)) {
  throw "PromptWall clipboard guard not found: $guard"
}

$logDir = Split-Path -Parent $LogPath
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$node = Get-Command node -ErrorAction Stop
$env:PROMPTWALL_ENV_PATH = $config
Remove-Item Env:\SENTINEL_ENV_PATH -ErrorAction SilentlyContinue
Set-Location -LiteralPath $repo

$guardArgs = @(
  $guard,
  "--env", $config,
  "--max-chars", [string]$MaxChars,
  "--json"
)
if ($ClearOnBlock) {
  $guardArgs += "--clear-on-block"
}
if ($Destination) {
  $guardArgs += @("--destination", $Destination)
}
if ($User) {
  $guardArgs += @("--user", $User)
}

try {
  "$(Get-Date -Format o) clipboard guard requested" | Out-File -Append -Encoding utf8 -FilePath $LogPath
  $guardOutput = & $node.Source @guardArgs 2>&1
  $exitCode = $LASTEXITCODE
  $guardOutput | Out-File -Append -Encoding utf8 -FilePath $LogPath
  exit $exitCode
} catch {
  "$(Get-Date -Format o) clipboard guard failed: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 -FilePath $LogPath
  exit 1
}
