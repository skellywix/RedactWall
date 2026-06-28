param(
  [string]$ProjectDir,
  [string]$ConfigPath,
  [string]$LogPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($ProjectDir)) {
  $ProjectDir = Join-Path $PSScriptRoot '..'
}

$repoRoot = (Resolve-Path -LiteralPath $ProjectDir).Path

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
  $ConfigPath = Join-Path $repoRoot 'config\evidence-schedule.json'
}

if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
  $ConfigPath = Join-Path $repoRoot $ConfigPath
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
  throw "Evidence schedule config not found: $ConfigPath. Copy config\evidence-schedule.example.json to config\evidence-schedule.json and set the output folder before installing the scheduled task."
}

$resolvedConfig = (Resolve-Path -LiteralPath $ConfigPath).Path

if ([string]::IsNullOrWhiteSpace($LogPath)) {
  $LogPath = Join-Path $env:LOCALAPPDATA 'PromptWall\logs\evidence-pack.log'
}

$logDir = Split-Path -Parent $LogPath
if (-not [string]::IsNullOrWhiteSpace($logDir)) {
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) {
  $npm = Get-Command npm -ErrorAction Stop
}

$startedAt = Get-Date -Format o
"[$startedAt] Starting PromptWall scheduled evidence pack: $resolvedConfig" | Out-File -FilePath $LogPath -Append -Encoding utf8

Push-Location $repoRoot
try {
  & $npm.Source run evidence:pack:scheduled -- $resolvedConfig *>> $LogPath
  $exitCode = $LASTEXITCODE
} finally {
  Pop-Location
}

$finishedAt = Get-Date -Format o
if ($exitCode -ne 0) {
  "[$finishedAt] Scheduled evidence pack failed with exit code $exitCode" | Out-File -FilePath $LogPath -Append -Encoding utf8
  exit $exitCode
}

"[$finishedAt] Scheduled evidence pack completed" | Out-File -FilePath $LogPath -Append -Encoding utf8
