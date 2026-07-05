param(
  [Parameter(Mandatory = $true)]
  [string]$ExtensionId,
  [ValidateSet("chrome", "edge", "both")]
  [string]$Browser = "both",
  [string]$ConfigDir = "$env:LOCALAPPDATA\RedactWall",
  [string]$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
  [switch]$Force
)

# Registers the RedactWall browser file-intent native messaging host for the
# current user: a secret-free .cmd launcher, the host manifest JSON, and the
# per-user NativeMessagingHosts registry key for Chrome and/or Edge. The
# endpoint config (ingest key, handoff secret) stays in endpoint-agent.env;
# nothing secret is written into the launcher, manifest, or registry.

$ErrorActionPreference = "Stop"

$HostName = "com.redactwall.file_intent"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is required on PATH before installing the RedactWall file-intent host."
}
if ($ExtensionId -notmatch '^[a-p]{32}$') {
  throw "ExtensionId must be a 32-character Chrome extension id."
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$hostScript = Join-Path $repo "sensors\endpoint-agent\native-messaging-host.js"
if (-not (Test-Path -LiteralPath $hostScript)) {
  throw "Native messaging host not found: $hostScript"
}

$configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
$configPath = Join-Path $configRoot "endpoint-agent.env"
if (-not (Test-Path -LiteralPath $configPath)) {
  throw "Endpoint agent config not found: $configPath"
}

$launcherPath = Join-Path $configRoot "file-intent-host.cmd"
$manifestPath = Join-Path $configRoot "$HostName.json"
foreach ($existing in @($launcherPath, $manifestPath)) {
  if ((Test-Path -LiteralPath $existing) -and -not $Force) {
    throw "File-intent host artifact already exists. Re-run with -Force to replace it: $existing"
  }
}

New-Item -ItemType Directory -Force -Path $configRoot | Out-Null

$launcherBody = @(
  "@echo off",
  "node `"$hostScript`" --env `"$configPath`" %*"
) -join "`r`n"
Set-Content -LiteralPath $launcherPath -Value $launcherBody -Encoding Ascii

$manifestBody = [ordered]@{
  name = $HostName
  description = "RedactWall browser file-upload intent handoff"
  path = $launcherPath
  type = "stdio"
  allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json
Set-Content -LiteralPath $manifestPath -Value $manifestBody -Encoding UTF8

$registryRoots = @()
if ($Browser -eq "chrome" -or $Browser -eq "both") {
  $registryRoots += "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
}
if ($Browser -eq "edge" -or $Browser -eq "both") {
  $registryRoots += "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
}
foreach ($registryPath in $registryRoots) {
  New-Item -Path $registryPath -Force | Out-Null
  Set-ItemProperty -Path $registryPath -Name "(default)" -Value $manifestPath
  Write-Host "Registered native messaging host: $registryPath"
}

Write-Host "Host manifest: $manifestPath"
Write-Host "Launcher: $launcherPath"
Write-Host "Allowed origin: chrome-extension://$ExtensionId/"
