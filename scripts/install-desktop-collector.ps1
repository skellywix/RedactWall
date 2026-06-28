param(
  [string]$MenuName = "PromptWall Protected Upload",
  [string]$KeyName = "PromptWallProtectedUpload",
  [string]$Destination = "",
  [string]$ConfigDir = "$env:LOCALAPPDATA\PromptWall",
  [string]$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
  [string]$LogPath = "$env:LOCALAPPDATA\PromptWall\logs\desktop-collector.log",
  [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is required on PATH before installing the PromptWall desktop collector."
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$runner = Join-Path $repo "scripts\run-desktop-collector.ps1"
if (-not (Test-Path -LiteralPath $runner)) {
  throw "Desktop collector runner not found: $runner"
}

$configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
$configPath = Join-Path $configRoot "endpoint-agent.env"
if (-not (Test-Path -LiteralPath $configPath)) {
  throw "Endpoint agent config not found: $configPath"
}

$configText = Get-Content -LiteralPath $configPath -Raw
function Get-EndpointConfigValue {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text,

    [Parameter(Mandatory = $true)]
    [string[]]$Names
  )

  foreach ($name in $Names) {
    $pattern = "(?m)^\s*$([regex]::Escape($name))=(.+?)\s*$"
    $match = [regex]::Match($Text, $pattern)
    if ($match.Success -and $match.Groups[1].Value.Trim()) {
      return $match.Groups[1].Value.Trim()
    }
  }
  return ""
}

$handoffDirValue = Get-EndpointConfigValue -Text $configText -Names @("ENDPOINT_AGENT_HANDOFF_DIR", "PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR")
$handoffSecretValue = Get-EndpointConfigValue -Text $configText -Names @("ENDPOINT_AGENT_HANDOFF_SECRET", "PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET")
if (-not $handoffDirValue) {
  throw "Endpoint native handoff must be enabled before installing the desktop collector."
}
if ($handoffSecretValue.Trim().Length -lt 32) {
  throw "Endpoint native handoff secret must be at least 32 characters."
}

$commandKey = "Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\$KeyName"
if ((Test-Path -LiteralPath $commandKey) -and -not $Force) {
  throw "Desktop collector shell action already exists. Re-run with -Force to replace it."
}
if ($Force) {
  Remove-Item -LiteralPath $commandKey -Recurse -Force -ErrorAction SilentlyContinue
}

New-Item -Path $commandKey -Force | Out-Null
New-Item -Path (Join-Path $commandKey "command") -Force | Out-Null
Set-Item -LiteralPath $commandKey -Value $MenuName
New-ItemProperty -LiteralPath $commandKey -Name "MUIVerb" -Value $MenuName -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath $commandKey -Name "MultiSelectModel" -Value "Player" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath $commandKey -Name "Icon" -Value "powershell.exe" -PropertyType String -Force | Out-Null

$taskParts = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-WindowStyle", "Hidden",
  "-File", "`"$runner`"",
  "-RepoRoot", "`"$repo`"",
  "-ConfigPath", "`"$configPath`"",
  "-FilePath", '"%1"',
  "-LogPath", "`"$LogPath`""
)
if ($Destination) {
  $taskParts += @("-Destination", "`"$Destination`"")
}
$taskArgs = $taskParts -join " "
$command = "powershell.exe $taskArgs"
Set-Item -LiteralPath (Join-Path $commandKey "command") -Value $command

Write-Host "Installed $MenuName"
Write-Host "Registry key: HKCU\Software\Classes\*\shell\$KeyName"
Write-Host "Config file: $configPath"
Write-Host "Log file: $LogPath"
