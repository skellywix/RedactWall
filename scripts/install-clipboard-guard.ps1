param(
  [string]$ShortcutName = "PromptWall Clipboard Guard",
  [string]$Destination = "",
  [string]$ConfigDir = "$env:LOCALAPPDATA\PromptWall",
  [string]$RepoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path,
  [string]$LogPath = "$env:LOCALAPPDATA\PromptWall\logs\clipboard-guard.log",
  [string]$HotKey = "",
  [switch]$ClearOnBlock,
  [switch]$DesktopShortcut,
  [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  throw "Node.js is required on PATH before installing the PromptWall clipboard guard."
}

$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$runner = Join-Path $repo "scripts\run-clipboard-guard.ps1"
if (-not (Test-Path -LiteralPath $runner)) {
  throw "Clipboard guard runner not found: $runner"
}

$configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)
$configPath = Join-Path $configRoot "endpoint-agent.env"
if (-not (Test-Path -LiteralPath $configPath)) {
  throw "Endpoint agent config not found: $configPath"
}

function Assert-SafeShortcutName {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not $Name.Trim()) {
    throw "ShortcutName is required."
  }
  if ($Name -match '[\\/:*?"<>|]' -or $Name -match "[`r`n]") {
    throw "ShortcutName must be a plain shortcut label, not a path."
  }
}

function Assert-SafeShortcutArgument {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Value = ""
  )
  if ($Value -match "[`"`r`n]") {
    throw "$Name cannot contain quotes or line breaks."
  }
}

Assert-SafeShortcutName -Name $ShortcutName
Assert-SafeShortcutArgument -Name "Destination" -Value $Destination
Assert-SafeShortcutArgument -Name "LogPath" -Value $LogPath
Assert-SafeShortcutArgument -Name "HotKey" -Value $HotKey

function New-ClipboardGuardShortcut {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ShortcutPath,

    [Parameter(Mandatory = $true)]
    [string]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$WorkingDirectory,

    [string]$HotKey = ""
  )

  $parent = Split-Path -Parent $ShortcutPath
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $shell = New-Object -ComObject WScript.Shell
  $shortcut = $shell.CreateShortcut($ShortcutPath)
  $shortcut.TargetPath = "powershell.exe"
  $shortcut.Arguments = $Arguments
  $shortcut.WorkingDirectory = $WorkingDirectory
  $shortcut.WindowStyle = 7
  $shortcut.Description = "PromptWall one-shot clipboard guard"
  if ($HotKey) {
    $shortcut.Hotkey = $HotKey
  }
  $shortcut.Save()
}

$programsDir = [Environment]::GetFolderPath("Programs")
$shortcutPaths = @(Join-Path $programsDir "$ShortcutName.lnk")
if ($DesktopShortcut) {
  $shortcutPaths += (Join-Path ([Environment]::GetFolderPath("Desktop")) "$ShortcutName.lnk")
}

foreach ($shortcutPath in $shortcutPaths) {
  if ((Test-Path -LiteralPath $shortcutPath) -and -not $Force) {
    throw "Clipboard guard shortcut already exists. Re-run with -Force to replace it: $shortcutPath"
  }
}
if ($Force) {
  foreach ($shortcutPath in $shortcutPaths) {
    Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
  }
}

$taskParts = @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-WindowStyle", "Hidden",
  "-File", "`"$runner`"",
  "-RepoRoot", "`"$repo`"",
  "-ConfigPath", "`"$configPath`"",
  "-LogPath", "`"$LogPath`""
)
if ($Destination) {
  $taskParts += @("-Destination", "`"$Destination`"")
}
if ($ClearOnBlock) {
  $taskParts += "-ClearOnBlock"
}
$taskArgs = $taskParts -join " "

foreach ($shortcutPath in $shortcutPaths) {
  New-ClipboardGuardShortcut -ShortcutPath $shortcutPath -Arguments $taskArgs -WorkingDirectory $repo -HotKey $HotKey
  Write-Host "Installed clipboard guard shortcut: $shortcutPath"
}
Write-Host "Config file: $configPath"
Write-Host "Log file: $LogPath"
