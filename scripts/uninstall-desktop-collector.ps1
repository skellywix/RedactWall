param(
  [string]$KeyName = "RedactWallProtectedUpload"
)

$ErrorActionPreference = "Stop"

$commandKey = "Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\$KeyName"
Remove-Item -LiteralPath $commandKey -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Uninstalled RedactWall desktop collector shell action"
