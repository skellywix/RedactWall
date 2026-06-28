param(
  [string]$KeyName = "PromptWallProtectedUpload"
)

$ErrorActionPreference = "Stop"

$commandKey = "Registry::HKEY_CURRENT_USER\Software\Classes\*\shell\$KeyName"
Remove-Item -LiteralPath $commandKey -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Uninstalled PromptWall desktop collector shell action"
