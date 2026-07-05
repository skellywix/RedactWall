param(
  [string]$ShortcutName = "RedactWall Clipboard Guard",
  [switch]$DesktopShortcut
)

$ErrorActionPreference = "Stop"

$shortcutPaths = @(Join-Path ([Environment]::GetFolderPath("Programs")) "$ShortcutName.lnk")
if ($DesktopShortcut) {
  $shortcutPaths += (Join-Path ([Environment]::GetFolderPath("Desktop")) "$ShortcutName.lnk")
}

foreach ($shortcutPath in $shortcutPaths) {
  Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction SilentlyContinue
}
Write-Host "Uninstalled RedactWall clipboard guard shortcut"
