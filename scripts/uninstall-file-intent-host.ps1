param(
  [string]$ConfigDir = "$env:LOCALAPPDATA\RedactWall"
)

# Removes the RedactWall browser file-intent native messaging host for the
# current user: the Chrome/Edge registry keys, the host manifest JSON, and the
# secret-free launcher. Endpoint config (endpoint-agent.env) is left in place.

$ErrorActionPreference = "Stop"

$HostName = "com.redactwall.file_intent"
$configRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigDir)

foreach ($registryPath in @(
  "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName",
  "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
)) {
  if (Test-Path -Path $registryPath) {
    Remove-Item -Path $registryPath -Recurse -Force
    Write-Host "Removed native messaging host registration: $registryPath"
  }
}

foreach ($artifact in @(
  (Join-Path $configRoot "$HostName.json"),
  (Join-Path $configRoot "file-intent-host.cmd")
)) {
  if (Test-Path -LiteralPath $artifact) {
    Remove-Item -LiteralPath $artifact -Force
    Write-Host "Removed: $artifact"
  }
}
