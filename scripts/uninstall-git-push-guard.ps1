param(
  [Parameter(Mandatory = $true)]
  [string]$RepoPath,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Resolve-GitDir {
  param([string]$Repo)
  $gitDir = (& git -C $Repo rev-parse --git-dir 2>$null)
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gitDir)) {
    throw "RepoPath is not a git repository"
  }
  $gitDir = $gitDir.Trim()
  if ([System.IO.Path]::IsPathRooted($gitDir)) {
    return (Resolve-Path -LiteralPath $gitDir).Path
  }
  return (Resolve-Path -LiteralPath (Join-Path $Repo $gitDir)).Path
}

$repo = (Resolve-Path -LiteralPath $RepoPath).Path
$gitDir = Resolve-GitDir -Repo $repo
$hookPath = Join-Path (Join-Path $gitDir 'hooks') 'pre-push'
$marker = 'PromptWall Git Push Guard'

if (-not (Test-Path -LiteralPath $hookPath -PathType Leaf)) {
  Write-Host "PromptWall git push guard hook is not installed"
  exit 0
}

$existing = Get-Content -LiteralPath $hookPath -Raw
if ($existing -notmatch [regex]::Escape($marker) -and -not $Force) {
  throw "pre-push hook is not managed by PromptWall. Re-run with -Force after reviewing it."
}

Remove-Item -LiteralPath $hookPath -Force
Write-Host "Removed PromptWall git push guard hook at $hookPath"
