param(
  [switch]$CheckOnly,
  [switch]$NoPush,
  [string]$LogPath = $(Join-Path $env:LOCALAPPDATA 'PromptWall\logs\docs-sync.log')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Log {
  param([string]$Message)

  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
  $line = "[$timestamp] $Message"
  $logDir = Split-Path -Parent $LogPath
  if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
  }
  Add-Content -LiteralPath $LogPath -Value $line
  Write-Host $line
}

function Resolve-Tool {
  param(
    [string[]]$Names,
    [string]$FriendlyName
  )

  foreach ($name in $Names) {
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if ($command) {
      return $command.Source
    }
  }
  throw "$FriendlyName was not found on PATH."
}

function Format-CommandLine {
  param(
    [string]$Tool,
    [string[]]$Arguments
  )

  $parts = @($Tool) + ($Arguments | ForEach-Object {
    if ($_ -match '\s') {
      '"' + ($_ -replace '"', '\"') + '"'
    } else {
      $_
    }
  })
  return ($parts -join ' ')
}

function Invoke-Logged {
  param(
    [string]$Tool,
    [string[]]$Arguments
  )

  Write-Log ("> " + (Format-CommandLine -Tool $Tool -Arguments $Arguments))
  $previousErrorActionPreference = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = & $Tool @Arguments 2>&1
    $exitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  foreach ($line in $output) {
    Write-Log ([string]$line)
  }
  if ($exitCode -ne 0) {
    throw "Command failed with exit code ${exitCode}: $(Format-CommandLine -Tool $Tool -Arguments $Arguments)"
  }
  return @($output | ForEach-Object { [string]$_ })
}

function Test-DocumentationPath {
  param([string]$Path)

  $normalized = $Path -replace '\\', '/'
  return $normalized.EndsWith('.md', [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-GitLines {
  param([string[]]$Arguments)
  return @(Invoke-Logged -Tool $script:Git -Arguments $Arguments)
}

function Get-Upstream {
  $output = & $script:Git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>$null
  if ($LASTEXITCODE -ne 0) {
    return $null
  }
  return ([string]$output).Trim()
}

function Get-RevisionCounts {
  param([string]$Range)

  $raw = (Get-GitLines -Arguments @('rev-list', '--left-right', '--count', $Range)) -join ''
  $parts = $raw.Trim() -split '\s+'
  if ($parts.Count -ne 2) {
    throw "Unexpected rev-list count output: $raw"
  }
  return [pscustomobject]@{
    Ahead = [int]$parts[0]
    Behind = [int]$parts[1]
  }
}

function Get-AheadChangedFiles {
  $commits = Get-GitLines -Arguments @('log', '--format=%H', '@{u}..HEAD')
  $files = New-Object System.Collections.Generic.HashSet[string]
  foreach ($commit in $commits) {
    if (-not $commit) {
      continue
    }
    $changed = Get-GitLines -Arguments @('diff-tree', '--no-commit-id', '--name-only', '-r', $commit)
    foreach ($file in $changed) {
      if ($file) {
        [void]$files.Add($file)
      }
    }
  }
  return @($files)
}

function Assert-NoStagedChanges {
  $staged = Get-GitLines -Arguments @('diff', '--cached', '--name-only')
  if ($staged.Count -gt 0) {
    throw "Staged changes already exist. Clear the index before running documentation sync: $($staged -join ', ')"
  }
}

function Assert-NoNonDocWorkingChanges {
  $changed = Get-GitLines -Arguments @('diff', '--name-only')
  $nonDocs = @($changed | Where-Object { -not (Test-DocumentationPath $_) })
  if ($nonDocs.Count -gt 0) {
    throw "Non-document tracked changes exist. Refusing to mix docs sync with unrelated work: $($nonDocs -join ', ')"
  }
}

function Push-IfNeeded {
  param([string]$Branch)

  if ($NoPush) {
    Write-Log 'NoPush was set; skipping GitHub push.'
    return
  }

  $upstream = Get-Upstream
  if ($upstream) {
    $counts = Get-RevisionCounts -Range 'HEAD...@{u}'
    if ($counts.Ahead -eq 0 -and $counts.Behind -eq 0) {
      Write-Log "Local branch already matches $upstream."
      return
    }
    if ($counts.Behind -gt 0) {
      throw "Local branch is behind $upstream after docs sync; pull/rebase manually before pushing."
    }
    $aheadFiles = Get-AheadChangedFiles
    $nonDocAhead = @($aheadFiles | Where-Object { -not (Test-DocumentationPath $_) })
    if ($nonDocAhead.Count -gt 0) {
      throw "Unpushed commits include non-document files. Refusing automatic push: $($nonDocAhead -join ', ')"
    }
    Invoke-Logged -Tool $script:Git -Arguments @('push')
  } else {
    Invoke-Logged -Tool $script:Git -Arguments @('push', '-u', 'origin', $Branch)
  }

  Invoke-Logged -Tool $script:Git -Arguments @('fetch', '--prune', 'origin') | Out-Null
  $upstream = Get-Upstream
  if ($upstream) {
    $counts = Get-RevisionCounts -Range 'HEAD...@{u}'
    if ($counts.Ahead -ne 0 -or $counts.Behind -ne 0) {
      throw "Documentation sync finished, but local and GitHub do not match. Ahead=$($counts.Ahead), Behind=$($counts.Behind)."
    }
    Write-Log "Verified local branch matches $upstream."
  }
}

$script:Git = Resolve-Tool -Names @('git.exe', 'git') -FriendlyName 'Git'
$script:Npm = Resolve-Tool -Names @('npm.cmd', 'npm') -FriendlyName 'npm'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$lockPath = Join-Path $env:TEMP 'promptwall-docs-sync.lock'
$lock = $null

try {
  $lock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  Set-Location -LiteralPath $repoRoot
  Write-Log "PromptWall documentation sync started in $repoRoot."

  Invoke-Logged -Tool $script:Git -Arguments @('rev-parse', '--is-inside-work-tree') | Out-Null
  $branch = ((Get-GitLines -Arguments @('symbolic-ref', '--quiet', '--short', 'HEAD')) -join '').Trim()
  if (-not $branch) {
    throw 'Detached HEAD detected. Documentation sync requires a checked-out branch.'
  }

  if ($CheckOnly) {
    Invoke-Logged -Tool $script:Npm -Arguments @('run', 'docs:demo-guide:check') | Out-Null
    Write-Log 'Documentation check completed.'
    return
  }

  Invoke-Logged -Tool $script:Git -Arguments @('fetch', '--prune', 'origin') | Out-Null
  Assert-NoStagedChanges
  Assert-NoNonDocWorkingChanges

  $upstream = Get-Upstream
  if ($upstream) {
    $counts = Get-RevisionCounts -Range 'HEAD...@{u}'
    if ($counts.Ahead -gt 0 -and $counts.Behind -gt 0) {
      throw "Local branch and $upstream have diverged. Resolve manually before documentation sync."
    }
    if ($counts.Behind -gt 0) {
      $workingChanges = Get-GitLines -Arguments @('diff', '--name-only')
      if ($workingChanges.Count -gt 0) {
        throw "Local documentation changes exist while branch is behind $upstream. Resolve manually before syncing."
      }
      Invoke-Logged -Tool $script:Git -Arguments @('pull', '--ff-only') | Out-Null
    }
    if ($counts.Ahead -gt 0) {
      $aheadFiles = Get-AheadChangedFiles
      $nonDocAhead = @($aheadFiles | Where-Object { -not (Test-DocumentationPath $_) })
      if ($nonDocAhead.Count -gt 0) {
        throw "Local branch has unpushed non-document commits. Refusing automatic docs push: $($nonDocAhead -join ', ')"
      }
    }
  }

  Invoke-Logged -Tool $script:Npm -Arguments @('run', 'docs:demo-guide') | Out-Null
  Invoke-Logged -Tool $script:Npm -Arguments @('run', 'docs:demo-guide:check') | Out-Null

  $changed = Get-GitLines -Arguments @('diff', '--name-only', '--diff-filter=ACMRT')
  $nonDocs = @($changed | Where-Object { -not (Test-DocumentationPath $_) })
  if ($nonDocs.Count -gt 0) {
    throw "Documentation sync produced non-document changes. Refusing to commit: $($nonDocs -join ', ')"
  }

  $docs = @($changed | Where-Object { Test-DocumentationPath $_ })
  if ($docs.Count -gt 0) {
    Invoke-Logged -Tool $script:Npm -Arguments @('run', 'review:ci') | Out-Null
    foreach ($doc in $docs) {
      Invoke-Logged -Tool $script:Git -Arguments @('add', '--', $doc) | Out-Null
    }
    Invoke-Logged -Tool $script:Git -Arguments @('commit', '-m', 'docs: sync generated documentation') | Out-Null
    Write-Log "Committed documentation changes: $($docs -join ', ')"
  } else {
    Write-Log 'No documentation changes to commit.'
  }

  Push-IfNeeded -Branch $branch
  Write-Log 'PromptWall documentation sync completed successfully.'
} catch {
  Write-Log "ERROR: $($_.Exception.Message)"
  throw
} finally {
  if ($lock) {
    $lock.Dispose()
  }
}
