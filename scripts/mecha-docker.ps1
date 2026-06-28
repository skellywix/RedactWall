param(
  [ValidateSet('start', 'rebuild', 'restart', 'stop', 'status', 'check', 'smoke', 'logs')]
  [string]$Command = 'start'
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$EnvFile = if ($env:PROMPTWALL_MECHA_ENV) { $env:PROMPTWALL_MECHA_ENV } else { Join-Path $RepoRoot '.env.mecha.local' }
$ProjectName = if ($env:PROMPTWALL_MECHA_PROJECT) { $env:PROMPTWALL_MECHA_PROJECT } else { 'promptwall-mecha-20260628' }
$HostPort = if ($env:PROMPTWALL_MECHA_PORT) { [int]$env:PROMPTWALL_MECHA_PORT } else { 4027 }

function Write-Step($Message) {
  Write-Host "[mecha-docker] $Message"
}

function New-RandomBytes([int]$Count) {
  $bytes = New-Object byte[] $Count
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($bytes)
  } finally {
    $rng.Dispose()
  }
  return $bytes
}

function New-HexSecret([string]$Prefix, [int]$ByteCount = 32) {
  $hex = [BitConverter]::ToString((New-RandomBytes $ByteCount)).Replace('-', '').ToLowerInvariant()
  return "$Prefix$hex"
}

function New-Base32Secret([int]$Length = 32) {
  $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  $bytes = New-RandomBytes $Length
  $chars = foreach ($byte in $bytes) {
    $alphabet[[int]($byte % 32)]
  }
  return -join $chars
}

function Ensure-EnvFile {
  if (Test-Path -LiteralPath $EnvFile) {
    return
  }

  $adminPassword = New-HexSecret 'MechaAdmin!' 12
  $totpSecret = New-Base32Secret 32
  $sessionSecret = New-HexSecret 'mecha_session_' 32
  $dataKey = New-HexSecret 'mecha_data_' 32
  $ingestKey = New-HexSecret 'ps_ingest_mecha_' 32

  $content = @"
# PromptWall MECHA standing Docker test environment.
# Generated synthetic local secrets only. This file is ignored by Git.
PORT=$HostPort
NODE_ENV=production
HTTPS=true
COOKIE_SECURE=true

SENTINEL_SAAS_MODE=true
SENTINEL_TENANT_ID=mock-mecha
SENTINEL_SEAT_LIMIT=25
SENTINEL_REQUIRE_TENANT_CONTEXT=true
SENTINEL_REQUIRE_USER_IDENTITY=true

ADMIN_USER=admin
ADMIN_PASSWORD=$adminPassword
ADMIN_TOTP_SECRET=$totpSecret
SENTINEL_SECRET=$sessionSecret
SENTINEL_DATA_KEY=$dataKey
INGEST_API_KEY=$ingestKey

SENTINEL_POLICY_PATH=/data/policy.json
SENTINEL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json
"@
  $encoding = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($EnvFile, "$content`n", $encoding)
  Write-Step "created $EnvFile"
}

function Invoke-Compose([string[]]$ComposeArgs) {
  Ensure-EnvFile
  Push-Location $RepoRoot
  try {
    & docker compose --env-file $EnvFile -p $ProjectName @ComposeArgs
  } finally {
    Pop-Location
  }
}

function Read-EnvValue([string]$Name) {
  Ensure-EnvFile
  $line = Get-Content -LiteralPath $EnvFile |
    Where-Object { $_ -match "^\s*$([regex]::Escape($Name))=" } |
    Select-Object -First 1
  if (-not $line) {
    return $null
  }
  return ($line -replace "^\s*$([regex]::Escape($Name))=", '').Trim()
}

function Wait-Ready {
  $url = "http://localhost:$HostPort/readyz"
  $deadline = (Get-Date).AddSeconds(60)
  do {
    try {
      $ready = Invoke-RestMethod -Uri $url -TimeoutSec 5
      if ($ready.ready -eq $true) {
        Write-Step "ready at $url"
        return
      }
    } catch {
      Start-Sleep -Seconds 2
      continue
    }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)
  throw "PromptWall did not become ready at $url"
}

function Invoke-ContainerCheck {
  Invoke-Compose @('exec', '-T', 'promptwall', 'npm', 'run', 'setup:check')
  Invoke-Compose @(
    'exec', '-T', 'promptwall', 'node', '-e',
    "const db=require('./server/db'); const out={audit:db.verifyAuditChain(), stats:db.stats()}; if(!out.audit.ok) process.exitCode=1; console.log(JSON.stringify(out,null,2));"
  )
}

function Invoke-Smoke {
  $ingestKey = Read-EnvValue 'INGEST_API_KEY'
  if (-not $ingestKey) {
    throw "INGEST_API_KEY is missing from $EnvFile"
  }

  $env:PROMPTWALL_MECHA_SMOKE_KEY = $ingestKey
  $env:PROMPTWALL_MECHA_SMOKE_PORT = [string]$HostPort
  Push-Location $RepoRoot
  try {
    & node -e @'
const key = process.env.PROMPTWALL_MECHA_SMOKE_KEY;
const port = process.env.PROMPTWALL_MECHA_SMOKE_PORT || '4027';
const body = {
  prompt: 'Synthetic member SSN 524-71-9043 for MECHA Docker smoke only.',
  destination: 'chatgpt.com',
  source: 'browser_extension',
  channel: 'submit',
  user: 'analyst@example.test',
  orgId: 'mock-mecha',
  sensor: { name: 'mecha-docker-smoke', version: 'local', platform: 'windows-docker-desktop' }
};
fetch(`http://localhost:${port}/api/v1/gate`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-api-key': key },
  body: JSON.stringify(body)
}).then(async (res) => {
  const data = await res.json();
  if (res.status !== 200) throw new Error(`Unexpected HTTP ${res.status}: ${JSON.stringify(data)}`);
  const findings = (data.findings || []).map((item) => item.type);
  if (data.decision !== 'block') throw new Error(`Expected block, got ${data.decision}`);
  if (data.status !== 'pending') throw new Error(`Expected pending, got ${data.status}`);
  if (!findings.includes('US_SSN')) throw new Error(`Expected US_SSN finding, got ${findings.join(',')}`);
  console.log(JSON.stringify({
    httpStatus: res.status,
    id: data.id,
    decision: data.decision,
    status: data.status,
    mode: data.mode,
    riskScore: data.riskScore,
    findings
  }, null, 2));
}).catch((err) => {
  console.error(err.message);
  process.exit(1);
});
'@
  } finally {
    Remove-Item Env:\PROMPTWALL_MECHA_SMOKE_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:\PROMPTWALL_MECHA_SMOKE_PORT -ErrorAction SilentlyContinue
    Pop-Location
  }
}

switch ($Command) {
  'start' {
    Invoke-Compose @('up', '-d')
    Wait-Ready
    Invoke-Compose @('ps')
  }
  'rebuild' {
    Invoke-Compose @('up', '-d', '--build')
    Wait-Ready
    Invoke-Compose @('ps')
  }
  'restart' {
    Invoke-Compose @('restart', 'promptwall')
    Wait-Ready
    Invoke-Compose @('ps')
  }
  'stop' {
    Invoke-Compose @('stop')
  }
  'status' {
    Invoke-Compose @('ps')
  }
  'check' {
    Wait-Ready
    Invoke-ContainerCheck
  }
  'smoke' {
    Wait-Ready
    Invoke-Smoke
    Invoke-ContainerCheck
  }
  'logs' {
    Invoke-Compose @('logs', '--tail', '200', 'promptwall')
  }
}
