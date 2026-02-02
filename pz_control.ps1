# pz_control.ps1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("save","stop","start","restart","status","players")]
  [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===== Base / paths =====
$Base = $env:PZ_BASE_DIR
if ([string]::IsNullOrWhiteSpace($Base)) { $Base = "C:\PZServerBuild42" }

$StartBat = Join-Path $Base "StartServer64.bat"
$WorkDir  = $Base

# ===== mcrcon =====
$McrconExe = $env:PZ_MCRCON_EXE
if ([string]::IsNullOrWhiteSpace($McrconExe)) {
  $McrconExe = Join-Path $Base "tools\mcrcon.exe"
}

$RconHost = $env:PZ_RCON_HOST
if ([string]::IsNullOrWhiteSpace($RconHost)) { $RconHost = "127.0.0.1" }

function Write-Out([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { $s = "(no output)" }
  Write-Output $s
}

function Get-PZServerProcess {
  Get-CimInstance Win32_Process |
    Where-Object {
      $_.Name -match '^java(\.exe)?$' -and
      $_.CommandLine -match 'zombie\.network\.GameServer'
    }
}

function Get-UserHomeFromStartBat([string]$StartBatPath) {
  $fallback = Join-Path $Base "hh_saves"
  if (-not (Test-Path -LiteralPath $StartBatPath)) { return $fallback }

  try { $txt = Get-Content -LiteralPath $StartBatPath -Raw -ErrorAction Stop } catch { return $fallback }

  if ($txt -match '-Duser\.home\s*=\s*"([^"]+)"') {
    $p = $matches[1].Trim()
    if (-not [string]::IsNullOrWhiteSpace($p)) { return $p }
  }

  return $fallback
}

function Get-ServerIniPath {
  $userHome = Get-UserHomeFromStartBat $StartBat
  Join-Path $userHome "Zomboid\Server\servertest.ini"
}

function Get-RconConfig {
  $ini = Get-ServerIniPath
  if (-not (Test-Path -LiteralPath $ini)) { return $null }

  $port = $null
  $pass = $null
  foreach ($line in (Get-Content -LiteralPath $ini -ErrorAction Stop)) {
    if ($line -match '^\s*RCONPort\s*=\s*(\d+)\s*$')      { $port = [int]$matches[1]; continue }
    if ($line -match '^\s*RCONPassword\s*=\s*(.+?)\s*$') { $pass = $matches[1].Trim(); continue }
  }

  if ($null -eq $port -or [string]::IsNullOrWhiteSpace($pass)) { return $null }
  [pscustomobject]@{ Port = $port; Pass = $pass }
}

# Interactive mcrcon (stdin) so output is reliably captured
function Invoke-Mcrcon([string]$Command) {
  if (-not (Test-Path -LiteralPath $McrconExe)) {
    throw "mcrcon.exe not found: $McrconExe (set PZ_MCRCON_EXE or place it under $Base\tools\mcrcon.exe)"
  }

  $cfg = Get-RconConfig
  if ($null -eq $cfg) {
    throw "RCONPort/RCONPassword not found in $(Get-ServerIniPath)"
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $McrconExe
  $psi.Arguments = "-H $RconHost -P $($cfg.Port) -p `"$($cfg.Pass)`""
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput  = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi

  if (-not $p.Start()) { throw "Unable to start mcrcon.exe" }

  $p.StandardInput.WriteLine($Command)
  $p.StandardInput.WriteLine("exit")
  $p.StandardInput.Flush()
  $p.StandardInput.Close()

  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit(5000) | Out-Null

  $out = (($stdout + "`n" + $stderr) -replace "`r","").Trim()
  if ($out -match '(?i)\bconnection failed\b') {
    throw "Connection failed (RCON host/port/pass?)"
  }
  return $out
}

function Extract-PlayersFromOutput([string]$raw) {
  if ([string]::IsNullOrWhiteSpace($raw)) { return @() }

  $lines = $raw -split "`n" |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" }

  # Remove headers/noise
  $lines = $lines | Where-Object {
    $_ -notmatch '^(?i)(players connected|connected players|players online|online players|usage|help|authenticated|connecting|mcrcon|>)\b'
  }

  $names = New-Object System.Collections.Generic.List[string]

  foreach ($l in $lines) {
    $s = $l.Trim()

    # PZ format: "-name"
    $s = $s -replace '^\-+\s*', ''

    # Strip list index "1. Name"
    if ($s -match '^\s*\d+\s*[\.\)\-:]\s*(.+)$') { $s = $matches[1].Trim() }

    # Keep name before extra info
    $s = ($s -split '\s+\(|\s+\[|\s+-\s+|\s+steamid\s*[:=]\s*', 2)[0].Trim()

    if ($s -match '^[A-Za-z0-9_\-\.]{2,32}$') {
      $names.Add($s)
    }
  }

  @($names.ToArray() | Sort-Object -Unique)
}

function Get-PlayersViaRcon {
  $raw = Invoke-Mcrcon "players"
  $players = Extract-PlayersFromOutput $raw
  @($players)
}

switch ($Action) {

  "status" {
    $proc = Get-PZServerProcess
    if ($null -eq $proc) { Write-Out "STOPPED | players=0"; exit 0 }

    try {
      $players = @(Get-PlayersViaRcon)
      Write-Out ("RUNNING | players={0}" -f $players.Count)
    } catch {
      Write-Out "RUNNING | players=?"
    }
    exit 0
  }

  "players" {
    $proc = Get-PZServerProcess
    if ($null -eq $proc) { Write-Out "STOPPED"; exit 0 }

    try {
      $players = @(Get-PlayersViaRcon)
      if ($players.Count -eq 0) { Write-Out "(none)"; exit 0 }
      $players | ForEach-Object { Write-Output $_ }
      exit 0
    } catch {
      Write-Out ("ERROR: " + $_.Exception.Message)
      exit 2
    }
  }

  "start" {
    if (-not (Test-Path -LiteralPath $StartBat)) {
      Write-Out "ERROR: StartServer64.bat not found: $StartBat"
      exit 2
    }

    $proc = Get-PZServerProcess
    if ($null -ne $proc) { Write-Out "RUNNING"; exit 0 }

    Start-Process -FilePath $StartBat -WorkingDirectory $WorkDir | Out-Null
    Start-Sleep -Seconds 2

    $proc2 = Get-PZServerProcess
    if ($null -ne $proc2) { Write-Out "LAUNCHED"; exit 0 }

    Write-Out "LAUNCH_FAILED"
    exit 2
  }

  "stop" {
    $proc = Get-PZServerProcess
    if ($null -eq $proc) { Write-Out "STOPPED"; exit 0 }

    foreach ($p in $proc) {
      try { Stop-Process -Id $p.ProcessId -ErrorAction SilentlyContinue } catch {}
    }

    Start-Sleep -Seconds 3
    $proc2 = Get-PZServerProcess
    if ($null -eq $proc2) { Write-Out "STOPPED"; exit 0 }

    foreach ($p in $proc2) {
      try { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
    }

    Start-Sleep -Seconds 1
    $proc3 = Get-PZServerProcess
    if ($null -eq $proc3) { Write-Out "STOPPED"; exit 0 }

    Write-Out "STOP_FAILED"
    exit 2
  }

  "restart" {
    & $PSCommandPath -Action stop | Out-Null
    Start-Sleep -Seconds 1
    & $PSCommandPath -Action start
    exit $LASTEXITCODE
  }

  "save" {
    $proc = Get-PZServerProcess
    if ($null -eq $proc) { Write-Out "STOPPED"; exit 0 }
    Write-Out "OK"
    exit 0
  }
}
