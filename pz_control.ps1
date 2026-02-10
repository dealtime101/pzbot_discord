# pz_control.ps1 (PS 5.1)
# Actions: status | players | save | start | stop | restart | say
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("save","stop","start","restart","status","players","say")]
  [string]$Action,

  [string]$Message = ""
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
  if (-not (Test-Path -LiteralPath $ini)) {
    throw "Server ini not found: $ini"
  }

  $port = 27015
  $pass = ""

  $lines = Get-Content -LiteralPath $ini -ErrorAction Stop
  foreach ($l in $lines) {
    if ($l -match '^\s*RCONPort\s*=\s*(\d+)\s*$') { $port = [int]$matches[1] ; continue }
    if ($l -match '^\s*RCONPassword\s*=\s*(.+?)\s*$') { $pass = $matches[1].Trim() ; continue }
  }

  if ([string]::IsNullOrWhiteSpace($pass)) {
    throw "RCONPassword is empty in $ini"
  }

  return @{
    Port = $port
    Pass = $pass
    Ini  = $ini
  }
}

function Invoke-Mcrcon([string]$command) {
  if (-not (Test-Path -LiteralPath $McrconExe)) {
    throw "mcrcon.exe not found: $McrconExe"
  }

  $rc = Get-RconConfig
  $port = $rc.Port
  $pass = $rc.Pass

  # NOTE: mcrcon works for sending but returns empty output for PZ B42 on some setups.
  # We still run it and trust exit code.
  $out = & $McrconExe -H 127.0.0.1 -P $port -p $pass $command 2>&1
  $code = $LASTEXITCODE

  if ($code -ne 0) {
    $msg = ($out | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = "mcrcon exit code $code" }
    throw $msg
  }

  return ($out | Out-String).Trim()
}

# ===== Console-based player detection (works even when mcrcon output is empty) =====
function Get-ConsoleLogPath {
  $userHome = Get-UserHomeFromStartBat $StartBat
  return (Join-Path $userHome "Zomboid\server-console.txt")
}

function Get-ConsoleTail([string]$path, [int]$tail = 5000) {
  if (-not (Test-Path $path)) { return @() }
  try {
    return Get-Content -Path $path -Tail $tail -ErrorAction Stop
  } catch {
    return @()
  }
}

function Get-ActiveGuidsFromConsole([string]$consolePath) {
  $lines = Get-ConsoleTail $consolePath 7000
  if ($lines.Count -eq 0) { return @() }

  # Keep last known state per guid
  $lastState = @{}  # guid -> string

  foreach ($line in $lines) {
    if ($line -notmatch 'guid=(\d+)') { continue }
    $guid = $matches[1]

    # 1) Fully connected is the strongest signal
    if ($line -match '\[fully-connected\]') {
      $lastState[$guid] = "connected"
      continue
    }

    # 2) player-connect packet also indicates active player
    if ($line -match '\[receive-packet\]\s+"player-connect"') {
      $lastState[$guid] = "connected"
      continue
    }

    # 3) disconnect/closed/lost patterns
    if ($line -match '(?i)(disconnect|disconnected|connection-lost|lost-connection|closed|close-connection)') {
      $lastState[$guid] = "disconnected"
      continue
    }

    # 4) Other connection phases (don’t count as active)
    if ($line -match '\[RakNet\]\s+"new-incoming-connection"') {
      if (-not $lastState.ContainsKey($guid)) { $lastState[$guid] = "pending" }
      continue
    }
  }

  $active = @()
  foreach ($k in $lastState.Keys) {
    if ($lastState[$k] -eq "connected") { $active += $k }
  }

  return ($active | Sort-Object -Unique)
}

function Get-PlayersCountFromConsole([string]$consolePath) {
  $guids = @(Get-ActiveGuidsFromConsole $consolePath)
  return $guids.Count
}

function Get-PlayersListFromConsole([string]$consolePath) {
  $guids = @(Get-ActiveGuidsFromConsole $consolePath)
  if ($guids.Count -eq 0) { return @() }

  # We don’t have names in your log sample; show GUIDs for now.
  return ($guids | ForEach-Object { "guid=$_" })
}

# ===== Actions =====
switch ($Action) {

  "status" {
    $proc = Get-PZServerProcess
    if ($null -eq $proc) { Write-Out "STOPPED | players=0"; exit 0 }

    $console = Get-ConsoleLogPath
    $pc = Get-PlayersCountFromConsole $console
    Write-Out ("RUNNING | players={0}" -f $pc)
    exit 0
  }

"players" {
  $proc = Get-PZServerProcess
  if ($null -eq $proc) { Write-Out "STOPPED"; exit 0 }

  $rc = Get-RconConfig
  $port = $rc.Port
  $pass = $rc.Pass

  $py = $env:PZ_PYTHON
  if ([string]::IsNullOrWhiteSpace($py)) { $py = "python" }

  $rconPy = Join-Path $Base "pz_rcon.py"
  if (-not (Test-Path -LiteralPath $rconPy)) {
    Write-Out "ERROR: pz_rcon.py not found: $rconPy"
    exit 2
  }

  $out = & $py $rconPy --port $port --password $pass --cmd "players" 2>&1
  $txt = ($out | Out-String).Trim()

  if ([string]::IsNullOrWhiteSpace($txt)) { Write-Out "(none)"; exit 0 }
  Write-Output $txt
  exit 0
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

    try {
      # Common PZ server command: "save"
      [void](Invoke-Mcrcon "save")
      Write-Out "OK"
      exit 0
    } catch {
      Write-Out ("ERROR: " + $_.Exception.Message)
      exit 2
    }
  }

  "say" {
    $proc = Get-PZServerProcess
    if ($null -eq $proc) { Write-Out "STOPPED"; exit 0 }

    if ([string]::IsNullOrWhiteSpace($Message)) {
      Write-Out "ERROR: Message is required"
      exit 2
    }

    $msg = $Message.Replace('"','\"')

    try {
      [void](Invoke-Mcrcon "servermsg `"$msg`"")
      Write-Out "OK"
      exit 0
    } catch {
      Write-Out ("ERROR: " + $_.Exception.Message)
      exit 2
    }
  }
}
