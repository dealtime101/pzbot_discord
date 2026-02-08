# pz_control.ps1 (PS 5.1)
# Actions: status | players | save | start | stop | restart | say
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("status","players","save","start","stop","restart","say")]
  [string]$Action,

  [string]$Message = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function EnvOr([string]$name, [string]$fallback) {
  $v = [Environment]::GetEnvironmentVariable($name, "Process")
  if ([string]::IsNullOrWhiteSpace($v)) { $v = [Environment]::GetEnvironmentVariable($name, "Machine") }
  if ([string]::IsNullOrWhiteSpace($v)) { return $fallback }
  return $v.Trim()
}

$ServerRoot = EnvOr "PZ_SERVER_ROOT" "C:\PZServerBuild42"
$StartBat   = EnvOr "PZ_START_BAT"   (Join-Path $ServerRoot "StartServer64.bat")

$RconHost = EnvOr "PZ_RCON_HOST" "127.0.0.1"
$RconPort = [int](EnvOr "PZ_RCON_PORT" "27015")
$RconPass = EnvOr "PZ_RCON_PASSWORD" ""

$McrconExe = EnvOr "PZ_MCRCON_EXE" (Join-Path $ServerRoot "mcrcon.exe")

function Get-PZProcess {
  $procs = Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction SilentlyContinue
  foreach ($p in $procs) {
    try {
      if ($p.CommandLine -and ($p.CommandLine -match "zombie\.network\.GameServer")) { return $p }
    } catch {}
  }
  return $null
}

function Invoke-Rcon([string]$cmd) {
  if ([string]::IsNullOrWhiteSpace($RconPass)) {
    throw "PZ_RCON_PASSWORD is missing (cannot run rcon command: $cmd)"
  }
  if (-not (Test-Path -LiteralPath $McrconExe)) {
    throw "mcrcon.exe not found at: $McrconExe (set PZ_MCRCON_EXE)"
  }

  $args = @(
    "-H", $RconHost,
    "-P", "$RconPort",
    "-p", $RconPass,
    $cmd
  )

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $McrconExe
  $psi.Arguments = ($args -join " ")
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  return ($stdout + "`n" + $stderr).Trim()
}

function Status-Text {
  $proc = Get-PZProcess
  if ($null -eq $proc) {
    return "STOPPED players=?"
  }

  $players = "?"
  try {
    $resp = Invoke-Rcon "players"
    if ($resp) {
      $names = @($resp -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
      $players = "$($names.Count)"
    }
  } catch { }

  return "RUNNING players=$players"
}

function Players-Text {
  $proc = Get-PZProcess
  if ($null -eq $proc) { return "STOPPED" }

  try {
    $resp = Invoke-Rcon "players"
    $names = @($resp -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($names.Count -eq 0) { return "(none)" }
    return ($names -join "`n")
  } catch {
    return "(none)"
  }
}

function Start-Server {
  if (-not (Test-Path -LiteralPath $StartBat)) {
    throw "Start script not found: $StartBat (set PZ_START_BAT)"
  }
  $proc = Get-PZProcess
  if ($proc) { return "Already running" }

  Start-Process -FilePath $StartBat -WorkingDirectory (Split-Path -Parent $StartBat) | Out-Null
  Start-Sleep -Seconds 2
  return "Start initiated"
}

function Stop-Server {
  $proc = Get-PZProcess
  if (-not $proc) { return "Already stopped" }

  try { [void](Invoke-Rcon "quit") } catch {}
  Start-Sleep -Seconds 2

  $proc = Get-PZProcess
  if ($proc) {
    Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
  }
  return "Stop initiated"
}

function Save-World {
  $proc = Get-PZProcess
  if (-not $proc) { return "STOPPED" }

  try { [void](Invoke-Rcon "save") } catch {}
  return "Save triggered"
}

function Say-Server([string]$msg) {
  $proc = Get-PZProcess
  if (-not $proc) { return "STOPPED" }
  if ([string]::IsNullOrWhiteSpace($msg)) { return "Message empty" }

  $safe = $msg.Replace('"','\"')
  try { [void](Invoke-Rcon "servermsg ""$safe""") } catch {}
  return "Message sent"
}

switch ($Action) {
  "status"  { Status-Text; exit 0 }
  "players" { Players-Text; exit 0 }
  "save"    { Save-World; exit 0 }
  "start"   { Start-Server; exit 0 }
  "stop"    { Stop-Server; exit 0 }
  "restart" { [void](Stop-Server); Start-Sleep -Seconds 2; Start-Server; exit 0 }
  "say"     { Say-Server $Message; exit 0 }
}
