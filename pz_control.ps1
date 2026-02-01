# pz_control.ps1
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("save","stop","start","restart","status")]
  [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---- Paths / settings ----
$Base = "C:\PZServerBuild42"
$StartBat = Join-Path $Base "StartServer64.bat"
$WorkDir  = $Base

# how to detect the server
function Get-PZServerProcess {
  # Heuristic: java.exe with "zombie.network.GameServer" in cmdline
  Get-CimInstance Win32_Process |
    Where-Object {
      $_.Name -match '^java(\.exe)?$' -and
      $_.CommandLine -match 'zombie\.network\.GameServer'
    }
}

function Write-Out([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { $s = "(no output)" }
  Write-Output $s
}

switch ($Action) {

  "status" {
    $p = Get-PZServerProcess
    if ($null -ne $p) { Write-Out "RUNNING"; exit 0 }
    Write-Out "STOPPED"; exit 0
  }

  "start" {
    if (-not (Test-Path -LiteralPath $StartBat)) {
      Write-Out "ERROR: StartServer64.bat not found: $StartBat"
      exit 2
    }

    $p = Get-PZServerProcess
    if ($null -ne $p) {
      Write-Out "RUNNING"
      exit 0
    }

    Start-Process -FilePath $StartBat -WorkingDirectory $WorkDir | Out-Null
    Start-Sleep -Seconds 2

    $p2 = Get-PZServerProcess
    if ($null -ne $p2) { Write-Out "LAUNCHED"; exit 0 }

    Write-Out "LAUNCH_FAILED"
    exit 2
  }

  "stop" {
    $p = Get-PZServerProcess
    if ($null -eq $p) {
      Write-Out "STOPPED"
      exit 0
    }

    # soft stop attempt
    foreach ($proc in $p) {
      try {
        Stop-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
      } catch {}
    }

    Start-Sleep -Seconds 3
    $p2 = Get-PZServerProcess
    if ($null -eq $p2) {
      Write-Out "STOPPED"
      exit 0
    }

    # force stop
    foreach ($proc in $p2) {
      try { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
    }

    Start-Sleep -Seconds 1
    $p3 = Get-PZServerProcess
    if ($null -eq $p3) { Write-Out "STOPPED"; exit 0 }

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
    # Placeholder: implement your actual RCON save here if you have it.
    # If server is down, answer STOPPED to be clean.
    $p = Get-PZServerProcess
    if ($null -eq $p) { Write-Out "STOPPED"; exit 0 }

    # TODO: Replace with actual save mechanism (RCON)
    Write-Out "OK"
    exit 0
  }
}
