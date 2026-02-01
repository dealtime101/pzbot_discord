# run_bot_watchdog.ps1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Python    = "C:\Program Files\Python314\python.exe"
$BotScript = "C:\PZServerBuild42\discord_bot.py"

$LogDir = "C:\PZServerBuild42\logs"
$RunLog = Join-Path $LogDir "pz_bot_watchdog.log"
$StdOut = Join-Path $LogDir "pz_bot_stdout.log"
$StdErr = Join-Path $LogDir "pz_bot_stderr.log"

$MutexName = "Global\PZBotWatchdogMutex"

function Log([string]$msg) {
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  Add-Content -LiteralPath $RunLog -Value "[$ts] $msg" -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $LogDir)) {
  New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Log ("Watchdog started as user: {0}" -f [Environment]::UserName)
Log "Python=$Python"
Log "Script=$BotScript"

# ---- Mutex (avoid double watchdog) ----
$createdNew = $false
$mutex = New-Object System.Threading.Mutex($false, $MutexName, [ref]$createdNew)

if (-not $createdNew) {
  Log "Another watchdog already running. Exiting."
  exit 0
}

try {
  while ($true) {
    Log "Starting PZBot..."
    Log "Cmd: `"$Python`" -X faulthandler `"$BotScript`""

    # Start-Process avoids PowerShell treating stderr as an error record
    $p = Start-Process -FilePath $Python `
      -ArgumentList @("-X","faulthandler", $BotScript) `
      -WorkingDirectory (Split-Path -Parent $BotScript) `
      -RedirectStandardOutput $StdOut `
      -RedirectStandardError  $StdErr `
      -PassThru

    $p.WaitForExit()
    $code = $p.ExitCode

    Log "PZBot exited with code=$code"

    # quick backoff to prevent tight crash loops
    Start-Sleep -Seconds 5
  }
}
finally {
  try { $mutex.ReleaseMutex() | Out-Null } catch {}
  $mutex.Dispose()
}
