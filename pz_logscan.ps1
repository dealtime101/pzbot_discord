param(
  [string]$LogPath = "",
  [string]$StateDir = "",
  [int]$MaxCriticalLines = 8,
  [string]$IgnoreRegex = "",
  [string]$IgnoreFile = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Resolve-PathOrDefault([string]$value, [string]$envName, [string]$defaultValue) {
  if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
  $e = [Environment]::GetEnvironmentVariable($envName, "Process")
  if ([string]::IsNullOrWhiteSpace($e)) { $e = [Environment]::GetEnvironmentVariable($envName, "Machine") }
  if (-not [string]::IsNullOrWhiteSpace($e)) { return $e }
  return $defaultValue
}

function ConvertTo-HashtableRecursive($obj) {
  if ($null -eq $obj) { return $null }

  if ($obj -is [System.Collections.IDictionary]) {
    $ht = @{}
    foreach ($k in $obj.Keys) { $ht[$k] = ConvertTo-HashtableRecursive $obj[$k] }
    return $ht
  }

  if ($obj -is [System.Collections.IEnumerable] -and -not ($obj -is [string])) {
    $arr = @()
    foreach ($item in $obj) { $arr += (ConvertTo-HashtableRecursive $item) }
    return $arr
  }

  if ($obj -is [pscustomobject]) {
    $ht = @{}
    foreach ($p in $obj.PSObject.Properties) { $ht[$p.Name] = ConvertTo-HashtableRecursive $p.Value }
    return $ht
  }

  return $obj
}

function Load-Json([string]$p, $fallback) {
  if (Test-Path -LiteralPath $p) {
    try {
      $raw = Get-Content -LiteralPath $p -Raw -Encoding UTF8
      if ([string]::IsNullOrWhiteSpace($raw)) { return $fallback }
      return (ConvertTo-HashtableRecursive ($raw | ConvertFrom-Json))
    } catch { return $fallback }
  }
  return $fallback
}

function Save-Json([string]$p, $obj) {
  $obj | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $p -Encoding UTF8
}

# Defaults "friendly user"
$LogPath  = Resolve-PathOrDefault $LogPath  "PZ_CONSOLE_LOG" (Join-Path $env:USERPROFILE "Zomboid\server-console.txt")
$StateDir = Resolve-PathOrDefault $StateDir "PZ_LOGSCAN_STATE_DIR" "C:\PZ_MaintenanceLogs\PZLogScan"
$IgnoreRegex = Resolve-PathOrDefault $IgnoreRegex "PZ_LOGSCAN_IGNORE_REGEX" ""
$IgnoreFile = Resolve-PathOrDefault $IgnoreFile "PZ_LOGSCAN_IGNORE_FILE" (Join-Path $StateDir "ignore_regex.txt")

if (-not (Test-Path -LiteralPath $LogPath)) { throw "LogPath not found: $LogPath" }
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

# Ignore patterns: (file + param)
$ignorePatterns = @()

# From file: 1 regex per line (ignore empty + comments)
if (-not [string]::IsNullOrWhiteSpace($IgnoreFile) -and (Test-Path -LiteralPath $IgnoreFile)) {
  try {
    $lines = Get-Content -LiteralPath $IgnoreFile -Encoding UTF8
    foreach ($ln in $lines) {
      $t = ($ln + "").Trim()
      if (-not $t) { continue }
      if ($t.StartsWith("#")) { continue }
      $ignorePatterns += $t
    }
  } catch {
    # don't break scanning
  }
}

# From param: multiple regex separated by ';'
if (-not [string]::IsNullOrWhiteSpace($IgnoreRegex)) {
  foreach ($p in ($IgnoreRegex -split ';')) {
    $pp = $p.Trim()
    if ($pp) { $ignorePatterns += $pp }
  }
}

function Is-IgnoredText([string]$text) {
  if ($ignorePatterns.Count -eq 0) { return $false }
  foreach ($pat in $ignorePatterns) {
    try {
      if ($text -match $pat) { return $true }
    } catch {
      continue
    }
  }
  return $false
}

$stateFile  = Join-Path $StateDir "state.json"
$bucketFile = Join-Path $StateDir "buckets.json"

# state: last byte offset
$state = Load-Json $stateFile @{ offset = 0 }
if ($null -eq $state) { $state = @{ offset = 0 } }
if (-not $state.ContainsKey("offset")) { $state["offset"] = 0 }

# buckets: { "yyyyMMddHH": { warn:int, error:int, stack:int } }
$buckets = Load-Json $bucketFile @{}
if ($null -eq $buckets) { $buckets = @{} }

# Handle truncation
$fi = Get-Item -LiteralPath $LogPath
if ($fi.Length -lt [int64]$state["offset"]) { $state["offset"] = 0 }

# Read new bytes
$fs = [System.IO.File]::Open($LogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$newLines = New-Object System.Collections.Generic.List[string]
try {
  $fs.Seek([int64]$state["offset"], [System.IO.SeekOrigin]::Begin) | Out-Null
  $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8, $true, 4096, $true)
  while (-not $sr.EndOfStream) {
    $line = $sr.ReadLine()
    if ($null -ne $line) { $newLines.Add($line) }
  }
  $state["offset"] = $fs.Position
}
finally { $fs.Dispose() }

# PZ console timestamp: [25-01-26 12:32:55.070]
$tsRe = [regex]'^\[(\d{2})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?\]'

function Parse-Timestamp([string]$line) {
  $m = $tsRe.Match($line)
  if (-not $m.Success) { return $null }
  $yy = [int]$m.Groups[1].Value
  $MM = [int]$m.Groups[2].Value
  $dd = [int]$m.Groups[3].Value
  $HH = [int]$m.Groups[4].Value
  $mm = [int]$m.Groups[5].Value
  $ss = [int]$m.Groups[6].Value
  $fff = 0
  if ($m.Groups[7].Success) {
    $fffStr = $m.Groups[7].Value
    if ($fffStr.Length -eq 1) { $fff = [int]($fffStr + "00") }
    elseif ($fffStr.Length -eq 2) { $fff = [int]($fffStr + "0") }
    else { $fff = [int]$fffStr }
  }
  $year = 2000 + $yy
  try { return [datetime]::new($year, $MM, $dd, $HH, $mm, $ss, $fff) } catch { return $null }
}

function HourKey([datetime]$dt) { $dt.ToString("yyyyMMddHH") }

function EnsureBucket([string]$k) {
  if (-not $buckets.ContainsKey($k)) {
    $buckets[$k] = @{ warn = 0; error = 0; stack = 0 }
  } else {
    if (-not ($buckets[$k] -is [System.Collections.IDictionary])) {
      $buckets[$k] = ConvertTo-HashtableRecursive $buckets[$k]
    }
    foreach ($key in @("warn","error","stack")) {
      if (-not $buckets[$k].ContainsKey($key)) { $buckets[$k][$key] = 0 }
    }
  }
}

function IncBucket([string]$k, [string]$field, [int]$delta = 1) {
  EnsureBucket $k
  $buckets[$k][$field] = [int]$buckets[$k][$field] + $delta
}

# Counts
$newCritical = New-Object System.Collections.Generic.List[string]
$newCounts = @{ warn = 0; error = 0; stack = 0 }
$ignoredCounts = @{ warn = 0; error = 0; stack = 0 }

$now = Get-Date

function Is-NewEntryLine([string]$line) { return ($tsRe.IsMatch($line)) }

for ($i = 0; $i -lt $newLines.Count; $i++) {
  $line = $newLines[$i]
  $upper = $line.ToUpperInvariant()

  $isWarn  = $upper -match '\bWARN\b'
  $isStackStart = ($upper -match 'STACK TRACE') -or ($upper -match 'STACKTRACE')
  $isError = (-not $isStackStart) -and ($upper -match '\bERROR\b')

  if (-not ($isWarn -or $isError -or $isStackStart)) { continue }

  $dt = Parse-Timestamp $line
  if ($null -eq $dt) { $dt = $now }
  $hk = HourKey $dt

  # Ignore warn/error on the line itself
  if (($isWarn -or $isError) -and (Is-IgnoredText $line)) {
    if ($isWarn)  { $ignoredCounts["warn"]++ }
    if ($isError) { $ignoredCounts["error"]++ }
    continue
  }

  if ($isWarn)  { IncBucket $hk "warn"  1; $newCounts["warn"]++ }

  if ($isError) {
    IncBucket $hk "error" 1
    $newCounts["error"]++
    if ($newCritical.Count -lt $MaxCriticalLines) { $newCritical.Add($line) }
  }

  if ($isStackStart) {
    # Capture stack block (~20 lines)
    $block = New-Object System.Collections.Generic.List[string]

    # include up to 2 previous non-entry lines as context
    for ($b = 2; $b -ge 1; $b--) {
      $pi = $i - $b
      if ($pi -ge 0) {
        $prev = $newLines[$pi]
        if (-not (Is-NewEntryLine $prev)) { $block.Add($prev) }
      }
    }

    $block.Add($line)

    $maxFollow = 20
    for ($j = 1; $j -le $maxFollow; $j++) {
      $k = $i + $j
      if ($k -ge $newLines.Count) { break }
      $next = $newLines[$k]
      if (Is-NewEntryLine $next) { break }
      $block.Add($next)
    }

    # skip consumed lines
    $i = $i + ($block.Count - 1)

    $blockText = ($block -join "`n")

    if (Is-IgnoredText $blockText) {
      $ignoredCounts["stack"]++
      continue
    }

    IncBucket $hk "stack" 1
    $newCounts["stack"]++

    if ($newCritical.Count -lt $MaxCriticalLines) { $newCritical.Add($blockText) }
  }
}

# cleanup old buckets > 35 days
$cutoff = (Get-Date).AddDays(-35)
foreach ($k in @($buckets.Keys)) {
  if ($k -match '^\d{10}$') {
    $dt = [datetime]::ParseExact($k, "yyyyMMddHH", $null)
    if ($dt -lt $cutoff) { $buckets.Remove($k) | Out-Null }
  }
}

function Sum-Window([timespan]$span) {
  $from = (Get-Date).Add(-$span)
  $sum = @{ warn = 0; error = 0; stack = 0 }
  foreach ($k in $buckets.Keys) {
    if ($k -notmatch '^\d{10}$') { continue }
    $dt = [datetime]::ParseExact($k, "yyyyMMddHH", $null)
    if ($dt -ge $from) {
      $sum["warn"]  += [int]$buckets[$k]["warn"]
      $sum["error"] += [int]$buckets[$k]["error"]
      $sum["stack"] += [int]$buckets[$k]["stack"]
    }
  }
  return $sum
}

$stats1h  = Sum-Window ([timespan]::FromHours(1))
$stats24h = Sum-Window ([timespan]::FromHours(24))
$stats3d  = Sum-Window ([timespan]::FromDays(3))
$stats7d  = Sum-Window ([timespan]::FromDays(7))
$stats30d = Sum-Window ([timespan]::FromDays(30))

# persist
Save-Json $stateFile  $state
Save-Json $bucketFile $buckets

# output JSON
$out = @{
  log_path = $LogPath
  scanned_new_lines = $newLines.Count
  new_warn  = $newCounts["warn"]
  new_error = $newCounts["error"]
  new_stack = $newCounts["stack"]
  new_critical_count = ($newCounts["error"] + $newCounts["stack"])
  new_critical_lines = $newCritical
  stats_1h  = $stats1h
  stats_24h = $stats24h
  stats_3d  = $stats3d
  stats_7d  = $stats7d
  stats_30d = $stats30d
  timestamp = (Get-Date).ToString("o")
  ignored_warn  = $ignoredCounts["warn"]
  ignored_error = $ignoredCounts["error"]
  ignored_stack = $ignoredCounts["stack"]
  ignored_total = ($ignoredCounts["warn"] + $ignoredCounts["error"] + $ignoredCounts["stack"])
  ignore_file   = $IgnoreFile
  ignore_regex  = (($ignorePatterns | Select-Object -Unique) -join ";")
}

$out | ConvertTo-Json -Depth 10
exit 0
