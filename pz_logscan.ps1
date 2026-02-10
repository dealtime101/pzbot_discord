param(
  [string]$LogPath = "",
  [string]$StateDir = "",
  [int]$MaxCriticalLines = 8,
  [string]$IgnoreRegex = "",
  [string]$IgnoreFile = "",
  [int]$MaxEventHistory = 5000,
  [int]$RecentReturn = 15
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

function Load-Events([string]$p) {
  $arr = Load-Json $p @()
  if ($null -eq $arr) { return @() }
  if ($arr -is [System.Collections.IEnumerable] -and -not ($arr -is [string])) { return @($arr) }
  return @()
}

function Save-Events([string]$p, $events) {
  Save-Json $p $events
}

# Defaults (friendly)
$LogPath  = Resolve-PathOrDefault $LogPath  "PZ_CONSOLE_LOG" (Join-Path $env:USERPROFILE "Zomboid\server-console.txt")
$StateDir = Resolve-PathOrDefault $StateDir "PZ_LOGSCAN_STATE_DIR" "C:\PZ_MaintenanceLogs\PZLogScan"
$IgnoreRegex = Resolve-PathOrDefault $IgnoreRegex "PZ_LOGSCAN_IGNORE_REGEX" ""
$IgnoreFile = Resolve-PathOrDefault $IgnoreFile "PZ_LOGSCAN_IGNORE_FILE" (Join-Path $StateDir "ignore_regex.txt")

if (-not (Test-Path -LiteralPath $LogPath)) { throw "LogPath not found: $LogPath" }
if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }

# Ignore patterns: file + param
$ignorePatterns = @()

# From file (1 regex per line, ignore empty + comments)
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

# From param: ';' separated
if (-not [string]::IsNullOrWhiteSpace($IgnoreRegex)) {
  foreach ($p in ($IgnoreRegex -split ';')) {
    $pp = $p.Trim()
    if ($pp) { $ignorePatterns += $pp }
  }
}

function Is-IgnoredText([string]$text) {
  if ($ignorePatterns.Count -eq 0) { return $false }
  foreach ($pat in $ignorePatterns) {
    try { if ($text -match $pat) { return $true } } catch { continue }
  }
  return $false
}

$stateFile   = Join-Path $StateDir "state.json"
$bucketFile  = Join-Path $StateDir "buckets.json"
$eventsFile  = Join-Path $StateDir "events.json"

# state: last byte offset
$state = Load-Json $stateFile @{ offset = 0 }
if ($null -eq $state) { $state = @{ offset = 0 } }
if (-not $state.ContainsKey("offset")) { $state["offset"] = 0 }

# buckets: { "yyyyMMddHH": { warn:int, error:int, stack:int } }
$buckets = Load-Json $bucketFile @{}
if ($null -eq $buckets) { $buckets = @{} }

# events history
$events = Load-Events $eventsFile
if ($null -eq $events) { $events = @() }

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

# Timestamp: [25-01-26 12:32:55.070]
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

# ---- Signature logic ----
function Strip-Noise([string]$t) {
  if ([string]::IsNullOrWhiteSpace($t)) { return "" }

  $t = $t -replace '^\[\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?\]\s*', ''
  $t = $t -replace '^\s*LOG\s*:\s*', ''
  $t = $t -replace '^\s*ERROR\s*:\s*', 'ERROR: '
  $t = $t -replace '^\s*WARN\s*:\s*', 'WARN: '

  $t = $t -replace '^\s*General\s+f:\d+,\s*t:\d+,\s*st:[^>]+>\s*', ''
  $t = $t -replace '^\s*[^>]{0,80}>\s*', ''

  $t = ($t -replace '\s+', ' ').Trim()
  return $t
}

function Normalize-DynamicBits([string]$t) {
  if ([string]::IsNullOrWhiteSpace($t)) { return "" }
  $t = $t -replace '\b\d{1,6},\d{1,6},\d{1,3}\b', '#,#,#'
  $t = $t -replace '\b\d+\b', '#'
  $t = $t -replace '0x[0-9a-fA-F]+', '0x#'
  return $t
}

function Make-Signature([string]$type, [string]$text) {
  $t = Strip-Noise $text

  if ($type -eq "error") {
    if ($t -match '(?i)\bERROR:\s*(.+)$') { $t = "ERROR: " + $matches[1] }
    $t = Normalize-DynamicBits $t
    if ($t.Length -gt 160) { $t = $t.Substring(0,160) }
    return $t
  }

  if ($type -eq "stack") {
    $lines = $text -split "`r?`n"
    $pick = $null

    foreach ($ln in $lines) {
      $x = (Strip-Noise $ln)
      if (-not $x) { continue }
      if ($x -match '(?i)\bException thrown\b') { $pick = $x; break }
      if ($x -match '(?i)\bjava\.' ) { $pick = $x; break }
      if ($x -match '(?i)\bfunction:\b') { $pick = $x; break }
      if ($x -match '(?i)\bruntimeexception\b') { $pick = $x; break }
    }
    if (-not $pick) { $pick = Strip-Noise ($lines | Select-Object -First 1) }
    $pick = Normalize-DynamicBits $pick
    if ($pick.Length -gt 160) { $pick = $pick.Substring(0,160) }
    return "STACK: " + $pick
  }

  $t = Normalize-DynamicBits $t
  if ($t.Length -gt 160) { $t = $t.Substring(0,160) }
  return $t
}

# Counters
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

  # Ignore warn/error based on this line
  if (($isWarn -or $isError) -and (Is-IgnoredText $line)) {
    if ($isWarn)  { $ignoredCounts["warn"]++ }
    if ($isError) { $ignoredCounts["error"]++ }
    continue
  }

  if ($isWarn) {
    IncBucket $hk "warn" 1
    $newCounts["warn"]++
  }

  if ($isError) {
    IncBucket $hk "error" 1
    $newCounts["error"]++

    # critical preview
    if ($newCritical.Count -lt $MaxCriticalLines) { $newCritical.Add($line) }

    # event
    $events += [pscustomobject]@{
      ts = ($dt.ToString("o"))
      type = "error"
      signature = (Make-Signature "error" $line)
      excerpt = $(if ($line.Length -gt 600) { $line.Substring(0,600) } else { $line })
    }
  }

  if ($isStackStart) {
    # Capture stack block (~20 lines) with a bit of context
    $block = New-Object System.Collections.Generic.List[string]

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

    # ignore whole block?
    if (Is-IgnoredText $blockText) {
      $ignoredCounts["stack"]++
      continue
    }

    IncBucket $hk "stack" 1
    $newCounts["stack"]++

    if ($newCritical.Count -lt $MaxCriticalLines) { $newCritical.Add($blockText) }

    $events += [pscustomobject]@{
      ts = ($dt.ToString("o"))
      type = "stack"
      signature = (Make-Signature "stack" $blockText)
      excerpt = $(if ($blockText.Length -gt 900) { $blockText.Substring(0,900) } else { $blockText })
    }
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

function Events-InWindow([timespan]$span) {
  $from = (Get-Date).Add(-$span)
  return @($events | Where-Object {
    try { ([datetime]$_.ts) -ge $from } catch { $false }
  })
}

function Top-Signatures($evs, [int]$limit = 10) {
  $h = @{}
  foreach ($e in $evs) {
    $sig = [string]$e.signature
    if ([string]::IsNullOrWhiteSpace($sig)) { continue }
    if (-not $h.ContainsKey($sig)) { $h[$sig] = 0 }
    $h[$sig] = [int]$h[$sig] + 1
  }
  $items = @()
  foreach ($k in $h.Keys) {
    $items += [pscustomobject]@{ signature = $k; count = [int]$h[$k] }
  }
  return @($items | Sort-Object count -Descending | Select-Object -First $limit)
}

$stats1h  = Sum-Window ([timespan]::FromHours(1))
$stats24h = Sum-Window ([timespan]::FromHours(24))
$stats3d  = Sum-Window ([timespan]::FromDays(3))
$stats7d  = Sum-Window ([timespan]::FromDays(7))
$stats30d = Sum-Window ([timespan]::FromDays(30))

# prune events (keep 8 days + max history)
$cutEv = (Get-Date).AddDays(-8)
$events = @($events | Where-Object {
  try { ([datetime]$_.ts) -ge $cutEv } catch { $false }
})
if ($events.Count -gt $MaxEventHistory) { $events = @($events | Select-Object -Last $MaxEventHistory) }

$ev24 = Events-InWindow ([timespan]::FromHours(24))
$ev7d = Events-InWindow ([timespan]::FromDays(7))

$recentCritical = @($events | Sort-Object ts | Select-Object -Last $RecentReturn)
$top24 = Top-Signatures $ev24 10
$top7 = Top-Signatures $ev7d 10

# persist
Save-Json   $stateFile  $state
Save-Json   $bucketFile $buckets
Save-Events $eventsFile $events

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

  recent_critical = $recentCritical
  top_24h = $top24
  top_7d  = $top7

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
