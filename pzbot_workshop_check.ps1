# pzbot_workshop_check.ps1 (PS 5.1 compatible)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ====== CONFIG ======
$AppId = 108600
$IniPath = "C:\PZServerBuild42\hh_saves\Zomboid\Server\servertest.ini"
$WorkshopContentRoot = "C:\PZServerBuild42\steamapps\workshop\content\108600"

# Logs (OK to purge)
$LogDir = "C:\PZServerBuild42\logs"
$LogPath = Join-Path $LogDir "workshop-check.log"
$LockPath = Join-Path $LogDir "workshop-check.lock"

# State (DO NOT purge)
$StateDir = "C:\PZServerBuild42\state"
$StatePath = Join-Path $StateDir "workshop-webhook-state.json"

# Webhook display identity (prevents "servertest" / server name from showing)
$WebhookUsername = [string]$env:DISCORD_WEBHOOK_USERNAME
if ($null -eq $WebhookUsername -or [string]::IsNullOrWhiteSpace($WebhookUsername)) { $WebhookUsername = "PZBot" }
$WebhookUsername = $WebhookUsername.Trim()

# Optional: role mention string like "<@&ROLE_ID>" or "@here" or ""
$DiscordPingOnUpdate = [string]$env:DISCORD_PING_ON_UPDATE
if ($null -eq $DiscordPingOnUpdate) { $DiscordPingOnUpdate = "" }
$DiscordPingOnUpdate = $DiscordPingOnUpdate.Trim()

# Optional: Restrict allowed_mentions to a specific role id (safer).
# You can also provide it via env: DISCORD_PING_ROLE_ID
$PingRoleId = [string]$env:DISCORD_PING_ROLE_ID
if ($null -eq $PingRoleId -or [string]::IsNullOrWhiteSpace($PingRoleId)) {
  $PingRoleId = "1465913550730952726"  # default fallback
}
$PingRoleId = ($PingRoleId -replace "\D","").Trim()


# ====== HELPERS ======
function Ensure-Dir([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Write-Log([string]$Message) {
  Ensure-Dir $LogDir
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  try {
    Add-Content -LiteralPath $LogPath -Value "[$ts] $Message" -Encoding UTF8
  } catch {
    Write-Host "LOGFAIL: $Message"
  }
}

function Get-WebhookParts([string]$Url) {
  $Url = ($Url -replace "[`r`n`t ]", "").Trim()
  if ($Url -notmatch "/webhooks/(\d+)/([^/?]+)") { throw "Invalid webhook url format." }
  return @{ id = $matches[1]; token = $matches[2].Trim() }
}

function Read-State {
  Write-Log ("STATE PATH: {0}" -f $StatePath)

  if (-not (Test-Path -LiteralPath $StatePath)) {
    Write-Log "STATE: file missing"
    return @{ check=$null; details=$null }
  }

  try {
    $rawText = Get-Content -LiteralPath $StatePath -Raw
    Write-Log ("STATE RAW: {0}" -f ($rawText -replace "`r?`n"," "))

    $obj = $rawText | ConvertFrom-Json

    $check = $null
    $details = $null

    if ($obj.PSObject.Properties.Name -contains "check")   { $check = [string]$obj.check }
    if ($obj.PSObject.Properties.Name -contains "details") { $details = [string]$obj.details }

    # Backward compatibility
    if (-not $check -and ($obj.PSObject.Properties.Name -contains "check_message_id")) {
      $check = [string]$obj.check_message_id
    }
    if (-not $details -and ($obj.PSObject.Properties.Name -contains "details_message_id")) {
      $details = [string]$obj.details_message_id
    }

    if ([string]::IsNullOrWhiteSpace($check)) { $check = $null }
    if ([string]::IsNullOrWhiteSpace($details)) { $details = $null }

    Write-Log ("STATE PARSED: check='{0}' details='{1}'" -f $check, $details)
    return @{ check=$check; details=$details }
  }
  catch {
    Write-Log ("STATE READ ERROR: {0}" -f $_.Exception.Message)
    return @{ check=$null; details=$null }
  }
}

function Write-State($state) {
  $out = @{ check = $state.check; details = $state.details }
  $json = $out | ConvertTo-Json -Depth 6
  Ensure-Dir $StateDir
  Set-Content -LiteralPath $StatePath -Value $json -Encoding UTF8
  Write-Log ("STATE WROTE: check='{0}' details='{1}'" -f $state.check, $state.details)
}

function Invoke-DiscordDeleteMessage([string]$WebhookUrl, [string]$MessageId) {
  if ([string]::IsNullOrWhiteSpace($MessageId)) { return }

  $WebhookUrl = ($WebhookUrl -replace "[`r`n]", "").Trim()
  $parts = Get-WebhookParts $WebhookUrl
  $deleteUrl = "https://discord.com/api/webhooks/$($parts.id)/$($parts.token)/messages/$MessageId"

  $safeDeleteUrl = "https://discord.com/api/webhooks/$($parts.id)/***/messages/$MessageId"
  Write-Log "DELETE TRY: $safeDeleteUrl"

  try {
    Invoke-RestMethod -Method Delete -Uri $deleteUrl -TimeoutSec 30 | Out-Null
    Write-Log "DELETE OK: id=$MessageId"
  } catch {
    $code = $null
    $body = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    try {
      $stream = $_.Exception.Response.GetResponseStream()
      if ($stream) {
        $reader = New-Object System.IO.StreamReader($stream)
        $body = $reader.ReadToEnd()
      }
    } catch {}

    if ($body) {
      Write-Log "DELETE FAILED: id=$MessageId code=$code body=$body"
    } else {
      Write-Log "DELETE FAILED: id=$MessageId code=$code msg=$($_.Exception.Message)"
    }
  }
}

function Invoke-DiscordPostEmbed([string]$WebhookUrl, $payloadObj) {
  $WebhookUrl = ($WebhookUrl -replace "[`r`n`t ]", "").Trim()
  Write-Log ("POST WEBHOOK URL (sanitized) = '{0}'" -f $WebhookUrl)

  try {
    $u = [Uri]$WebhookUrl
    if (-not $u.Scheme -or -not $u.Host) { throw }
  } catch {
    throw ("Invalid webhook URL: '{0}'" -f $WebhookUrl)
  }

  # force webhook username (prevents "server name" / "servertest" look)
  if (-not ($payloadObj.ContainsKey("username"))) {
    $payloadObj["username"] = $WebhookUsername
  } else {
    $payloadObj["username"] = $WebhookUsername
  }

  $json = $payloadObj | ConvertTo-Json -Depth 10
  $postUrl = [Uri]::new($WebhookUrl + "?wait=true")

  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $resp = Invoke-RestMethod -Uri $postUrl `
      -Method Post `
      -Body $bytes `
      -ContentType 'application/json; charset=utf-8' `
      -TimeoutSec 30
    return $resp.id
  }
  catch {
    Write-Log ("DISCORD POST FAILED: {0}" -f $_.Exception.Message)
    Write-Log ("DISCORD POST SENT JSON: {0}" -f ($json -replace "`r?`n"," "))
    throw
  }
}

function Get-WorkshopIdsFromIni([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { throw "INI not found: $Path" }

  $line = Get-Content -LiteralPath $Path |
    Where-Object { $_ -and ($_ -notmatch '^\s*#') -and ($_ -match '^\s*WorkshopItems\s*=') } |
    Select-Object -First 1

  if (-not $line) { throw "Could not find WorkshopItems= in INI: $Path" }

  $value = ($line -split '=', 2)[1].Trim()
  if ([string]::IsNullOrWhiteSpace($value)) { return @() }

  return @(
    $value.Split(';') |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -match '^\d+$' } |
      Select-Object -Unique
  )
}

function Get-PublishedFileDetails([string[]]$Ids) {
  $uri = "https://api.steampowered.com/ISteamRemoteStorage/GetPublishedFileDetails/v1/"
  $pairs = @()
  $pairs += "itemcount=$($Ids.Count)"
  for ($i = 0; $i -lt $Ids.Count; $i++) {
    $pairs += "publishedfileids[$i]=$($Ids[$i])"
  }
  $body = ($pairs -join "&")
  return Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/x-www-form-urlencoded" -Body $body -TimeoutSec 30
}

function Get-FolderLastWriteUtcDeep([string]$FolderPath) {
  if (-not (Test-Path -LiteralPath $FolderPath)) { return $null }
  $latest = $null
  Get-ChildItem -LiteralPath $FolderPath -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $_.LastWriteTimeUtc
    if (-not $latest -or $t -gt $latest) { $latest = $t }
  }
  if (-not $latest) { $latest = (Get-Item -LiteralPath $FolderPath).LastWriteTimeUtc }
  return $latest
}

function New-Embed($title, $desc, $ok) {
  $color = if ($ok -eq $true) { 3066993 } elseif ($ok -eq $false) { 15158332 } else { 3447003 }
  return @{
    title = $title
    description = $desc
    color = $color
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
  }
}

function New-AllowedMentionsForPingRole {
  if (-not [string]::IsNullOrWhiteSpace($PingRoleId)) {
    return @{ parse = @(); roles = @($PingRoleId) }
  }
  return @{ parse = @("roles","everyone") }
}


# ====== MAIN ======
Ensure-Dir $LogDir
Ensure-Dir $StateDir
Write-Log ("PID={0} User={1}" -f $PID, [Environment]::UserName)

$url = [string]$env:DISCORD_WEBHOOK_URL
if ($null -eq $url) { $url = "" }
$url = ($url -replace "[`r`n`t ]", "").Trim()

Write-Log ("WEBHOOK URL (sanitized) startswith=https? {0}" -f ($url.StartsWith("https://")))
Write-Log ("ENV(DISCORD_WEBHOOK_URL)='{0}'" -f ($url -replace '[\r\n]',''))

# Validation URL (fail fast)
try {
  $u = [Uri]$url
  if (-not $u.Scheme -or -not $u.Host) { throw "Invalid DISCORD_WEBHOOK_URL (no scheme/host)" }
} catch {
  throw ("Invalid DISCORD_WEBHOOK_URL value: '{0}'" -f ($url -replace '[\r\n]',''))
}

if ([string]::IsNullOrWhiteSpace($url)) {
  Write-Log "FATAL: DISCORD_WEBHOOK_URL missing."
  exit 3
}

# Acquire lock (anti double run)
$lockStream = $null
try {
  $lockStream = [System.IO.File]::Open($LockPath, 'CreateNew', 'Write', 'None')
} catch {
  Write-Log "LOCKED: Another instance is already running. Exiting."
  exit 0
}

try {
  Write-Log "START workshop check"

  if (-not (Test-Path -LiteralPath $WorkshopContentRoot)) {
    throw "WorkshopContentRoot not found: $WorkshopContentRoot"
  }

  $ids = Get-WorkshopIdsFromIni $IniPath
  if ($ids.Count -eq 0) {
    Write-Log "No Workshop IDs found in INI."

    $state = Read-State
    Invoke-DiscordDeleteMessage $url $state.check
    Invoke-DiscordDeleteMessage $url $state.details

    $idCheck = Invoke-DiscordPostEmbed $url @{
      content = ""
      embeds = @( New-Embed "PZ Workshop Check" "No WorkshopItems found in the INI." $null )
      allowed_mentions = (New-AllowedMentionsForPingRole)
    }

    $state.check = $idCheck
    $state.details = $null
    Write-State $state
    Write-Log "END workshop check"
    exit 0
  }

  # Steam API in batches
  $batchSize = 50
  $results = @()

  for ($offset = 0; $offset -lt $ids.Count; $offset += $batchSize) {
    $end = [Math]::Min($offset + $batchSize - 1, $ids.Count - 1)
    $batch = $ids[$offset..$end]
    $api = Get-PublishedFileDetails $batch

    foreach ($d in $api.response.publishedfiledetails) {
      $results += [pscustomobject]@{
        WorkshopId  = [string]$d.publishedfileid
        Result      = [int]$d.result
        Title       = $d.title
        TimeUpdated = if ($d.time_updated) { [int64]$d.time_updated } else { $null }
      }
    }
  }

  $updates = New-Object System.Collections.Generic.List[object]
  $missing = New-Object System.Collections.Generic.List[object]
  $errors  = New-Object System.Collections.Generic.List[object]

  foreach ($r in ($results | Sort-Object WorkshopId)) {
    if ($r.Result -ne 1 -or -not $r.TimeUpdated) {
      $errors.Add([pscustomobject]@{
        WorkshopId = $r.WorkshopId
        Title = $r.Title
        Notes = "Steam API result=$($r.Result)"
      }) | Out-Null
      continue
    }

    $apiUtc = [DateTimeOffset]::FromUnixTimeSeconds($r.TimeUpdated).UtcDateTime
    $localPath = Join-Path $WorkshopContentRoot $r.WorkshopId
    $localUtc = Get-FolderLastWriteUtcDeep $localPath

    if (-not $localUtc) {
      $missing.Add([pscustomobject]@{
        WorkshopId = $r.WorkshopId
        Title = $r.Title
      }) | Out-Null
      continue
    }

    if ($apiUtc -gt $localUtc.AddMinutes(2)) {
      $updates.Add([pscustomobject]@{
        WorkshopId = $r.WorkshopId
        Title = $r.Title
      }) | Out-Null
    }
  }

  Write-Log ("RESULT: Updates={0} Missing={1} Errors={2}" -f $updates.Count, $missing.Count, $errors.Count)

  # ---- Delete old messages and post new ones ----
  $state = Read-State
  Invoke-DiscordDeleteMessage $url $state.check
  Invoke-DiscordDeleteMessage $url $state.details

  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

  $checkDesc = "Date: **$ts**`nWatched IDs: **$($ids.Count)**`n"
  if ($updates.Count -gt 0) {
    $checkDesc += "`n🚨 **UPDATE AVAILABLE:** $($updates.Count)`n"
    $maxLines = 15
    $i = 0
    foreach ($u in $updates) {
      if ($i -ge $maxLines) { $checkDesc += "`n… (+$($updates.Count-$maxLines) more)"; break }
      $t = if ($u.Title) { $u.Title } else { "(no title)" }
      $checkDesc += "• **$($u.WorkshopId)** — $t`n"
      $i++
    }
  } else {
    $checkDesc += "`n✅ No updates detected."
  }

  # Content ping (only when updates)
  $content = ""
  if ($updates.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($DiscordPingOnUpdate)) {
    $content = $DiscordPingOnUpdate
  }

  $idCheck = Invoke-DiscordPostEmbed $url @{
    content = $content
    embeds = @( New-Embed "PZ Workshop Check" $checkDesc ($updates.Count -eq 0) )
    allowed_mentions = (New-AllowedMentionsForPingRole)
  }

  $idDetails = $null
  if ($missing.Count -gt 0 -or $errors.Count -gt 0) {
    $details = ""
    if ($missing.Count -gt 0) {
      $details += "📦 **MISSING LOCALLY:** $($missing.Count)`n"
      foreach ($m in $missing) {
        $t = if ($m.Title) { $m.Title } else { "(no title)" }
        $details += "• **$($m.WorkshopId)** — $t`n"
      }
      $details += "`n"
    }
    if ($errors.Count -gt 0) {
      $details += "⚠️ **ERRORS:** $($errors.Count)`n"
      foreach ($e in $errors) {
        $t = if ($e.Title) { $e.Title } else { "(no title)" }
        $details += "• **$($e.WorkshopId)** — $t — $($e.Notes)`n"
      }
    }

    $idDetails = Invoke-DiscordPostEmbed $url @{
      content = ""
      embeds = @( New-Embed "PZ Workshop Check — Details" $details $false )
      allowed_mentions = (New-AllowedMentionsForPingRole)
    }
  }

  if ([string]::IsNullOrWhiteSpace([string]$idDetails)) { $idDetails = $null }

  $state.check = $idCheck
  $state.details = $idDetails
  Write-State $state

  Write-Log "END workshop check"
  exit 0
}
catch {
  $msg = $_.Exception.Message
  Write-Log "FATAL: $msg"

  $state = Read-State
  Invoke-DiscordDeleteMessage $url $state.check
  Invoke-DiscordDeleteMessage $url $state.details

  $idCheck = Invoke-DiscordPostEmbed $url @{
    content = ""
    embeds = @( New-Embed "PZ Workshop Check — FATAL" $msg $false )
    allowed_mentions = (New-AllowedMentionsForPingRole)
  }

  $state.check = $idCheck
  $state.details = $null
  Write-State $state

  exit 3
}
finally {
  if ($lockStream) { $lockStream.Dispose() }
  Remove-Item -LiteralPath $LockPath -ErrorAction SilentlyContinue | Out-Null
}
