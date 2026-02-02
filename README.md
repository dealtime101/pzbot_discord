# Project Zomboid – Workshop Update Notifier (Discord)

A robust, production-ready PowerShell system that monitors Project Zomboid Steam Workshop mods
and posts clean, auto-updating Discord notifications when changes are detected.

Designed for dedicated servers, Build 42, and long-running unattended environments.

---

## ✨ Features

- Automatically checks Steam Workshop mods defined in your server INI
- Deletes the previous Discord message before posting a new one (no spam)
- Keeps exactly one live status message updated every run
- Optional role ping when updates are detected
- Persistent state stored safely outside log cleanup
- PowerShell 5.1 safe (encoding, JSON parsing, CR/LF sanitization)
- Scheduler-safe (lock file + no overlapping runs)
- Designed to coexist with Discord bots / watchdogs

## 🧠 How It Works

1. Reads WorkshopItems= from your Project Zomboid server INI
2. Queries Steam Web API for the latest time_updated
3. Compares Steam time_updated with local workshop folder timestamps
4. Detects updates available, missing mods, and Steam API errors
5. Updates a single Discord webhook message
6. Stores message IDs in a persistent state file for safe deletion next run

## 📂 Project Structure

`	ext
PZServerBuild42/
- Maintain-PZServerUpdateNotifTask.ps1  # Main script
- logs/workshop-check.log  # Rotatable logs
- state/workshop-webhook-state.json  # Persistent Discord message IDs (do not purge)
`"
    AddBlank
  }
}

# Requirements
 = GetDictOrNull System.Collections.Hashtable 

## 🛠 Installation

1. Clone or download this repository
2. Place files in your server directory (e.g. C:\PZServerBuild42)
3. Create the persistent state folder: mkdir C:\PZServerBuild42\state
4. Set environment variables at Machine scope (System Properties → Environment Variables)
5. Create a Scheduled Task running as SYSTEM
6. Trigger every 10 minutes
7. Action: powershell.exe -NoProfile -ExecutionPolicy Bypass -File Maintain-PZServerUpdateNotifTask.ps1
8. Task settings: Multiple instances = Ignore new, Execution time limit = 5 minutes, Start when available = true

## 📣 Discord Output

- ✅ No updates → green status
- 🚨 Updates detected → red status + optional role ping
- ⚠️ Errors / missing mods → optional secondary details embed
- Only one message is kept visible (previous message is deleted each run)

If the state file is deleted, the script cannot delete the previous message and you may see duplicates.

## 🧪 Tested With

- Windows Server 2019
- Windows Server 2022
- PowerShell 5.1
- Project Zomboid Build 42
- Workshop mods: 100+
- Uptime: 24/7 long-running servers

## ⚠️ Known Issues

- Steam Web API rate limits may cause temporary API errors
- Workshop folders with delayed filesystem timestamps may trigger false positives (2-minute buffer applied)
- Discord webhooks cannot delete messages created by a different webhook/token

## 🧯 Troubleshooting

### Duplicate messages appearing

State file missing or deleted. Ensure C:\PZServerBuild42\state is excluded from any cleanup jobs.

### Invalid URI / hostname parsing errors

Your environment variable contains hidden whitespace/newlines. The script sanitizes it, but ensure Machine-scope value is clean.

### 401 Unauthorized on delete

Webhook token changed or invalid. Recreate the webhook and update DISCORD_WEBHOOK_URL (Machine scope).

## 🗺 Roadmap

- [ ] Optional auto-restart hook after updates
- [ ] Multi-server support
- [ ] JSON/YAML config file (optional) for script settings
- [ ] GitHub Actions example
- [ ] Linux (bash) version

## 📝 Changelog

### v1.0.0 – Initial Public Release

- Workshop update detection via Steam Web API
- Single-message Discord webhook system
- Persistent state handling outside log cleanup
- SYSTEM-safe environment variable support
- PowerShell 5.1 compatibility
- Robust error handling and logging

## 📜 License

MIT License

## 🤝 Contributing

PRs and issues are welcome.
If you run a large PZ server and improve this script, feel free to share.


## ⭐ Why This Exists

Most Workshop notifiers:

- Spam Discord channels
- Break after weeks of unattended runtime
- Don’t handle scheduler edge cases

**Goal:** A notifier built to survive months of unattended runtime with clean, non-spammy Discord updates.

