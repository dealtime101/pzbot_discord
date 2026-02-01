# 🧟 Project Zomboid – Workshop Update Notifier (Discord)

A **robust, production-ready PowerShell system** that monitors **Project Zomboid Workshop mods** and posts **clean, auto-updating Discord notifications** when changes are detected.

Designed for **dedicated servers**, **Build 42**, and **long-running unattended environments**.

---

## ✨ Features

- 🔄 Automatically checks Steam Workshop mods defined in your server INI
- 🧹 Deletes the previous Discord message before posting a new one (no spam)
- 📌 Keeps exactly **one live status message** updated every run
- 🚨 Optional **role ping** when updates are detected
- 🗂 Persistent state stored safely outside log cleanup
- 🧠 Handles PowerShell 5.1 quirks (encoding, JSON, CR/LF issues)
- 🔒 Scheduler-safe (lock file + no overlapping runs)
- 🧩 Designed to coexist with Discord bots / watchdogs

---

## 🧠 How It Works

1. Reads `WorkshopItems=` from your Project Zomboid server INI
2. Queries Steam Web API for latest `time_updated`
3. Compares with local workshop folder timestamps
4. Detects:
   - ✅ Updates available
   - 📦 Missing mods
   - ⚠️ Steam API errors
5. Updates a **single Discord webhook message**
6. Persists message IDs in a state file for safe deletion on next run

---

## 📂 Project Structure

```text
PZServerBuild42/
├─ Maintain-PZServerUpdateNotifTask.ps1   # Main script
├─ logs/
│  └─ workshop-check.log                  # Rotatable logs
├─ state/
│  └─ workshop-webhook-state.json          # Persistent message IDs

Discord Webhook

Scheduled Task (recommended)
