# config.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass

# Bot version (SemVer)
BOT_VERSION = "1.3.5.1"


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None or str(v).strip() == "":
        raise RuntimeError(f"Missing environment variable: {name}")
    return str(v).strip()


def _env_int_flexible(name: str, default: str | None = None) -> int:
    """Accept plain integers or mention-like values: <123>, <@123>, <@&123>."""
    raw = _env(name, default)
    digits = re.sub(r"\D+", "", raw)
    if digits == "":
        raise ValueError(f"{name} must be an integer (got: {raw!r})")
    return int(digits)


@dataclass(frozen=True)
class Config:
    # Discord
    DISCORD_BOT_TOKEN: str
    DISCORD_GUILD_ID: int
    PZ_ADMIN_ROLE_ID: int
    DISCORD_BUGS_CHANNEL_ID: int

    # Optional mention string (e.g. "<@&123>" or "@here" or "")
    DISCORD_PING_ON_UPDATE: str

    # Paths
    POWERSHELL_EXE: str
    PZ_CONTROL_PS1: str
    WORKSHOP_CHECK_PS1: str
    PZ_LOGSCAN_PS1: str
    PZ_CONSOLE_LOG: str

    # Behaviour
    ALLOW_CHANNEL_PERMS: bool
    CONFIRM_SECONDS: int
    COOLDOWN_SECONDS: int
    STATUS_REFRESH_SECONDS: int
    PZ_LOGSCAN_INTERVAL_SECONDS: int

    # Dedup / alert pacing
    PZ_LOG_DEDUP_SECONDS: int
    PZ_ALERT_MIN_INTERVAL_SECONDS: int

    # Logging
    LOG_DIR: str
    BOT_LOG_FILE: str
    ACTION_AUDIT_LOG: str

    # Nickname
    DISCORD_BOT_NICKNAME: str


def load_config() -> Config:
    base = r"C:\PZServerBuild42"
    log_dir = os.environ.get("PZ_LOG_DIR", r"C:\PZ_MaintenanceLogs").strip()

    return Config(
        DISCORD_BOT_TOKEN=_env("DISCORD_BOT_TOKEN"),
        DISCORD_GUILD_ID=_env_int_flexible("DISCORD_GUILD_ID"),
        PZ_ADMIN_ROLE_ID=_env_int_flexible("PZ_ADMIN_ROLE_ID"),
        DISCORD_BUGS_CHANNEL_ID=_env_int_flexible("DISCORD_BUGS_CHANNEL_ID", "0"),
        DISCORD_PING_ON_UPDATE=os.environ.get("DISCORD_PING_ON_UPDATE", "").strip(),

        POWERSHELL_EXE=os.environ.get(
            "POWERSHELL_EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
        PZ_CONTROL_PS1=os.environ.get("PZ_CONTROL_PS1", rf"{base}\pz_control.ps1"),
        WORKSHOP_CHECK_PS1=os.environ.get("WORKSHOP_CHECK_PS1", rf"{base}\pzbot_workshop_check.ps1"),
        PZ_LOGSCAN_PS1=os.environ.get("PZ_LOGSCAN_PS1", rf"{base}\pz_logscan.ps1"),
        PZ_CONSOLE_LOG=os.environ.get(
            "PZ_CONSOLE_LOG",
            os.path.join(os.environ.get("USERPROFILE", r"C:\Users\Public"), "Zomboid", "server-console.txt"),
        ),

        ALLOW_CHANNEL_PERMS=os.environ.get("PZ_ALLOW_CHANNEL_PERMS", "true").lower() == "true",
        CONFIRM_SECONDS=int(os.environ.get("PZ_CONFIRM_SECONDS", "20")),
        COOLDOWN_SECONDS=int(os.environ.get("PZ_COOLDOWN_SECONDS", "10")),
        STATUS_REFRESH_SECONDS=int(os.environ.get("PZ_STATUS_REFRESH_SECONDS", "30")),
        PZ_LOGSCAN_INTERVAL_SECONDS=int(os.environ.get("PZ_LOGSCAN_INTERVAL_SECONDS", "25")),

        PZ_LOG_DEDUP_SECONDS=int(os.environ.get("PZ_LOG_DEDUP_SECONDS", "600")),  # 10 min
        PZ_ALERT_MIN_INTERVAL_SECONDS=int(os.environ.get("PZ_ALERT_MIN_INTERVAL_SECONDS", "15")),

        LOG_DIR=log_dir,
        BOT_LOG_FILE=os.path.join(log_dir, "pz_discord_bot.log"),
        ACTION_AUDIT_LOG=os.path.join(log_dir, "pz_discord_actions.log"),

        DISCORD_BOT_NICKNAME=os.environ.get("DISCORD_BOT_NICKNAME", "PZBot").strip() or "PZBot",
    )
