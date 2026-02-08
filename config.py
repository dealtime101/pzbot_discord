# config.py
from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None or str(v).strip() == "":
        raise RuntimeError(f"Missing environment variable: {name}")
    return str(v).strip()


def _sanitize_int_text(v: str) -> str:
    """
    Accept:
      123
      <123>
      <@&123>
      <@123>
    """
    t = (v or "").strip()
    t = t.replace("<@&", "").replace("<@", "").replace(">", "").replace("<", "")
    return t.strip()


def _env_int(name: str, default: str | None = None) -> int:
    raw = _env(name, default)
    raw = _sanitize_int_text(raw)
    return int(raw)


def _env_bool(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Config:
    DISCORD_BOT_TOKEN: str
    DISCORD_GUILD_ID: int
    PZ_ADMIN_ROLE_ID: int
    DISCORD_BUGS_CHANNEL_ID: int

    POWERSHELL_EXE: str
    PZ_CONTROL_PS1: str
    PZ_LOGSCAN_PS1: str
    WORKSHOP_CHECK_PS1: str

    ALLOW_CHANNEL_PERMS: bool
    CONFIRM_SECONDS: int
    COOLDOWN_SECONDS: int
    STATUS_REFRESH_SECONDS: int
    LOGSCAN_INTERVAL_SECONDS: int

    PS_TIMEOUT_SECONDS: int
    WORKSHOP_TIMEOUT_SECONDS: int
    LOGSCAN_TIMEOUT_SECONDS: int

    LOG_DIR: str
    BOT_LOG_FILE: str
    ACTION_AUDIT_LOG: str

    IGNORE_FILE: str
    DISCORD_PING_ON_UPDATE: str

    BOT_VERSION: str


def load_config() -> Config:
    base = r"C:\PZServerBuild42"
    log_dir = os.environ.get("PZ_LOG_DIR", r"C:\PZ_MaintenanceLogs").strip()

    ignore_file_default = os.path.join(base, "pz_ignore_regex.txt")

    return Config(
        DISCORD_BOT_TOKEN=_env("DISCORD_BOT_TOKEN"),
        DISCORD_GUILD_ID=_env_int("DISCORD_GUILD_ID"),
        PZ_ADMIN_ROLE_ID=_env_int("PZ_ADMIN_ROLE_ID"),
        DISCORD_BUGS_CHANNEL_ID=_env_int("DISCORD_BUGS_CHANNEL_ID", "0"),

        POWERSHELL_EXE=os.environ.get(
            "POWERSHELL_EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ).strip(),
        PZ_CONTROL_PS1=os.environ.get("PZ_CONTROL_PS1", rf"{base}\pz_control.ps1").strip(),
        PZ_LOGSCAN_PS1=os.environ.get("PZ_LOGSCAN_PS1", rf"{base}\pz_logscan.ps1").strip(),
        WORKSHOP_CHECK_PS1=os.environ.get("WORKSHOP_CHECK_PS1", rf"{base}\pzbot_workshop_check.ps1").strip(),

        ALLOW_CHANNEL_PERMS=_env_bool("PZ_ALLOW_CHANNEL_PERMS", "true"),
        CONFIRM_SECONDS=int(os.environ.get("PZ_CONFIRM_SECONDS", "20")),
        COOLDOWN_SECONDS=int(os.environ.get("PZ_COOLDOWN_SECONDS", "10")),
        STATUS_REFRESH_SECONDS=int(os.environ.get("PZ_STATUS_REFRESH_SECONDS", "30")),
        LOGSCAN_INTERVAL_SECONDS=int(os.environ.get("PZ_LOGSCAN_INTERVAL_SECONDS", "25")),

        PS_TIMEOUT_SECONDS=int(os.environ.get("PZ_PS_TIMEOUT_SECONDS", "90")),
        WORKSHOP_TIMEOUT_SECONDS=int(os.environ.get("PZ_WORKSHOP_TIMEOUT_SECONDS", "240")),
        LOGSCAN_TIMEOUT_SECONDS=int(os.environ.get("PZ_LOGSCAN_TIMEOUT_SECONDS", "45")),

        LOG_DIR=log_dir,
        BOT_LOG_FILE=os.path.join(log_dir, "pz_discord_bot.log"),
        ACTION_AUDIT_LOG=os.path.join(log_dir, "pz_discord_actions.log"),

        IGNORE_FILE=os.environ.get("PZ_IGNORE_FILE", ignore_file_default).strip(),
        DISCORD_PING_ON_UPDATE=os.environ.get("DISCORD_PING_ON_UPDATE", "").strip(),

        BOT_VERSION=os.environ.get("PZBOT_VERSION", "1.3.5.5").strip(),
    )
