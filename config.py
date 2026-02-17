# config.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass

BOT_VERSION = os.environ.get("PZBOT_VERSION", "1.3.8.4").strip() or "1.3.8.4"


def _getenv_raw(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name, default)
    if v is None:
        return None
    v = str(v).strip()
    return v if v != "" else None


def _env_required(name: str) -> str:
    v = _getenv_raw(name)
    if v is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return v


def _parse_discord_id(value: str, var_name: str) -> int:
    m = re.search(r"\d+", value)
    if not m:
        raise ValueError(f"{var_name} must contain a numeric ID (got: {value!r})")
    return int(m.group(0))


def _env_int_required(name: str) -> int:
    v = _env_required(name)
    return _parse_discord_id(v, name)


def _env_str(name: str, default: str) -> str:
    v = _getenv_raw(name, default)
    return (v if v is not None else default).strip()


def _env_int(name: str, default: int) -> int:
    v = _getenv_raw(name, str(default))
    if v is None:
        return default
    return _parse_discord_id(v, name)


def _env_bool(name: str, default: bool) -> bool:
    v = _getenv_raw(name, None)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Config:
    # Discord
    DISCORD_BOT_TOKEN: str
    DISCORD_GUILD_ID: int
    PZ_ADMIN_ROLE_ID: int

    # Bug / logscan
    DISCORD_BUGS_CHANNEL_ID: int
    PZ_LOGSCAN_PS1: str
    PZ_CONSOLE_LOG: str
    PZ_LOGSCAN_STATE_DIR: str
    PZ_LOGSCAN_INTERVAL_SECONDS: int
    PZ_LOGSCAN_ALERT_COOLDOWN_SECONDS: int
    PZ_LOGSCAN_DEDUP_SECONDS: int

    # Paths
    POWERSHELL_EXE: str
    PZ_CONTROL_PS1: str
    WORKSHOP_CHECK_PS1: str
    PZ_IGNORE_FILE: str

    # Behaviour
    ALLOW_CHANNEL_PERMS: bool
    CONFIRM_SECONDS: int
    COOLDOWN_SECONDS: int
    STATUS_REFRESH_SECONDS: int

    # Logging
    LOG_DIR: str
    BOT_LOG_FILE: str
    ACTION_AUDIT_LOG: str

    # Optional
    DISCORD_PING_ON_UPDATE: str
    BOT_VERSION: str


def load_config() -> Config:
    base = _env_str("PZ_BASE_DIR", r"C:\PZServerBuild42")
    log_dir = _env_str("PZ_LOG_DIR", r"C:\PZ_MaintenanceLogs")
    pz_ignore_file = _env_str("PZ_IGNORE_FILE", "")

    return Config(
        # Discord
        DISCORD_BOT_TOKEN=_env_required("DISCORD_BOT_TOKEN"),
        DISCORD_GUILD_ID=_env_int_required("DISCORD_GUILD_ID"),
        PZ_ADMIN_ROLE_ID=_env_int("PZ_ADMIN_ROLE_ID", 0),

        # Bug/logscan
        DISCORD_BUGS_CHANNEL_ID=_env_int("DISCORD_BUGS_CHANNEL_ID", 0),
        PZ_LOGSCAN_PS1=_env_str("PZ_LOGSCAN_PS1", rf"{base}\pz_logscan.ps1"),
        PZ_CONSOLE_LOG=_env_str("PZ_CONSOLE_LOG", rf"{base}\hh_saves\Zomboid\server-console.txt"),
        PZ_LOGSCAN_STATE_DIR=_env_str("PZ_LOGSCAN_STATE_DIR", r"C:\PZ_MaintenanceLogs\PZLogScan"),
        PZ_LOGSCAN_INTERVAL_SECONDS=_env_int("PZ_LOGSCAN_INTERVAL_SECONDS", 25),
        PZ_LOGSCAN_ALERT_COOLDOWN_SECONDS=_env_int("PZ_LOGSCAN_ALERT_COOLDOWN_SECONDS", 30),
        PZ_LOGSCAN_DEDUP_SECONDS=_env_int("PZ_LOGSCAN_DEDUP_SECONDS", 600),

        # Paths
        POWERSHELL_EXE=_env_str(
            "POWERSHELL_EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
        PZ_CONTROL_PS1=_env_str("PZ_CONTROL_PS1", rf"{base}\pz_control.ps1"),
        WORKSHOP_CHECK_PS1=_env_str("WORKSHOP_CHECK_PS1", rf"{base}\pzbot_workshop_check.ps1"),
        PZ_IGNORE_FILE=pz_ignore_file,

        # Behaviour
        ALLOW_CHANNEL_PERMS=_env_bool("PZ_ALLOW_CHANNEL_PERMS", True),
        CONFIRM_SECONDS=_env_int("PZ_CONFIRM_SECONDS", 20),
        COOLDOWN_SECONDS=_env_int("PZ_COOLDOWN_SECONDS", 10),
        STATUS_REFRESH_SECONDS=_env_int("PZ_STATUS_REFRESH_SECONDS", 30),

        # Logging
        LOG_DIR=log_dir,
        BOT_LOG_FILE=os.path.join(log_dir, "pz_discord_bot.log"),
        ACTION_AUDIT_LOG=os.path.join(log_dir, "pz_discord_actions.log"),

        # Optional
        DISCORD_PING_ON_UPDATE=_env_str("DISCORD_PING_ON_UPDATE", ""),
        BOT_VERSION=BOT_VERSION,
    )
