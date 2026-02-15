# config.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass

BOT_VERSION = os.environ.get("PZBOT_VERSION", "1.3.8.3").strip() or "1.3.8.3"


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
    DISCORD_BOT_TOKEN: str
    DISCORD_GUILD_ID: int
    PZ_ADMIN_ROLE_ID: int

    POWERSHELL_EXE: str
    PZ_CONTROL_PS1: str
    PZ_LOGSCAN_PS1: str
    PZ_CONSOLE_LOG: str
    WORKSHOP_CHECK_PS1: str
    PZ_IGNORE_FILE: str

    STATUS_REFRESH_SECONDS: int
    CONFIRM_SECONDS: int

    LOG_DIR: str
    BOT_LOG_FILE: str
    ACTION_AUDIT_LOG: str

    BOT_VERSION: str


def load_config() -> Config:
    base = _env_str("PZ_BASE_DIR", r"C:\PZServerBuild42")
    log_dir = _env_str("PZ_LOG_DIR", r"C:\PZ_MaintenanceLogs")

    return Config(
        DISCORD_BOT_TOKEN=_env_required("DISCORD_BOT_TOKEN"),
        DISCORD_GUILD_ID=_env_int_required("DISCORD_GUILD_ID"),
        PZ_ADMIN_ROLE_ID=_env_int("PZ_ADMIN_ROLE_ID", 0),

        POWERSHELL_EXE=_env_str(
            "POWERSHELL_EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
        PZ_CONTROL_PS1=_env_str("PZ_CONTROL_PS1", rf"{base}\pz_control.ps1"),
        PZ_LOGSCAN_PS1=_env_str("PZ_LOGSCAN_PS1", rf"{base}\pz_logscan.ps1"),
        PZ_CONSOLE_LOG=_env_str("PZ_CONSOLE_LOG", rf"{base}\hh_saves\Zomboid\server-console.txt"),
        WORKSHOP_CHECK_PS1=_env_str("WORKSHOP_CHECK_PS1", rf"{base}\pzbot_workshop_check.ps1"),
        PZ_IGNORE_FILE=_env_str("PZ_IGNORE_FILE", ""),

        STATUS_REFRESH_SECONDS=_env_int("PZ_STATUS_REFRESH_SECONDS", 30),
        CONFIRM_SECONDS=_env_int("PZ_CONFIRM_SECONDS", 20),

        LOG_DIR=log_dir,
        BOT_LOG_FILE=os.path.join(log_dir, "pz_discord_bot.log"),
        ACTION_AUDIT_LOG=os.path.join(log_dir, "pz_discord_actions.log"),

        BOT_VERSION=BOT_VERSION,
    )
