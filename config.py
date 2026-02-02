# config.py
from __future__ import annotations

import os
import re
from dataclasses import dataclass


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
    """
    Accepts:
      - 725383719455817758
      - <725383719455817758>
      - <@725383719455817758>
      - <@&725383719455817758>
    """
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

    # Paths
    POWERSHELL_EXE: str
    PZ_CONTROL_PS1: str
    WORKSHOP_CHECK_PS1: str  # webhook script

    # Behaviour
    ALLOW_CHANNEL_PERMS: bool
    CONFIRM_SECONDS: int
    COOLDOWN_SECONDS: int
    STATUS_REFRESH_SECONDS: int  # how often to update bot presence

    # Logging
    LOG_DIR: str
    BOT_LOG_FILE: str
    ACTION_AUDIT_LOG: str

    # Optional: role mention (string like "<@&123>" or "@here" or "")
    DISCORD_PING_ON_UPDATE: str


def load_config() -> Config:
    base = _env_str("PZ_BASE_DIR", r"C:\PZServerBuild42")
    log_dir = _env_str("PZ_LOG_DIR", r"C:\PZ_MaintenanceLogs")

    return Config(
        DISCORD_BOT_TOKEN=_env_required("DISCORD_BOT_TOKEN"),
        DISCORD_GUILD_ID=_env_int_required("DISCORD_GUILD_ID"),
        PZ_ADMIN_ROLE_ID=_env_int_required("PZ_ADMIN_ROLE_ID"),

        POWERSHELL_EXE=_env_str(
            "POWERSHELL_EXE",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
        PZ_CONTROL_PS1=_env_str(
            "PZ_CONTROL_PS1",
            rf"{base}\pz_control.ps1",
        ),
        WORKSHOP_CHECK_PS1=_env_str(
            "WORKSHOP_CHECK_PS1",
            rf"{base}\Maintain-PZServerUpdateNotifTask.ps1",
        ),

        ALLOW_CHANNEL_PERMS=_env_bool("PZ_ALLOW_CHANNEL_PERMS", True),
        CONFIRM_SECONDS=int(_env_str("PZ_CONFIRM_SECONDS", "20")),
        COOLDOWN_SECONDS=int(_env_str("PZ_COOLDOWN_SECONDS", "10")),
        STATUS_REFRESH_SECONDS=int(_env_str("PZ_STATUS_REFRESH_SECONDS", "30")),

        LOG_DIR=log_dir,
        BOT_LOG_FILE=os.path.join(log_dir, "pz_discord_bot.log"),
        ACTION_AUDIT_LOG=os.path.join(log_dir, "pz_discord_actions.log"),

        DISCORD_PING_ON_UPDATE=_env_str("DISCORD_PING_ON_UPDATE", ""),
    )
