# discord_bot.py
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Optional

import discord
from discord import app_commands

from config import load_config, Config, BOT_VERSION


# ------------------ Logging ------------------
def setup_logging(cfg: Config) -> logging.Logger:
    os.makedirs(cfg.LOG_DIR, exist_ok=True)

    logger = logging.getLogger("pzbot")
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(cfg.BOT_LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    logger.info("=== PZBot logging started (v%s) ===", BOT_VERSION)
    logger.info("Log file: %s", cfg.BOT_LOG_FILE)
    return logger


def audit_log(cfg: Config, line: str) -> None:
    os.makedirs(cfg.LOG_DIR, exist_ok=True)
    with open(cfg.ACTION_AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")


# ------------------ Helpers ------------------
async def run_powershell_script(ps_exe: str, script_path: str, args: list[str]) -> tuple[int, str]:
    cmd = [
        ps_exe,
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-NonInteractive",
        "-File", script_path,
        *args,
    ]
    p = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await p.communicate()
    text = (out or b"").decode("utf-8", errors="replace").strip()
    if not text:
        text = "(no output)"
    # allow big outputs for logscan JSON
    return p.returncode, text[:12000]


def make_embed(title: str, description: str, color: int) -> discord.Embed:
    emb = discord.Embed(title=title, description=description, color=color)
    emb.timestamp = discord.utils.utcnow()
    return emb


def user_tag(i: discord.Interaction) -> str:
    u = i.user
    return f"{u.name}({u.id})"


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _codeblock(text: str, max_len: int = 1700) -> str:
    t = (text or "").strip()
    if len(t) > max_len:
        t = t[: max_len - 3] + "..."
    t = t.replace("```", "``\u200b`")
    return f"```\n{t}\n```"


def parse_status_with_players(out: str) -> tuple[str, str]:
    t = (out or "").strip()
    up = t.upper()

    status = "UNKNOWN"
    if "RUNNING" in up:
        status = "RUNNING"
    elif "STOPPED" in up:
        status = "STOPPED"

    m = re.search(r"(?i)\bplayers\s*=\s*(\d+|\?)\b", t)
    players = m.group(1) if m else "?"
    return status, players


# ------------------ Severity styles ------------------
SEV_GREEN = 0x2ecc71
SEV_ORANGE = 0xf39c12
SEV_RED = 0xe74c3c
SEV_BLUE = 0x3498db


def severity_style(warn: int, error: int, stack: int) -> tuple[int, str]:
    if error > 0 or stack > 0:
        return SEV_RED, "🚨"
    if warn > 0:
        return SEV_ORANGE, "⚠️"
    return SEV_GREEN, "✅"


# ------------------ Permission model ------------------
async def get_member(i: discord.Interaction) -> Optional[discord.Member]:
    if i.guild is None:
        return None
    if isinstance(i.user, discord.Member):
        return i.user
    try:
        return await i.guild.fetch_member(i.user.id)
    except (discord.NotFound, discord.Forbidden):
        return None


def has_admin_role(cfg: Config, m: discord.Member) -> bool:
    role_ids = getattr(m, "_roles", None)
    if role_ids is not None:
        return cfg.PZ_ADMIN_ROLE_ID in role_ids
    return any(getattr(r, "id", None) == cfg.PZ_ADMIN_ROLE_ID for r in getattr(m, "roles", []))


def has_discord_admin_perm(m: discord.Member) -> bool:
    try:
        return bool(m.guild_permissions.administrator)
    except Exception:
        return False


def has_channel_permission(cfg: Config, i: discord.Interaction, m: discord.Member) -> bool:
    if not cfg.ALLOW_CHANNEL_PERMS:
        return False
    if i.channel is None:
        return False
    perms = i.channel.permissions_for(m)
    return perms.manage_guild or perms.manage_channels or perms.manage_messages


async def require_admin(cfg: Config, i: discord.Interaction) -> Optional[discord.Member]:
    m = await get_member(i)
    if m is None:
        await i.response.send_message(
            embed=make_embed(
                "Access denied",
                "Unable to resolve the member. Make sure **Server Members Intent** is enabled.",
                SEV_RED,
            ),
            ephemeral=True,
        )
        return None

    if has_admin_role(cfg, m) or has_discord_admin_perm(m) or has_channel_permission(cfg, i, m):
        return m

    await i.response.send_message(
        embed=make_embed("Access denied", "You don't have permission to use this command.", SEV_RED),
        ephemeral=True,
    )
    return None


# ------------------ Cooldown ------------------
class Cooldown:
    def __init__(self, seconds: int):
        self.seconds = seconds
        self._last: dict[tuple[int, str], float] = {}

    def check(self, user_id: int, key: str) -> bool:
        now = time.time()
        k = (user_id, key)
        last = self._last.get(k, 0.0)
        if now - last < self.seconds:
            return False
        self._last[k] = now
        return True


# ------------------ Confirm buttons ------------------
@dataclass
class PendingAction:
    action: str
    created_at: float
    interaction_user_id: int


class ConfirmView(discord.ui.View):
    def __init__(self, cfg: Config, pending: PendingAction, on_confirm):
        super().__init__(timeout=cfg.CONFIRM_SECONDS)
        self.cfg = cfg
        self.pending = pending
        self.on_confirm = on_confirm

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.pending.interaction_user_id:
            await interaction.response.send_message(
                embed=make_embed("Confirmation", "Only the original requester can confirm.", SEV_RED),
                ephemeral=True,
            )
            return False
        return True

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.on_confirm(interaction)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(
            embed=make_embed("Cancelled", "Action cancelled.", SEV_BLUE),
            view=None,
        )
        self.stop()


# ------------------ Bot ------------------
cfg = load_config()
logger = setup_logging(cfg)
cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

intents = discord.Intents.default()
intents.members = True  # for role checks
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Dedup cache (signature -> last seen timestamp)
dedup_seen: dict[str, float] = {}
last_alert_sent_at: float = 0.0

_ts_prefix_re = re.compile(r"^\[[^\]]+\]\s*")
_noise_re = re.compile(r"\b(f:\d+|t:\d+|st:[0-9,]+)\b", re.IGNORECASE)


def normalize_critical_text(s: str) -> str:
    t = (s or "").strip()
    t = _ts_prefix_re.sub("", t)
    t = _noise_re.sub("", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:1400]


def critical_signature(s: str) -> str:
    norm = normalize_critical_text(s).encode("utf-8", errors="ignore")
    return hashlib.sha1(norm).hexdigest()


async def run_control(action: str) -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, ["-Action", action])


async def run_workshop_check() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [])


async def run_logscan() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_LOGSCAN_PS1, ["-LogPath", cfg.PZ_CONSOLE_LOG])


def log_action(i: discord.Interaction, action: str, exit_code: int, out: str):
    g = i.guild.id if i.guild else 0
    ch = i.channel.id if i.channel else 0
    line = f"action={action} user={user_tag(i)} guild={g} channel={ch} exit={exit_code} out={out.replace(chr(10),'\\\\n')[:250]}"
    logger.info(line)
    audit_log(cfg, line)


# ------------------ Nickname enforcement ------------------
async def ensure_bot_nickname():
    """Force bot nickname to cfg.DISCORD_BOT_NICKNAME (requires 'Change Nickname' or 'Manage Nicknames')."""
    try:
        guild = client.get_guild(cfg.DISCORD_GUILD_ID)
        if guild is None:
            guild = await client.fetch_guild(cfg.DISCORD_GUILD_ID)

        me = guild.me
        if me is None:
            me = await guild.fetch_member(client.user.id)

        if me and me.nick != cfg.DISCORD_BOT_NICKNAME:
            await me.edit(nick=cfg.DISCORD_BOT_NICKNAME, reason="PZBot nickname enforcement")
            logger.info("Nickname enforced: %s", cfg.DISCORD_BOT_NICKNAME)
    except Exception as e:
        # Don't crash; just log
        logger.warning("Failed to enforce nickname: %s", e)


# ------------------ Presence ------------------
async def update_presence_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            _, out = await run_control("status")
            status, players = parse_status_with_players(out)

            if status == "RUNNING":
                suffix = f" ({players})" if players != "?" else ""
                await client.change_presence(
                    activity=discord.Game(f"PZ: RUNNING{suffix}"),
                    status=discord.Status.online,
                )
            elif status == "STOPPED":
                await client.change_presence(activity=discord.Game("PZ: STOPPED"), status=discord.Status.idle)
            else:
                await client.change_presence(activity=discord.Game("PZ: ?"), status=discord.Status.dnd)
        except Exception:
            pass

        await asyncio.sleep(cfg.STATUS_REFRESH_SECONDS)


# ------------------ Logscan monitor -> #bugs-reports ------------------
def _parse_logscan_json(text: str) -> dict:
    t = (text or "").strip()
    if t.startswith("{") and t.endswith("}"):
        return json.loads(t)
    a = t.find("{")
    b = t.rfind("}")
    if a != -1 and b != -1 and b > a:
        return json.loads(t[a : b + 1])
    raise ValueError("Unable to parse JSON output from pz_logscan.ps1")


async def post_console_alert(payload: dict) -> None:
    if cfg.DISCORD_BUGS_CHANNEL_ID <= 0:
        return

    ch = client.get_channel(cfg.DISCORD_BUGS_CHANNEL_ID)
    if ch is None:
        ch = await client.fetch_channel(cfg.DISCORD_BUGS_CHANNEL_ID)

    new_warn = _safe_int(payload.get("new_warn", 0))
    new_error = _safe_int(payload.get("new_error", 0))
    new_stack = _safe_int(payload.get("new_stack", 0))
    ignored_total = _safe_int(payload.get("ignored_total", 0))
    new_critical_count = _safe_int(payload.get("new_critical_count", 0))

    s1 = payload.get("stats_1h") or {}
    s24 = payload.get("stats_24h") or {}
    s30 = payload.get("stats_30d") or {}

    warn1 = _safe_int(s1.get("warn", 0))
    err1 = _safe_int(s1.get("error", 0))
    st1 = _safe_int(s1.get("stack", 0))
    color, emoji = severity_style(warn1, err1, st1)

    # Global pacing
    global last_alert_sent_at
    now = time.time()
    if now - last_alert_sent_at < cfg.PZ_ALERT_MIN_INTERVAL_SECONDS:
        return

    # Dedup filter
    dedup_window = float(cfg.PZ_LOG_DEDUP_SECONDS)
    critical_lines = payload.get("new_critical_lines") or []

    blocks: list[str] = []
    sent_count = 0

    for item in critical_lines:
        if len(blocks) >= 2:
            break
        txt = str(item)

        sig = critical_signature(txt)
        last = dedup_seen.get(sig, 0.0)
        if now - last < dedup_window:
            continue

        dedup_seen[sig] = now
        blocks.append(_codeblock(txt, max_len=1200))
        sent_count += 1

    # Prune old dedup entries
    for k, v in list(dedup_seen.items()):
        if now - v > dedup_window * 2:
            dedup_seen.pop(k, None)

    if sent_count == 0:
        # nothing new after dedup -> no alert
        return

    last_alert_sent_at = now

    mention = cfg.DISCORD_PING_ON_UPDATE.strip()
    mention_prefix = f"{mention}\n" if mention else ""

    desc = (
        f"**New critical:** `{new_critical_count}`  |  **Ignored:** `{ignored_total}`  |  **Sent:** `{sent_count}`\n"
        f"**New WARN:** `{new_warn}`  **New ERROR:** `{new_error}`  **New STACK:** `{new_stack}`\n\n"
        + ("\n".join(blocks) + "\n\n" if blocks else "")
        + f"**Last 1h** — WARN `{warn1}`, ERROR `{err1}`, STACK `{st1}`\n"
        + f"**Last 24h** — WARN `{_safe_int(s24.get('warn',0))}`, ERROR `{_safe_int(s24.get('error',0))}`, STACK `{_safe_int(s24.get('stack',0))}`\n"
        + f"**Last 30d** — WARN `{_safe_int(s30.get('warn',0))}`, ERROR `{_safe_int(s30.get('error',0))}`, STACK `{_safe_int(s30.get('stack',0))}`\n"
        + f"**Log:** `{payload.get('log_path','')}`"
    )

    emb = make_embed(f"{emoji} PZ — Console Alert", desc, color)
    await ch.send(content=mention_prefix, embed=emb)


async def monitor_console_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_logscan()
            if code == 0:
                payload = _parse_logscan_json(out)
                if _safe_int(payload.get("new_critical_count", 0)) > 0:
                    await post_console_alert(payload)
            else:
                logger.warning("logscan non-zero exit: %s | %s", code, out[:200])
        except Exception as e:
            logger.exception("monitor_console_loop failed: %s", e)

        await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)


# ------------------ Commands ------------------
@tree.command(name="pz_version", description="Show bot version", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_version(i: discord.Interaction):
    emb = make_embed("PZ — Version", f"Version: `v{BOT_VERSION}`", SEV_BLUE)
    await i.response.send_message(embed=emb, ephemeral=True)


@tree.command(name="pz_ping", description="Bot healthcheck", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.send_message(embed=make_embed("PZ — Ping", "✅ Pong.", SEV_GREEN), ephemeral=True)


@tree.command(name="pz_help", description="Commands + access rules", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        f"**PZBot v{BOT_VERSION}**\n\n"
        "**Commands**\n"
        "• `/pz_status` — server status + online players\n"
        "• `/pz_players` — list online players\n"
        "• `/pz_logstats` — console log stats (1h/24h/30d)\n"
        "• `/pz_workshop_check` — workshop check (webhook)\n"
        "• `/pz_save` — save world (sensitive)\n"
        "• `/pz_stop` — stop server (sensitive, confirmation)\n"
        "• `/pz_start` — start server (sensitive, confirmation)\n"
        "• `/pz_restart` — restart server (sensitive, confirmation)\n"
        "• `/pz_grant @user` — grant PZ role\n"
        "• `/pz_revoke @user` — revoke PZ role\n"
        "• `/pz_version` — bot version\n"
        "• `/pz_ping` — healthcheck\n\n"
        "**Monitoring**\n"
        "• Console ERROR/STACK alerts are posted to **#bugs-reports**\n\n"
        "**Access**\n"
        f"• Required role: <@&{cfg.PZ_ADMIN_ROLE_ID}>\n"
        "• OR Discord `Administrator`\n"
        "• OR (if enabled) channel perms: `manage_guild` / `manage_channels` / `manage_messages`\n\n"
        f"**Cooldown:** {cfg.COOLDOWN_SECONDS}s  |  **Confirm window:** {cfg.CONFIRM_SECONDS}s\n"
    )
    await i.response.send_message(embed=make_embed("PZ — Help", desc, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_status", description="Project Zomboid server status", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_status(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("status")
    status, players = parse_status_with_players(out)

    ok = (code == 0) and (status in ("RUNNING", "STOPPED"))
    color = SEV_GREEN if ok else SEV_RED
    desc = f"**Status:** `{status}`\n**Online players:** `{players}`"

    await i.followup.send(embed=make_embed("PZ — Status", desc, color), ephemeral=True)


@tree.command(name="pz_players", description="List online players", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_players(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("players")
    t = (out or "").strip()

    if "STOPPED" in t.upper():
        await i.followup.send(embed=make_embed("PZ — Players", "Server is stopped.", SEV_RED), ephemeral=True)
        return

    if t in ("(none)", ""):
        await i.followup.send(embed=make_embed("PZ — Players", "No players online.", SEV_GREEN), ephemeral=True)
        return

    names = [line.strip() for line in t.splitlines() if line.strip()]
    bullet_list = "\n".join([f"• `{n}`" for n in names])

    desc = f"**{len(names)} player(s) online:**\n{bullet_list}"
    await i.followup.send(embed=make_embed("PZ — Players", desc, SEV_GREEN), ephemeral=True)


@tree.command(name="pz_logstats", description="Show console log stats", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logstats(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_logscan()
    if code != 0:
        await i.followup.send(embed=make_embed("PZ — Log Stats", f"Log scan failed:\n{_codeblock(out, 1200)}", SEV_RED), ephemeral=True)
        return

    payload = _parse_logscan_json(out)
    s1 = payload.get("stats_1h") or {}
    s24 = payload.get("stats_24h") or {}
    s30 = payload.get("stats_30d") or {}

    warn = _safe_int(s1.get("warn", 0))
    error = _safe_int(s1.get("error", 0))
    stack = _safe_int(s1.get("stack", 0))
    color, emoji = severity_style(warn, error, stack)

    desc = (
        f"**Last 1h** — WARN `{warn}`, ERROR `{error}`, STACK `{stack}`\n"
        f"**Last 24h** — WARN `{_safe_int(s24.get('warn',0))}`, ERROR `{_safe_int(s24.get('error',0))}`, STACK `{_safe_int(s24.get('stack',0))}`\n"
        f"**Last 30d** — WARN `{_safe_int(s30.get('warn',0))}`, ERROR `{_safe_int(s30.get('error',0))}`, STACK `{_safe_int(s30.get('stack',0))}`\n\n"
        f"**Log:** `{payload.get('log_path','')}`"
    )
    emb = discord.Embed(title=f"{emoji} PZ — Log Stats", description=desc, color=color)
    emb.timestamp = discord.utils.utcnow()
    await i.followup.send(embed=emb, ephemeral=True)


@tree.command(name="pz_save", description="Save world now (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_save(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "save"):
        await i.response.send_message(embed=make_embed("Cooldown", "Please wait before using `/pz_save` again.", SEV_ORANGE), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_control("save")
    ok = (code == 0) and ("ERROR" not in out.upper())
    await i.followup.send(embed=make_embed("PZ — Save", f"**Result:**\n{_codeblock(out, 1500)}", SEV_GREEN if ok else SEV_RED), ephemeral=True)


async def _confirm_and_run(i: discord.Interaction, action: str, title: str, enforce_nick: bool = False):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, action):
        await i.response.send_message(embed=make_embed("Cooldown", f"Please wait before using `{action}` again.", SEV_ORANGE), ephemeral=True)
        return

    pending = PendingAction(action=action, created_at=time.time(), interaction_user_id=i.user.id)

    async def on_confirm(inter2: discord.Interaction):
        await inter2.response.defer(ephemeral=True)
        code, out = await run_control(action)
        ok = (code == 0) and ("ERROR" not in out.upper())

        if enforce_nick:
            await ensure_bot_nickname()

        await inter2.followup.send(
            embed=make_embed(title, f"**Result:**\n{_codeblock(out, 1500)}", SEV_GREEN if ok else SEV_RED),
            ephemeral=True,
        )

    view = ConfirmView(cfg, pending, on_confirm)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Confirm action: **{action.upper()}**", SEV_ORANGE),
        view=view,
        ephemeral=True,
    )


@tree.command(name="pz_stop", description="Stop server (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_stop(i: discord.Interaction):
    await _confirm_and_run(i, "stop", "PZ — Stop", enforce_nick=False)


@tree.command(name="pz_start", description="Start server (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_start(i: discord.Interaction):
    await _confirm_and_run(i, "start", "PZ — Start", enforce_nick=True)


@tree.command(name="pz_restart", description="Restart server (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_restart(i: discord.Interaction):
    await _confirm_and_run(i, "restart", "PZ — Restart", enforce_nick=True)


@tree.command(name="pz_workshop_check", description="Check Workshop updates (webhook)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_workshop_check(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "workshop_check"):
        await i.response.send_message(embed=make_embed("Cooldown", "Please wait before running the check again.", SEV_ORANGE), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_workshop_check()

    ok = (code == 0)
    msg = "✅ Workshop check triggered via webhook." if ok else f"❌ Workshop check failed:\n{_codeblock(out, 1500)}"
    await i.followup.send(embed=make_embed("PZ — Workshop Check", msg, SEV_GREEN if ok else SEV_RED), ephemeral=True)


@tree.command(name="pz_grant", description="Grant the PZ role to a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to grant access")
async def pz_grant(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_grant(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Grant", "Role not found (wrong ID?).", SEV_RED), ephemeral=True)
            return
        await user.add_roles(role, reason=f"pz_grant by {user_tag(i)}")
        audit_log(cfg, f"grant role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Grant", f"✅ Role **{role.name}** granted to {user.mention}.", SEV_GREEN), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("grant", time.time(), i.user.id), do_grant)
    await i.response.send_message(embed=make_embed("Confirmation required", f"Grant PZ role to {user.mention}?", SEV_ORANGE), view=view, ephemeral=True)


@tree.command(name="pz_revoke", description="Revoke the PZ role from a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to revoke access from")
async def pz_revoke(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_revoke(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Revoke", "Role not found (wrong ID?).", SEV_RED), ephemeral=True)
            return
        await user.remove_roles(role, reason=f"pz_revoke by {user_tag(i)}")
        audit_log(cfg, f"revoke role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Revoke", f"✅ Role **{role.name}** revoked from {user.mention}.", SEV_GREEN), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("revoke", time.time(), i.user.id), do_revoke)
    await i.response.send_message(embed=make_embed("Confirmation required", f"Revoke PZ role from {user.mention}?", SEV_ORANGE), view=view, ephemeral=True)


# ------------------ Events ------------------
@client.event
async def on_ready():
    logger.info("✅ Bot ready as %s (id=%s)", client.user, client.user.id)
    logger.info("✅ Guild ID: %s", cfg.DISCORD_GUILD_ID)

    try:
        await tree.sync(guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
        logger.info("✅ Commands synced (guild scoped).")
    except Exception as e:
        logger.exception("Command sync failed: %s", e)

    # Enforce nickname on startup
    await ensure_bot_nickname()

    client.loop.create_task(update_presence_loop())
    client.loop.create_task(monitor_console_loop())


# ------------------ Run ------------------
client.run(cfg.DISCORD_BOT_TOKEN)
