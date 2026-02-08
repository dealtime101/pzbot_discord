# discord_bot.py
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Optional

import discord
from discord import app_commands

from config import load_config, Config


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

    logger.info("=== PZBot logging started ===")
    logger.info("Log file: %s", cfg.BOT_LOG_FILE)
    logger.info("Version: %s", cfg.BOT_VERSION)
    return logger


def audit_log(cfg: Config, line: str) -> None:
    os.makedirs(cfg.LOG_DIR, exist_ok=True)
    with open(cfg.ACTION_AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")


# ------------------ Helpers ------------------
async def run_powershell_script(
    ps_exe: str,
    script_path: str,
    args: list[str],
    *,
    timeout_seconds: int,
) -> tuple[int, str]:
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

    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        try:
            p.kill()
        except Exception:
            pass
        return 124, f"TIMEOUT after {timeout_seconds}s while running: {os.path.basename(script_path)} {' '.join(args)}"

    text = (out or b"").decode("utf-8", errors="replace").strip()
    if not text:
        text = "(no output)"
    return p.returncode or 0, text[:1800]


def make_embed(title: str, description: str, *, ok: bool | None = None, color: int | None = None) -> discord.Embed:
    if color is None:
        if ok is True:
            color = 0x2ecc71
        elif ok is False:
            color = 0xe74c3c
        else:
            color = 0x3498db

    emb = discord.Embed(title=title, description=description, color=color)
    emb.timestamp = discord.utils.utcnow()
    return emb


def user_tag(i: discord.Interaction) -> str:
    u = i.user
    return f"{u.name}({u.id})"


def parse_status_with_players(out: str) -> tuple[str, str]:
    t = (out or "").strip()

    status = "UNKNOWN"
    up = t.upper()
    if "RUNNING" in up:
        status = "RUNNING"
    elif "STOPPED" in up:
        status = "STOPPED"

    m = re.search(r"(?i)\bplayers\s*=\s*(\d+|\?)\b", t)
    players = m.group(1) if m else "?"
    return status, players


def severity_style(warn: int, error: int, stack: int) -> tuple[int, str]:
    if error > 0 or stack > 0:
        return 0xE74C3C, "🚨"
    if warn > 0:
        return 0xE67E22, "⚠️"
    return 0x2ECC71, "✅"


# ------------------ Ignore list (file-backed) ------------------
_ignore_lock = asyncio.Lock()

def _normalize_regex_line(s: str) -> str:
    return (s or "").strip()

def _read_ignore_list(cfg: Config) -> list[str]:
    p = cfg.IGNORE_FILE
    if not os.path.exists(p):
        return []
    lines: list[str] = []
    with open(p, "r", encoding="utf-8") as f:
        for raw in f.readlines():
            t = raw.strip()
            if not t or t.startswith("#"):
                continue
            lines.append(t)
    seen = set()
    out = []
    for x in lines:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def _write_ignore_list(cfg: Config, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(cfg.IGNORE_FILE) or ".", exist_ok=True)
    with open(cfg.IGNORE_FILE, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l.rstrip() + "\n")


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
            embed=make_embed("Access denied", "Could not resolve member. Check **Server Members Intent**.", ok=False),
            ephemeral=True,
        )
        return None

    if has_admin_role(cfg, m) or has_discord_admin_perm(m) or has_channel_permission(cfg, i, m):
        return m

    await i.response.send_message(
        embed=make_embed("Access denied", "You don't have permission to run this command.", ok=False),
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
                embed=make_embed("Confirmation", "Only the command author can confirm.", ok=False),
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
            embed=make_embed("Cancelled", "Action cancelled.", ok=None),
            view=None,
        )
        self.stop()


# ------------------ Bot ------------------
cfg = load_config()
logger = setup_logging(cfg)
cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

intents = discord.Intents.default()
intents.members = True


class PZClient(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self) -> None:
        try:
            await self.tree.sync(guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
            logger.info("✅ Commands synced (guild scoped).")
        except Exception as e:
            logger.exception("Command sync failed: %s", e)

        asyncio.create_task(update_presence_loop())
        asyncio.create_task(console_monitor_loop())


client = PZClient()
tree = client.tree


async def run_control(action: str, extra_args: list[str] | None = None) -> tuple[int, str]:
    args = ["-Action", action]
    if extra_args:
        args.extend(extra_args)
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, args, timeout_seconds=cfg.PS_TIMEOUT_SECONDS)


async def run_workshop_check() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [], timeout_seconds=cfg.WORKSHOP_TIMEOUT_SECONDS)


async def run_logscan() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_LOGSCAN_PS1, [], timeout_seconds=cfg.LOGSCAN_TIMEOUT_SECONDS)


def log_action(i: discord.Interaction, action: str, exit_code: int, out: str):
    g = i.guild.id if i.guild else 0
    ch = i.channel.id if i.channel else 0
    line = f"action={action} user={user_tag(i)} guild={g} channel={ch} exit={exit_code} out={out.replace(chr(10),'\\\\n')[:200]}"
    logger.info(line)
    audit_log(cfg, line)


# ------------------ Presence loop ------------------
async def update_presence_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_control("status")
            status, players = parse_status_with_players(out)

            if status == "RUNNING":
                label = f"PZ: RUNNING({players})" if players != "?" else "PZ: RUNNING"
                await client.change_presence(activity=discord.Game(label), status=discord.Status.online)
            elif status == "STOPPED":
                await client.change_presence(activity=discord.Game("PZ: STOPPED"), status=discord.Status.idle)
            else:
                await client.change_presence(activity=discord.Game("PZ: ?"), status=discord.Status.dnd)
        except Exception:
            pass

        await asyncio.sleep(cfg.STATUS_REFRESH_SECONDS)


# ------------------ Console monitor loop ------------------
_alert_seen: dict[str, float] = {}

def _signature_from_lines(lines: list[str]) -> str:
    if not lines:
        return ""
    head = lines[0]
    head = re.sub(r"\d+", "N", head)
    return head[:180]

async def _post_console_alert(payload: dict) -> None:
    ch_id = cfg.DISCORD_BUGS_CHANNEL_ID
    if not ch_id:
        return
    channel = client.get_channel(ch_id)
    if channel is None:
        try:
            channel = await client.fetch_channel(ch_id)
        except Exception:
            return

    stats1h = payload.get("stats_1h") or {}
    stats24h = payload.get("stats_24h") or {}
    stats3d = payload.get("stats_3d") or {}
    stats7d = payload.get("stats_7d") or {}
    stats30d = payload.get("stats_30d") or {}

    nw = int(payload.get("new_warn", 0))
    ne = int(payload.get("new_error", 0))
    ns = int(payload.get("new_stack", 0))
    ignored = int(payload.get("ignored_total", 0))
    sent = int(payload.get("sent", 0))

    color, emoji = severity_style(nw, ne, ns)

    lines = payload.get("new_critical_lines") or []
    preview = "\n\n".join([f"```{l[:900]}```" for l in lines[:3]]) if lines else "(no details)"

    desc = (
        f"**New critical:** `{ne + ns}` | **Ignored:** `{ignored}` | **Sent:** `{sent}`\n"
        f"**New WARN:** `{nw}` **New ERROR:** `{ne}` **New STACK:** `{ns}`\n\n"
        f"{preview}\n\n"
        f"**Last 1h** — WARN `{int(stats1h.get('warn',0))}`, ERROR `{int(stats1h.get('error',0))}`, STACK `{int(stats1h.get('stack',0))}`\n"
        f"**Last 24h** — WARN `{int(stats24h.get('warn',0))}`, ERROR `{int(stats24h.get('error',0))}`, STACK `{int(stats24h.get('stack',0))}`\n"
        f"**Last 3d** — WARN `{int(stats3d.get('warn',0))}`, ERROR `{int(stats3d.get('error',0))}`, STACK `{int(stats3d.get('stack',0))}`\n"
        f"**Last 7d** — WARN `{int(stats7d.get('warn',0))}`, ERROR `{int(stats7d.get('error',0))}`, STACK `{int(stats7d.get('stack',0))}`\n"
        f"**Last 30d** — WARN `{int(stats30d.get('warn',0))}`, ERROR `{int(stats30d.get('error',0))}`, STACK `{int(stats30d.get('stack',0))}`\n"
    )

    emb = make_embed(f"{emoji} PZ — Console Alert", desc, ok=None, color=color)
    await channel.send(embed=emb)

async def console_monitor_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_logscan()
            if code != 0:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            import json as _json
            payload = _json.loads(out)
            crit = int(payload.get("new_critical_count", 0))
            if crit <= 0:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            lines = payload.get("new_critical_lines") or []
            sig = _signature_from_lines(lines)
            now = time.time()
            if sig and (sig in _alert_seen) and (now - _alert_seen[sig] < 300):
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue
            if sig:
                _alert_seen[sig] = now

            payload["sent"] = 1
            await _post_console_alert(payload)

        except Exception:
            pass

        await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)


# ------------------ Commands ------------------
@tree.command(name="pz_ping", description="Bot healthcheck", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.send_message(embed=make_embed("PZ — Ping", "✅ Pong.", ok=True), ephemeral=True)


@tree.command(name="pz_version", description="Show bot version", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_version(i: discord.Interaction):
    await i.response.send_message(embed=make_embed("PZ — Version", f"`{cfg.BOT_VERSION}`", ok=True), ephemeral=True)


@tree.command(name="pz_help", description="Command list + access rules", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        "**Commands**\n"
        "• `/pz_status` — server status + online player count\n"
        "• `/pz_players` — list online players\n"
        "• `/pz_logstats` — console log stats (1h/24h/3d/7d/30d)\n"
        "• `/pz_ignore_list` — show ignore regex list\n"
        "• `/pz_ignore_add <regex>` — add ignore regex\n"
        "• `/pz_ignore_remove <regex>` — remove ignore regex\n"
        "• `/pz_save` — save world (sensitive)\n"
        "• `/pz_stop` — stop server (sensitive, confirmation)\n"
        "• `/pz_start` — start server (sensitive, confirmation)\n"
        "• `/pz_restart` — restart server (sensitive, confirmation)\n"
        "• `/pz_workshop_check` — check Workshop updates (webhook)\n"
        "• `/pz_grant @user` — grant PZ role\n"
        "• `/pz_revoke @user` — revoke PZ role\n"
        "• `/pz_ping` — bot healthcheck\n"
        "• `/pz_version` — bot version\n\n"
        "**Access**\n"
        f"• Required role: <@&{cfg.PZ_ADMIN_ROLE_ID}>\n"
        "• OR Discord permission: `Administrator`\n"
        "• OR (if enabled) channel perms: `manage_guild` / `manage_channels` / `manage_messages`\n\n"
        f"**Cooldown**: {cfg.COOLDOWN_SECONDS}s (sensitive commands)\n"
        f"**Confirmation**: {cfg.CONFIRM_SECONDS}s (stop/start/restart/grant/revoke)\n"
    )
    await i.response.send_message(embed=make_embed("PZ — Help", desc, ok=None), ephemeral=True)


@tree.command(name="pz_status", description="Project Zomboid server status", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_status(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("status")
    status, players = parse_status_with_players(out)

    ok = (code == 0) and (status in ("RUNNING", "STOPPED"))
    desc = f"**Status:** `{status}`\n**Online players:** `{players}`"
    emb = make_embed("PZ — Status", desc, ok=ok)
    log_action(i, "status", code, out)
    await i.followup.send(embed=emb, ephemeral=True)


@tree.command(name="pz_players", description="List online players", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_players(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("players")
    t = (out or "").strip()

    if "STOPPED" in t.upper():
        emb = make_embed("PZ — Players", "🛑 Server stopped.", ok=False)
        log_action(i, "players", code, out)
        await i.followup.send(embed=emb, ephemeral=True)
        return

    if t in ("(none)", ""):
        emb = make_embed("PZ — Players", "No players online.", ok=True)
        log_action(i, "players", code, out)
        await i.followup.send(embed=emb, ephemeral=True)
        return

    names = [line.strip() for line in t.splitlines() if line.strip()]
    bullets = "\n".join([f"• `{n}`" for n in names])
    emb = make_embed("PZ — Players", f"**{len(names)} player(s) online:**\n{bullets}", ok=True)

    log_action(i, "players", code, out)
    await i.followup.send(embed=emb, ephemeral=True)


@tree.command(name="pz_logstats", description="Console log stats", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logstats(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_logscan()
    if code != 0:
        log_action(i, "logstats", code, out)
        await i.followup.send(embed=make_embed("PZ — Log Stats", f"❌ `{out}`", ok=False), ephemeral=True)
        return

    import json as _json
    payload = _json.loads(out)

    s1h = payload.get("stats_1h") or {}
    s24h = payload.get("stats_24h") or {}
    s3d = payload.get("stats_3d") or {}
    s7d = payload.get("stats_7d") or {}
    s30d = payload.get("stats_30d") or {}
    log_path = payload.get("log_path", "?")

    warn = int(s1h.get("warn", 0))
    error = int(s1h.get("error", 0))
    stack = int(s1h.get("stack", 0))
    color, emoji = severity_style(warn, error, stack)

    desc = (
        f"**Last 1h** — WARN `{warn}`, ERROR `{error}`, STACK `{stack}`\n"
        f"**Last 24h** — WARN `{int(s24h.get('warn',0))}`, ERROR `{int(s24h.get('error',0))}`, STACK `{int(s24h.get('stack',0))}`\n"
        f"**Last 3d** — WARN `{int(s3d.get('warn',0))}`, ERROR `{int(s3d.get('error',0))}`, STACK `{int(s3d.get('stack',0))}`\n"
        f"**Last 7d** — WARN `{int(s7d.get('warn',0))}`, ERROR `{int(s7d.get('error',0))}`, STACK `{int(s7d.get('stack',0))}`\n"
        f"**Last 30d** — WARN `{int(s30d.get('warn',0))}`, ERROR `{int(s30d.get('error',0))}`, STACK `{int(s30d.get('stack',0))}`\n\n"
        f"**Log:** `{log_path}`"
    )

    emb = make_embed(f"{emoji} PZ — Log Stats", desc, ok=None, color=color)
    log_action(i, "logstats", code, out)
    await i.followup.send(embed=emb, ephemeral=True)


@tree.command(name="pz_ignore_list", description="Show ignore regex list", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ignore_list(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    async with _ignore_lock:
        lines = _read_ignore_list(cfg)

    if not lines:
        desc = f"(empty)\n\nFile: `{cfg.IGNORE_FILE}`"
        await i.followup.send(embed=make_embed("PZ — Ignore List", desc, ok=True), ephemeral=True)
        return

    body = "\n".join([f"• `{l}`" for l in lines[:40]])
    more = ""
    if len(lines) > 40:
        more = f"\n… (+{len(lines)-40} more)"
    desc = f"**{len(lines)} rule(s):**\n{body}{more}\n\nFile: `{cfg.IGNORE_FILE}`"
    await i.followup.send(embed=make_embed("PZ — Ignore List", desc, ok=True), ephemeral=True)


@tree.command(name="pz_ignore_add", description="Add an ignore regex", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(regex="Regex to ignore (applies to WARN/ERROR/STACK blocks)")
async def pz_ignore_add(i: discord.Interaction, regex: str):
    if await require_admin(cfg, i) is None:
        return

    r = _normalize_regex_line(regex)
    if not r:
        await i.response.send_message(embed=make_embed("PZ — Ignore Add", "❌ Regex is empty.", ok=False), ephemeral=True)
        return

    try:
        re.compile(r)
    except re.error as e:
        await i.response.send_message(embed=make_embed("PZ — Ignore Add", f"❌ Invalid regex: `{e}`", ok=False), ephemeral=True)
        return

    async with _ignore_lock:
        lines = _read_ignore_list(cfg)
        if r in lines:
            await i.response.send_message(embed=make_embed("PZ — Ignore Add", "Already present.", ok=True), ephemeral=True)
            return
        lines.append(r)
        _write_ignore_list(cfg, lines)

    await i.response.send_message(embed=make_embed("PZ — Ignore Add", f"✅ Added:\n`{r}`", ok=True), ephemeral=True)


@tree.command(name="pz_ignore_remove", description="Remove an ignore regex", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(regex="Exact regex line to remove")
async def pz_ignore_remove(i: discord.Interaction, regex: str):
    if await require_admin(cfg, i) is None:
        return

    r = _normalize_regex_line(regex)
    async with _ignore_lock:
        lines = _read_ignore_list(cfg)
        if r not in lines:
            await i.response.send_message(embed=make_embed("PZ — Ignore Remove", "Not found.", ok=False), ephemeral=True)
            return
        lines = [x for x in lines if x != r]
        _write_ignore_list(cfg, lines)

    await i.response.send_message(embed=make_embed("PZ — Ignore Remove", f"✅ Removed:\n`{r}`", ok=True), ephemeral=True)


@tree.command(name="pz_save", description="Save world now (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_save(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "save"):
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Please wait before running `/pz_save` again.", ok=False), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_control("save")
    ok = (code == 0) and ("ERROR" not in out.upper())
    log_action(i, "save", code, out)
    await i.followup.send(embed=make_embed("PZ — Save", f"**Result:** `{out}`", ok=ok), ephemeral=True)


async def _confirm_and_run(i: discord.Interaction, action: str, title: str):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, action):
        await i.response.send_message(embed=make_embed("Cooldown", f"⏳ Please wait before running `{action}` again.", ok=False), ephemeral=True)
        return

    pending = PendingAction(action=action, created_at=time.time(), interaction_user_id=i.user.id)

    async def on_confirm(inter2: discord.Interaction):
        await inter2.response.defer(ephemeral=True)
        code, out = await run_control(action)
        ok = (code == 0) and ("ERROR" not in out.upper()) and ("FAILED" not in out.upper())
        log_action(i, action, code, out)
        await inter2.followup.send(embed=make_embed(title, f"**Result:** `{out}`", ok=ok), ephemeral=True)

    view = ConfirmView(cfg, pending, on_confirm)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Confirm action: **{action.upper()}**", ok=None),
        view=view,
        ephemeral=True,
    )


@tree.command(name="pz_stop", description="Stop server (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_stop(i: discord.Interaction):
    await _confirm_and_run(i, "stop", "PZ — Stop")


@tree.command(name="pz_start", description="Start server (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_start(i: discord.Interaction):
    await _confirm_and_run(i, "start", "PZ — Start")


@tree.command(name="pz_restart", description="Restart server (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_restart(i: discord.Interaction):
    await _confirm_and_run(i, "restart", "PZ — Restart")


@tree.command(name="pz_workshop_check", description="Check Workshop updates (webhook)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_workshop_check(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "workshop_check"):
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Please wait before running the check again.", ok=False), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_workshop_check()
    ok = (code == 0)
    log_action(i, "workshop_check", code, out)
    await i.followup.send(
        embed=make_embed("Workshop Check", "✅ Check executed (webhook posts results)." if ok else f"❌ `{out}`", ok=ok),
        ephemeral=True,
    )


@tree.command(name="pz_grant", description="Grant the PZ role to a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to authorize")
async def pz_grant(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_grant(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Grant", "❌ Role not found (bad ID?).", ok=False), ephemeral=True)
            return
        await user.add_roles(role, reason=f"pz_grant by {user_tag(i)}")
        logger.info("grant role=%s(%s) target=%s(%s) by=%s", role.name, role.id, user.name, user.id, user_tag(i))
        audit_log(cfg, f"grant role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Grant", f"✅ Granted **{role.name}** to {user.mention}.", ok=True), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("grant", time.time(), i.user.id), do_grant)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Grant PZ role to {user.mention}?", ok=None),
        view=view,
        ephemeral=True,
    )


@tree.command(name="pz_revoke", description="Revoke the PZ role from a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to remove")
async def pz_revoke(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_revoke(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Revoke", "❌ Role not found (bad ID?).", ok=False), ephemeral=True)
            return
        await user.remove_roles(role, reason=f"pz_revoke by {user_tag(i)}")
        logger.info("revoke role=%s(%s) target=%s(%s) by=%s", role.name, role.id, user.name, user.id, user_tag(i))
        audit_log(cfg, f"revoke role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Revoke", f"✅ Revoked **{role.name}** from {user.mention}.", ok=True), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("revoke", time.time(), i.user.id), do_revoke)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Revoke PZ role from {user.mention}?", ok=None),
        view=view,
        ephemeral=True,
    )


@client.event
async def on_ready():
    logger.info("✅ Bot ready as %s (id=%s)", client.user, client.user.id)
    logger.info("✅ Guild ID: %s", cfg.DISCORD_GUILD_ID)
    logger.info("✅ Admin Role ID: %s", cfg.PZ_ADMIN_ROLE_ID)


if __name__ == "__main__":
    client.run(cfg.DISCORD_BOT_TOKEN)
