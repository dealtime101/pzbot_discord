# discord_bot.py
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import discord
from discord import app_commands

from config import load_config, Config


# ------------------ Logging ------------------
def setup_logging(cfg: Config) -> logging.Logger:
    os.makedirs(cfg.LOG_DIR, exist_ok=True)

    logger = logging.getLogger("pzbot")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on restarts
    if logger.handlers:
        for h in list(logger.handlers):
            logger.removeHandler(h)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(cfg.BOT_LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    logger.info("=== PZBot logging started ===")
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
        "-ExecutionPolicy",
        "Bypass",
        "-NonInteractive",
        "-File",
        script_path,
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
    return p.returncode, text[:1800]


# Severity palette (Discord embed colors)
SEV_GREEN = 0x2ecc71
SEV_ORANGE = 0xF39C12
SEV_RED = 0xE74C3C
SEV_BLUE = 0x3498db


def severity_style(warn: int, error: int, stack: int) -> tuple[int, str]:
    if error > 0 or stack > 0:
        return SEV_RED, "🚨"
    if warn > 0:
        return SEV_ORANGE, "⚠️"
    return SEV_GREEN, "✅"


def make_embed(title: str, description: str, color: int) -> discord.Embed:
    emb = discord.Embed(title=title, description=description, color=color)
    emb.timestamp = discord.utils.utcnow()
    return emb


def user_tag(i: discord.Interaction) -> str:
    u = i.user
    return f"{u.name}({u.id})"


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
    if cfg.PZ_ADMIN_ROLE_ID <= 0:
        return False
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
                "Unable to resolve the member. Check **Server Members Intent**.",
                SEV_RED,
            ),
            ephemeral=True,
        )
        return None

    if has_admin_role(cfg, m) or has_discord_admin_perm(m) or has_channel_permission(cfg, i, m):
        return m

    await i.response.send_message(
        embed=make_embed("Access denied", "You do not have permission to run this command.", SEV_RED),
        ephemeral=True,
    )
    return None


# ------------------ Cooldown ------------------
class Cooldown:
    def __init__(self, seconds: int):
        self.seconds = max(0, int(seconds))
        self._last: dict[tuple[int, str], float] = {}

    def check(self, user_id: int, key: str) -> bool:
        if self.seconds <= 0:
            return True
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
                embed=make_embed("Confirmation", "Only the command author can confirm.", SEV_RED),
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


# ------------------ Bot bootstrap ------------------
cfg = load_config()
logger = setup_logging(cfg)
cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

intents = discord.Intents.default()
intents.members = True  # needed for role checks & nickname
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

# Files (no env vars)
IGNORE_FILE = Path(cfg.LOG_DIR) / "pz_ignore_regex.txt"
DEDUP_FILE = Path(cfg.LOG_DIR) / "pz_bug_dedup.json"


# ------------------ Ignore list helpers ------------------
def load_ignore_patterns() -> list[str]:
    try:
        if not IGNORE_FILE.exists():
            return []
        lines = IGNORE_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        out: list[str] = []
        for ln in lines:
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            out.append(t)
        # unique keep order
        seen = set()
        uniq: list[str] = []
        for p in out:
            if p not in seen:
                uniq.append(p)
                seen.add(p)
        return uniq
    except Exception:
        return []


def save_ignore_patterns(patterns: list[str]) -> None:
    IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(patterns).strip() + ("\n" if patterns else "")
    IGNORE_FILE.write_text(text, encoding="utf-8")


def validate_regex(pat: str) -> tuple[bool, str]:
    try:
        re.compile(pat)
        return True, ""
    except re.error as e:
        return False, str(e)


# ------------------ Dedup helpers (for bug reports) ------------------
def load_dedup_state() -> dict[str, float]:
    try:
        if not DEDUP_FILE.exists():
            return {}
        data = json.loads(DEDUP_FILE.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict):
            return {str(k): float(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def save_dedup_state(state: dict[str, float]) -> None:
    try:
        DEDUP_FILE.parent.mkdir(parents=True, exist_ok=True)
        DEDUP_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


# ------------------ Control runners ------------------
async def run_control(action: str) -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, ["-Action", action])


async def run_workshop_check() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [])


async def run_logscan() -> tuple[int, str]:
    args = ["-LogPath", cfg.PZ_CONSOLE_LOG, "-IgnoreFile", str(IGNORE_FILE)]
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_LOGSCAN_PS1, args)


# ------------------ Presence loop ------------------
async def update_presence_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_control("status")
            status, players = parse_status_with_players(out)

            if status == "RUNNING":
                await client.change_presence(
                    activity=discord.Game(f"PZ: RUNNING({players})"),
                    status=discord.Status.online,
                )
            elif status == "STOPPED":
                await client.change_presence(
                    activity=discord.Game("PZ: STOPPED"),
                    status=discord.Status.idle,
                )
            else:
                await client.change_presence(
                    activity=discord.Game("PZ: ?"),
                    status=discord.Status.dnd,
                )
        except Exception:
            pass

        await asyncio.sleep(cfg.STATUS_REFRESH_SECONDS)


# ------------------ Bug report alert loop (NO mentions) ------------------
async def bug_alert_loop():
    await client.wait_until_ready()

    if cfg.DISCORD_BUGS_CHANNEL_ID <= 0:
        logger.info("Bug alerts disabled: DISCORD_BUGS_CHANNEL_ID not set.")
        return

    # warm-up: set offset without sending alerts
    try:
        await run_logscan()
        logger.info("Logscan warm-up done (no alerts).")
    except Exception as e:
        logger.exception("Logscan warm-up failed: %s", e)

    dedup = load_dedup_state()
    ttl_seconds = 10 * 60  # 10 minutes

    while not client.is_closed():
        try:
            code, out = await run_logscan()
            if code != 0:
                await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)
                continue

            data = json.loads(out)
            new_critical_count = int(data.get("new_critical_count", 0) or 0)
            if new_critical_count <= 0:
                await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)
                continue

            recent = data.get("recent_critical", []) or []
            last = recent[-1] if recent else None
            sig = str((last or {}).get("signature", "")).strip()
            excerpt = str((last or {}).get("excerpt", "")).strip()

            now = time.time()
            dedup = {k: v for k, v in dedup.items() if (now - v) <= ttl_seconds}

            if sig and sig in dedup:
                save_dedup_state(dedup)
                await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)
                continue

            if sig:
                dedup[sig] = now
                save_dedup_state(dedup)

            stats1h = data.get("stats_1h", {}) or {}
            warn1 = int(stats1h.get("warn", 0) or 0)
            err1 = int(stats1h.get("error", 0) or 0)
            stack1 = int(stats1h.get("stack", 0) or 0)

            color, emoji = severity_style(warn1, err1, stack1)

            title = f"{emoji} PZ — Console Alert"
            desc = f"**New critical events:** `{new_critical_count}`\n"
            if sig:
                desc += f"**Signature:** `{sig}`\n"
            if excerpt:
                excerpt_short = excerpt[:1200]
                desc += f"\n```text\n{excerpt_short}\n```"

            # stats blocks
            s24 = data.get("stats_24h", {}) or {}
            s3d = data.get("stats_3d", {}) or {}
            s7d = data.get("stats_7d", {}) or {}
            s30 = data.get("stats_30d", {}) or {}

            desc += (
                f"\n**Last 1h** — WARN `{warn1}`, ERROR `{err1}`, STACK `{stack1}`"
                f"\n**Last 24h** — WARN `{s24.get('warn',0)}`, ERROR `{s24.get('error',0)}`, STACK `{s24.get('stack',0)}`"
                f"\n**Last 3d** — WARN `{s3d.get('warn',0)}`, ERROR `{s3d.get('error',0)}`, STACK `{s3d.get('stack',0)}`"
                f"\n**Last 7d** — WARN `{s7d.get('warn',0)}`, ERROR `{s7d.get('error',0)}`, STACK `{s7d.get('stack',0)}`"
                f"\n**Last 30d** — WARN `{s30.get('warn',0)}`, ERROR `{s30.get('error',0)}`, STACK `{s30.get('stack',0)}`"
                f"\n\n**Log:** `{data.get('log_path','')}`"
            )

            ch = client.get_channel(cfg.DISCORD_BUGS_CHANNEL_ID)
            if ch is None:
                ch = await client.fetch_channel(cfg.DISCORD_BUGS_CHANNEL_ID)

            await ch.send(embed=make_embed(title, desc, color))

        except Exception as e:
            logger.exception("bug_alert_loop error: %s", e)

        await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)


def log_action(i: discord.Interaction, action: str, exit_code: int, out: str):
    g = i.guild.id if i.guild else 0
    ch = i.channel.id if i.channel else 0
    line = f"action={action} user={user_tag(i)} guild={g} channel={ch} exit={exit_code} out={out.replace(chr(10),'\\n')[:200]}"
    logger.info(line)
    audit_log(cfg, line)


# ------------------ Commands ------------------
@tree.command(name="pz_help", description="Show PZBot commands")
async def pz_help(i: discord.Interaction):
    desc = (
        "**Core**\n"
        "• `/pz_status` — Server status\n"
        "• `/pz_players` — Online players\n"
        "• `/pz_version` — Bot version\n\n"
        "**Logs**\n"
        "• `/pz_logstats` — Log stats (1h/24h/3d/7d/30d)\n"
        "• `/pz_logs_recent` — Recent critical excerpts\n"
        "• `/pz_logs_top` — Top signatures (24h)\n\n"
        "**Ignore list**\n"
        "• `/pz_ignore_add <regex>`\n"
        "• `/pz_ignore_remove <regex>`\n"
        "• `/pz_ignore_list`\n\n"
        "**Admin**\n"
        "• `/pz_start` `/pz_stop` `/pz_restart`\n"
        "• `/pz_workshop_check` — Run workshop check now\n"
    )
    await i.response.send_message(embed=make_embed("PZ — Help", desc, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_version", description="Show bot version")
async def pz_version(i: discord.Interaction):
    await i.response.send_message(
        embed=make_embed("PZ — Version", f"**PZBot:** `{cfg.BOT_VERSION}`", SEV_BLUE),
        ephemeral=True,
    )


@tree.command(name="pz_status", description="Show server status")
async def pz_status(i: discord.Interaction):
    code, out = await run_control("status")
    status, players = parse_status_with_players(out)
    ok = status == "RUNNING"
    color = SEV_GREEN if ok else SEV_ORANGE if status == "STOPPED" else SEV_RED
    desc = f"**Status:** `{status}`\n**Players:** `{players}`"
    await i.response.send_message(embed=make_embed("PZ — Status", desc, color), ephemeral=True)


@tree.command(name="pz_players", description="Show online players")
async def pz_players(i: discord.Interaction):
    code, out = await run_control("players")
    color = SEV_BLUE if code == 0 else SEV_RED
    await i.response.send_message(embed=make_embed("PZ — Players", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_workshop_check", description="Run workshop check now")
async def pz_workshop_check(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if m is None:
        return
    code, out = await run_workshop_check()
    color = SEV_GREEN if code == 0 else SEV_RED
    log_action(i, "workshop_check", code, out)
    await i.response.send_message(embed=make_embed("PZ — Workshop Check", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_start", description="Start the PZ server (admin)")
async def pz_start(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if m is None:
        return
    code, out = await run_control("start")
    log_action(i, "start", code, out)
    await i.response.send_message(embed=make_embed("PZ — Start", f"```{out}```", SEV_BLUE), ephemeral=True)


@tree.command(name="pz_stop", description="Stop the PZ server (admin)")
async def pz_stop(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if m is None:
        return

    pending = PendingAction("stop", time.time(), i.user.id)

    async def do_confirm(interaction: discord.Interaction):
        code, out = await run_control("stop")
        log_action(i, "stop", code, out)
        await interaction.response.edit_message(embed=make_embed("PZ — Stop", f"```{out}```", SEV_BLUE), view=None)

    await i.response.send_message(
        embed=make_embed("Confirm", "Stop the server?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
    )


@tree.command(name="pz_restart", description="Restart the PZ server (admin)")
async def pz_restart(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if m is None:
        return

    pending = PendingAction("restart", time.time(), i.user.id)

    async def do_confirm(interaction: discord.Interaction):
        code, out = await run_control("restart")
        log_action(i, "restart", code, out)
        await interaction.response.edit_message(embed=make_embed("PZ — Restart", f"```{out}```", SEV_BLUE), view=None)

    await i.response.send_message(
        embed=make_embed("Confirm", "Restart the server?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
    )


@tree.command(name="pz_ignore_list", description="List ignore regex patterns")
async def pz_ignore_list(i: discord.Interaction):
    pats = load_ignore_patterns()
    if not pats:
        await i.response.send_message(embed=make_embed("PZ — Ignore List", "(empty)", SEV_BLUE), ephemeral=True)
        return
    body = "\n".join(f"• `{p}`" for p in pats[:50])
    if len(pats) > 50:
        body += f"\n… and {len(pats)-50} more"
    await i.response.send_message(embed=make_embed("PZ — Ignore List", body, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_ignore_add", description="Add a regex to ignore list")
@app_commands.describe(regex="Regex pattern to ignore")
async def pz_ignore_add(i: discord.Interaction, regex: str):
    m = await require_admin(cfg, i)
    if m is None:
        return

    regex = (regex or "").strip()
    ok, err = validate_regex(regex)
    if not ok:
        await i.response.send_message(
            embed=make_embed("Invalid regex", f"`{regex}`\nError: `{err}`", SEV_RED),
            ephemeral=True,
        )
        return

    pats = load_ignore_patterns()
    if regex in pats:
        await i.response.send_message(embed=make_embed("PZ — Ignore", "Already present.", SEV_BLUE), ephemeral=True)
        return

    pats.append(regex)
    save_ignore_patterns(pats)
    await i.response.send_message(embed=make_embed("PZ — Ignore", f"Added: `{regex}`", SEV_GREEN), ephemeral=True)


@tree.command(name="pz_ignore_remove", description="Remove a regex from ignore list")
@app_commands.describe(regex="Regex pattern to remove")
async def pz_ignore_remove(i: discord.Interaction, regex: str):
    m = await require_admin(cfg, i)
    if m is None:
        return

    regex = (regex or "").strip()
    pats = load_ignore_patterns()
    if regex not in pats:
        await i.response.send_message(embed=make_embed("PZ — Ignore", "Not found.", SEV_ORANGE), ephemeral=True)
        return

    pats = [p for p in pats if p != regex]
    save_ignore_patterns(pats)
    await i.response.send_message(embed=make_embed("PZ — Ignore", f"Removed: `{regex}`", SEV_GREEN), ephemeral=True)


@tree.command(name="pz_logstats", description="Show log stats (1h/24h/3d/7d/30d)")
async def pz_logstats(i: discord.Interaction):
    code, out = await run_logscan()
    if code != 0:
        await i.response.send_message(embed=make_embed("PZ — Log Stats", f"```{out}```", SEV_RED), ephemeral=True)
        return

    data = json.loads(out)
    s1 = data.get("stats_1h", {}) or {}
    s24 = data.get("stats_24h", {}) or {}
    s3d = data.get("stats_3d", {}) or {}
    s7d = data.get("stats_7d", {}) or {}
    s30 = data.get("stats_30d", {}) or {}

    warn = int(s1.get("warn", 0) or 0)
    err = int(s1.get("error", 0) or 0)
    stack = int(s1.get("stack", 0) or 0)

    color, emoji = severity_style(warn, err, stack)

    desc = (
        f"**Last 1h** — WARN `{warn}`, ERROR `{err}`, STACK `{stack}`\n"
        f"**Last 24h** — WARN `{s24.get('warn',0)}`, ERROR `{s24.get('error',0)}`, STACK `{s24.get('stack',0)}`\n"
        f"**Last 3d** — WARN `{s3d.get('warn',0)}`, ERROR `{s3d.get('error',0)}`, STACK `{s3d.get('stack',0)}`\n"
        f"**Last 7d** — WARN `{s7d.get('warn',0)}`, ERROR `{s7d.get('error',0)}`, STACK `{s7d.get('stack',0)}`\n"
        f"**Last 30d** — WARN `{s30.get('warn',0)}`, ERROR `{s30.get('error',0)}`, STACK `{s30.get('stack',0)}`\n\n"
        f"**Log:** `{data.get('log_path','')}`"
    )

    emb = discord.Embed(title=f"{emoji} PZ — Log Stats", description=desc, color=color)
    emb.timestamp = discord.utils.utcnow()
    await i.response.send_message(embed=emb, ephemeral=True)


@tree.command(name="pz_logs_recent", description="Show recent critical excerpts from the last scan")
async def pz_logs_recent(i: discord.Interaction):
    code, out = await run_logscan()
    if code != 0:
        await i.response.send_message(embed=make_embed("PZ — Logs Recent", f"```{out}```", SEV_RED), ephemeral=True)
        return

    data = json.loads(out)
    recent = data.get("recent_critical", []) or []
    if not recent:
        await i.response.send_message(embed=make_embed("PZ — Logs Recent", "(none)", SEV_GREEN), ephemeral=True)
        return

    lines = []
    for ev in recent[-8:]:
        sig = str(ev.get("signature", "")).strip()
        excerpt = str(ev.get("excerpt", "")).strip().replace("\n", " ")
        excerpt = excerpt[:180]
        if sig:
            lines.append(f"• `{sig}` — {excerpt}")
        else:
            lines.append(f"• {excerpt}")

    await i.response.send_message(embed=make_embed("PZ — Logs Recent", "\n".join(lines), SEV_BLUE), ephemeral=True)


@tree.command(name="pz_logs_top", description="Show top signatures (24h)")
async def pz_logs_top(i: discord.Interaction):
    code, out = await run_logscan()
    if code != 0:
        await i.response.send_message(embed=make_embed("PZ — Logs Top", f"```{out}```", SEV_RED), ephemeral=True)
        return

    data = json.loads(out)
    top = data.get("top_signatures_24h", []) or []
    if not top:
        await i.response.send_message(embed=make_embed("PZ — Logs Top", "(none)", SEV_GREEN), ephemeral=True)
        return

    rows = []
    for item in top[:10]:
        sig = str(item.get("signature", "")).strip()
        count = int(item.get("count", 0) or 0)
        label = str(item.get("label", "")).strip()
        if label:
            rows.append(f"• **{label}** × `{count}`")
        else:
            rows.append(f"• `{sig}` × `{count}`")

    await i.response.send_message(embed=make_embed("PZ — Logs Top (24h)", "\n".join(rows), SEV_BLUE), ephemeral=True)


# ------------------ Events ------------------
@client.event
async def on_ready():
    logger.info("Logged in as %s (%s)", client.user, client.user.id)

    # Auto nickname to "PZBot"
    try:
        guild = client.get_guild(cfg.DISCORD_GUILD_ID) or await client.fetch_guild(cfg.DISCORD_GUILD_ID)
        me = guild.get_member(client.user.id) or await guild.fetch_member(client.user.id)
        if me and me.nick != "PZBot":
            await me.edit(nick="PZBot")
    except Exception:
        pass

    try:
        await tree.sync(guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
        logger.info("Slash commands synced.")
    except Exception as e:
        logger.exception("Slash sync failed: %s", e)


# ------------------ Main ------------------
async def main():
    client.loop.create_task(update_presence_loop())
    client.loop.create_task(bug_alert_loop())
    await client.start(cfg.DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
