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
    return p.returncode, text[:1800]


# Severity palette (Discord embed colors)
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


def make_embed(title: str, description: str, color: int) -> discord.Embed:
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
            embed=make_embed("Access denied", "Unable to resolve member. Check **Server Members Intent**.", SEV_RED),
            ephemeral=True,
        )
        return None

    if has_admin_role(cfg, m) or has_discord_admin_perm(m) or has_channel_permission(cfg, i, m):
        return m

    await i.response.send_message(
        embed=make_embed("Access denied", "You don’t have permission to use this command.", SEV_RED),
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

    async def on_timeout(self):
        pass


# ------------------ Bot ------------------
cfg = load_config()
logger = setup_logging(cfg)
cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

intents = discord.Intents.default()
intents.members = True
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)

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
        seen = set()
        uniq = []
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
                await client.change_presence(activity=discord.Game(f"PZ: RUNNING({players})"), status=discord.Status.online)
            elif status == "STOPPED":
                await client.change_presence(activity=discord.Game("PZ: STOPPED"), status=discord.Status.idle)
            else:
                await client.change_presence(activity=discord.Game("PZ: ?"), status=discord.Status.dnd)
        except Exception:
            pass

        await asyncio.sleep(cfg.STATUS_REFRESH_SECONDS)


def log_action(i: discord.Interaction, action: str, exit_code: int, out: str):
    g = i.guild.id if i.guild else 0
    ch = i.channel.id if i.channel else 0
    line = f"action={action} user={user_tag(i)} guild={g} channel={ch} exit={exit_code} out={out.replace('\n','\\n')[:200]}"
    logger.info(line)
    audit_log(cfg, line)


# ------------------ Bug report alert loop (NO mentions) ------------------
async def bug_alert_loop():
    await client.wait_until_ready()

    if cfg.DISCORD_BUGS_CHANNEL_ID <= 0:
        logger.info("Bug alerts disabled: DISCORD_BUGS_CHANNEL_ID not set.")
        return

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
            # pick newest event as "main"
            last = recent[-1] if recent else None
            sig = str((last or {}).get("signature", "")).strip()
            excerpt = str((last or {}).get("excerpt", "")).strip()

            # dedup by signature
            now = time.time()
            # cleanup old dedup
            dedup = {k: v for k, v in dedup.items() if (now - v) <= ttl_seconds}
            if sig and sig in dedup:
                save_dedup_state(dedup)
                await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)
                continue

            # update dedup
            if sig:
                dedup[sig] = now
                save_dedup_state(dedup)

            # build embed
            stats1h = data.get("stats_1h", {}) or {}
            warn1 = int(stats1h.get("warn", 0) or 0)
            err1 = int(stats1h.get("error", 0) or 0)
            stack1 = int(stats1h.get("stack", 0) or 0)

            color, emoji = severity_style(warn1, err1, stack1)

            title = f"{emoji} PZ — Bug Report"
            desc = f"**New critical events:** `{new_critical_count}`\n"
            if sig:
                desc += f"**Signature:** `{sig}`\n"
            if excerpt:
                # keep short
                excerpt_short = excerpt[:900]
                desc += f"\n```text\n{excerpt_short}\n```"

            ch = client.get_channel(cfg.DISCORD_BUGS_CHANNEL_ID)
            if ch is None:
                # fallback to fetch
                ch = await client.fetch_channel(cfg.DISCORD_BUGS_CHANNEL_ID)

            await ch.send(embed=make_embed(title, desc, color))

        except Exception as e:
            # don't spam
            logger.exception("bug_alert_loop error: %s", e)

        await asyncio.sleep(cfg.PZ_LOGSCAN_INTERVAL_SECONDS)


# ------------------ Commands ------------------
@tree.command(name="pz_ping", description="Bot healthcheck", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.send_message(embed=make_embed("PZ — Ping", "✅ Pong.", SEV_GREEN), ephemeral=True)


@tree.command(name="pz_help", description="List commands + access rules", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        "**Commands**\n"
        "• `/pz_status` — show server status + online players\n"
        "• `/pz_players` — list online players\n"
        "• `/pz_logstats` — log counters (1h / 24h / 3d / 7d / 30d)\n"
        "• `/pz_logs recent` — recent critical log events\n"
        "• `/pz_logs top` — top signatures (24h / 7d)\n"
        "• `/pz_workshop_check` — check Workshop updates (webhook)\n"
        "• `/pz_version` — show bot version\n"
        "• `/pz_ping` — bot healthcheck\n\n"
        "**Log ignore list (persistent)**\n"
        "• `/pz_ignore_add <regex>` — add ignore regex\n"
        "• `/pz_ignore_remove <regex>` — remove ignore regex (exact match)\n"
        "• `/pz_ignore_list` — show ignore regex list\n\n"
        "**Sensitive commands (admin only)**\n"
        "• `/pz_save` — save world now\n"
        "• `/pz_stop` — stop server (confirm)\n"
        "• `/pz_start` — start server (confirm)\n"
        "• `/pz_restart` — restart server (confirm)\n"
        "• `/pz_grant @user` — grant PZ role (confirm)\n"
        "• `/pz_revoke @user` — revoke PZ role (confirm)\n\n"
        "**Access rules**\n"
        f"• Required role: <@&{cfg.PZ_ADMIN_ROLE_ID}>\n"
        "• OR Discord `Administrator`\n"
        "• OR (if enabled) channel perms: `manage_guild` / `manage_channels` / `manage_messages`\n\n"
        f"**Cooldown**: {cfg.COOLDOWN_SECONDS}s (sensitive commands)\n"
        f"**Confirm timeout**: {cfg.CONFIRM_SECONDS}s\n"
    )
    await i.response.send_message(embed=make_embed("PZ — Help", desc, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_version", description="Show bot version", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_version(i: discord.Interaction):
    await i.response.send_message(
        embed=make_embed("PZ — Version", f"**PZBot:** `{cfg.BOT_VERSION}`", SEV_BLUE),
        ephemeral=True,
    )


@tree.command(
    name="pz_status",
    description="Project Zomboid server status",
    guild=discord.Object(id=cfg.DISCORD_GUILD_ID),
)
async def pz_status(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("status")
    status, players = parse_status_with_players(out)

    ok = (code == 0) and (status in ("RUNNING", "STOPPED"))
    color = SEV_GREEN if ok else SEV_RED
    desc = f"**Status:** `{status}`\n**Players online:** `{players}`"

    emb = make_embed("PZ — Status", desc, color)
    log_action(i, "status", code, out)
    await i.followup.send(embed=emb, ephemeral=True)


@tree.command(
    name="pz_players",
    description="List online players",
    guild=discord.Object(id=cfg.DISCORD_GUILD_ID),
)
async def pz_players(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("players")
    t = (out or "").strip()

    if "STOPPED" in t.upper():
        emb = make_embed("PZ — Players", "🛑 Server is stopped.", SEV_RED)
        log_action(i, "players", code, out)
        await i.followup.send(embed=emb, ephemeral=True)
        return

    if t == "(none)" or t == "":
        emb = make_embed("PZ — Players", "No players online.", SEV_GREEN)
        log_action(i, "players", code, out)
        await i.followup.send(embed=emb, ephemeral=True)
        return

    names = [line.strip() for line in t.splitlines() if line.strip()]
    bullet_list = "\n".join([f"• `{n}`" for n in names])

    desc = f"**{len(names)} player(s) online:**\n{bullet_list}"
    emb = make_embed("PZ — Players", desc, SEV_BLUE)

    log_action(i, "players", code, out)
    await i.followup.send(embed=emb, ephemeral=True)


# -------- Log stats + logs group --------
def _get_int(d: dict, k: str) -> int:
    try:
        return int(d.get(k, 0) or 0)
    except Exception:
        return 0


@tree.command(name="pz_logstats", description="Log stats (1h/24h/3d/7d/30d)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logstats(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_logscan()
    if code != 0:
        await i.followup.send(embed=make_embed("PZ — Log Stats", f"Log scan failed:\n`{out}`", SEV_RED), ephemeral=True)
        return

    data = json.loads(out)
    stats1h = data.get("stats_1h", {}) or {}
    stats24h = data.get("stats_24h", {}) or {}
    stats3d = data.get("stats_3d", {}) or {}
    stats7d = data.get("stats_7d", {}) or {}
    stats30d = data.get("stats_30d", {}) or {}

    w1, e1, s1 = _get_int(stats1h, "warn"), _get_int(stats1h, "error"), _get_int(stats1h, "stack")
    w24, e24, s24 = _get_int(stats24h, "warn"), _get_int(stats24h, "error"), _get_int(stats24h, "stack")
    w3, e3, s3 = _get_int(stats3d, "warn"), _get_int(stats3d, "error"), _get_int(stats3d, "stack")
    w7, e7, s7 = _get_int(stats7d, "warn"), _get_int(stats7d, "error"), _get_int(stats7d, "stack")
    w30, e30, s30 = _get_int(stats30d, "warn"), _get_int(stats30d, "error"), _get_int(stats30d, "stack")

    color, emoji = severity_style(w1, e1, s1)

    desc = (
        f"**Last 1h**  — WARN: `{w1}`  ERROR: `{e1}`  STACK: `{s1}`\n"
        f"**Last 24h** — WARN: `{w24}` ERROR: `{e24}` STACK: `{s24}`\n"
        f"**Last 3d**  — WARN: `{w3}`  ERROR: `{e3}`  STACK: `{s3}`\n"
        f"**Last 7d**  — WARN: `{w7}`  ERROR: `{e7}`  STACK: `{s7}`\n"
        f"**Last 30d** — WARN: `{w30}` ERROR: `{e30}` STACK: `{s30}`\n"
    )

    emb = make_embed(f"{emoji} PZ — Log Stats", desc, color)
    await i.followup.send(embed=emb, ephemeral=True)


logs_group = app_commands.Group(
    name="pz_logs",
    description="Log insights (recent / top)",
)
tree.add_command(logs_group)


@logs_group.command(name="recent", description="Show recent critical log events (ERROR/STACK)")
async def pz_logs_recent(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_logscan()
    if code != 0:
        await i.followup.send(embed=make_embed("PZ — Logs Recent", f"Log scan failed:\n`{out}`", SEV_RED), ephemeral=True)
        return

    data = json.loads(out)
    rec = data.get("recent_critical", []) or []
    if not rec:
        await i.followup.send(embed=make_embed("PZ — Logs Recent", "No recent critical events.", SEV_GREEN), ephemeral=True)
        return

    lines = []
    for e in rec[-15:]:
        ts = str(e.get("ts", ""))[:19].replace("T", " ")
        sig = str(e.get("signature", "")).strip()
        lines.append(f"• `{ts}` — `{sig}`")

    desc = "\n".join(lines)
    await i.followup.send(embed=make_embed("PZ — Logs Recent", desc, SEV_BLUE), ephemeral=True)


@logs_group.command(name="top", description="Top error signatures (24h / 7d)")
async def pz_logs_top(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_logscan()
    if code != 0:
        await i.followup.send(embed=make_embed("PZ — Logs Top", f"Log scan failed:\n`{out}`", SEV_RED), ephemeral=True)
        return

    data = json.loads(out)
    top24 = data.get("top_24h", []) or []
    top7 = data.get("top_7d", []) or []

    def fmt(lst):
        if not lst:
            return "_(none)_"
        chunks = []
        for it in lst[:10]:
            sig = str(it.get("signature", "")).strip()
            c = int(it.get("count", 0) or 0)
            chunks.append(f"• `{sig}` × **{c}**")
        return "\n".join(chunks)

    desc = f"**Top (24h)**\n{fmt(top24)}\n\n**Top (7d)**\n{fmt(top7)}"
    await i.followup.send(embed=make_embed("PZ — Logs Top", desc, SEV_BLUE), ephemeral=True)


# -------- Ignore commands --------
@tree.command(name="pz_ignore_list", description="Show ignore regex list (log scanner)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ignore_list(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return

    pats = load_ignore_patterns()
    if not pats:
        emb = make_embed("PZ — Ignore List", f"No ignore patterns.\nFile: `{str(IGNORE_FILE)}`", SEV_GREEN)
        await i.response.send_message(embed=emb, ephemeral=True)
        return

    body = "\n".join([f"• `{p}`" for p in pats[:40]])
    if len(pats) > 40:
        body += f"\n… (+{len(pats)-40} more)"
    emb = make_embed("PZ — Ignore List", f"{body}\n\nFile: `{str(IGNORE_FILE)}`", SEV_BLUE)
    await i.response.send_message(embed=emb, ephemeral=True)


@tree.command(name="pz_ignore_add", description="Add ignore regex (log scanner)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(pattern="Regex pattern to ignore")
async def pz_ignore_add(i: discord.Interaction, pattern: str):
    if await require_admin(cfg, i) is None:
        return

    pat = (pattern or "").strip()
    ok, err = validate_regex(pat)
    if not pat or not ok:
        emb = make_embed("PZ — Ignore Add", f"Invalid regex.\n`{err}`", SEV_RED)
        await i.response.send_message(embed=emb, ephemeral=True)
        return

    pats = load_ignore_patterns()
    if pat in pats:
        emb = make_embed("PZ — Ignore Add", "Already in ignore list.", SEV_ORANGE)
        await i.response.send_message(embed=emb, ephemeral=True)
        return

    pats.append(pat)
    save_ignore_patterns(pats)

    emb = make_embed("PZ — Ignore Add", f"Added:\n`{pat}`\n\nTotal: `{len(pats)}`", SEV_GREEN)
    await i.response.send_message(embed=emb, ephemeral=True)


@tree.command(name="pz_ignore_remove", description="Remove ignore regex (log scanner)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(pattern="Exact regex pattern to remove")
async def pz_ignore_remove(i: discord.Interaction, pattern: str):
    if await require_admin(cfg, i) is None:
        return

    pat = (pattern or "").strip()
    pats = load_ignore_patterns()
    if pat not in pats:
        emb = make_embed("PZ — Ignore Remove", "Pattern not found (must match exactly).", SEV_ORANGE)
        await i.response.send_message(embed=emb, ephemeral=True)
        return

    pats = [p for p in pats if p != pat]
    save_ignore_patterns(pats)

    emb = make_embed("PZ — Ignore Remove", f"Removed:\n`{pat}`\n\nTotal: `{len(pats)}`", SEV_GREEN)
    await i.response.send_message(embed=emb, ephemeral=True)


# ------------------ Sensitive commands (unchanged core) ------------------
@tree.command(name="pz_save", description="Save world now (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_save(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "save"):
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Please wait before running `/pz_save` again.", SEV_ORANGE), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_control("save")
    ok = (code == 0) and ("ERROR" not in out.upper())
    log_action(i, "save", code, out)
    await i.followup.send(embed=make_embed("PZ — Save", f"**Result:** `{out}`", SEV_GREEN if ok else SEV_RED), ephemeral=True)


async def _confirm_and_run(i: discord.Interaction, action: str, title: str):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, action):
        await i.response.send_message(embed=make_embed("Cooldown", f"⏳ Please wait before running `{action}` again.", SEV_ORANGE), ephemeral=True)
        return

    pending = PendingAction(action=action, created_at=time.time(), interaction_user_id=i.user.id)

    async def on_confirm(inter2: discord.Interaction):
        await inter2.response.defer(ephemeral=True)
        code, out = await run_control(action)
        ok = (code == 0) and ("ERROR" not in out.upper())
        log_action(i, action, code, out)
        await inter2.followup.send(embed=make_embed(title, f"**Result:** `{out}`", SEV_GREEN if ok else SEV_RED), ephemeral=True)

    view = ConfirmView(cfg, pending, on_confirm)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Confirm action: **{action.upper()}**", SEV_BLUE),
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
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Please wait before running the workshop check again.", SEV_ORANGE), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_workshop_check()
    ok = (code == 0)
    log_action(i, "workshop_check", code, out)
    await i.followup.send(embed=make_embed("Workshop Check", "✅ Workshop check triggered." if ok else f"❌ Error: `{out}`", SEV_GREEN if ok else SEV_RED), ephemeral=True)


@tree.command(name="pz_grant", description="Grant PZ role to a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to authorize")
async def pz_grant(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_grant(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Grant", "❌ Role not found (bad ID?).", SEV_RED), ephemeral=True)
            return
        await user.add_roles(role, reason=f"pz_grant by {user_tag(i)}")
        logger.info("grant role=%s(%s) target=%s(%s) by=%s", role.name, role.id, user.name, user.id, user_tag(i))
        audit_log(cfg, f"grant role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Grant", f"✅ Granted **{role.name}** to {user.mention}.", SEV_GREEN), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("grant", time.time(), i.user.id), do_grant)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Grant PZ role to {user.mention}?", SEV_BLUE),
        view=view,
        ephemeral=True,
    )


@tree.command(name="pz_revoke", description="Revoke PZ role from a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to revoke")
async def pz_revoke(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_revoke(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Revoke", "❌ Role not found (bad ID?).", SEV_RED), ephemeral=True)
            return
        await user.remove_roles(role, reason=f"pz_revoke by {user_tag(i)}")
        logger.info("revoke role=%s(%s) target=%s(%s) by=%s", role.name, role.id, user.name, user.id, user_tag(i))
        audit_log(cfg, f"revoke role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Revoke", f"✅ Revoked **{role.name}** from {user.mention}.", SEV_GREEN), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("revoke", time.time(), i.user.id), do_revoke)
    await i.response.send_message(
        embed=make_embed("Confirmation required", f"Revoke PZ role from {user.mention}?", SEV_BLUE),
        view=view,
        ephemeral=True,
    )


# ------------------ Events ------------------
@client.event
async def on_ready():
    logger.info("✅ Bot ready as %s (id=%s)", client.user, client.user.id)
    logger.info("✅ Guild ID: %s", cfg.DISCORD_GUILD_ID)
    logger.info("✅ Admin Role ID: %s", cfg.PZ_ADMIN_ROLE_ID)
    logger.info("✅ ALLOW_CHANNEL_PERMS: %s", cfg.ALLOW_CHANNEL_PERMS)

    try:
        await tree.sync(guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
        logger.info("✅ Commands synced (guild scoped).")
    except Exception as e:
        logger.exception("Command sync failed: %s", e)

    client.loop.create_task(update_presence_loop())
    client.loop.create_task(bug_alert_loop())


# ------------------ Run ------------------
client.run(cfg.DISCORD_BOT_TOKEN)
