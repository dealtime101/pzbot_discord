# discord_bot.py
from __future__ import annotations

import re
import asyncio
import logging
import os
import json
import hashlib
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

    # Avoid duplicate handlers on restarts / reloads
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


def make_embed(title: str, description: str, ok: bool | None = None) -> discord.Embed:
    if ok is True:
        color = 0x2ecc71
    elif ok is False:
        color = 0xe74c3c
    else:
        color = 0x3498db

    emb = discord.Embed(title=title, description=description, color=color)
    emb.timestamp = discord.utils.utcnow()
    return emb

def severity_style(warn: int, error: int, stack: int) -> tuple[int, str]:
    if error > 0 or stack > 0:
        return 0xe74c3c, "🚨"   # red
    if warn > 0:
        return 0xf39c12, "⚠️"   # orange
    return 0x2ecc71, "✅"       # green


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
                "Unable to resolve member. Enable **Server Members Intent** in the Discord Developer Portal.",
                ok=False,
            ),
            ephemeral=True,
        )
        return None

    if has_admin_role(cfg, m) or has_discord_admin_perm(m) or has_channel_permission(cfg, i, m):
        return m

    await i.response.send_message(
        embed=make_embed("Access denied", "You don’t have permission to use this command.", ok=False),
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

    async def on_timeout(self):
        pass


# ------------------ Bot ------------------
cfg = load_config()
logger = setup_logging(cfg)
cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

intents = discord.Intents.default()
intents.members = True  # required for roles checks
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


async def run_control(action: str, extra_args: list[str] | None = None) -> tuple[int, str]:
    args = ["-Action", action]
    if extra_args:
        args.extend(extra_args)
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, args)

async def run_logscan() -> tuple[int, str]:
    return await run_powershell_script(
        cfg.POWERSHELL_EXE,
        cfg.PZ_LOGSCAN_PS1,
        ["-LogPath", cfg.PZ_CONSOLE_LOG],
    )

async def run_workshop_check() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [])


async def update_presence_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_control("status")
            status, players = parse_status_with_players(out)

            if status == "RUNNING":
                await client.change_presence(
                    activity=discord.Game(f"PZ: RUNNING ({players})"),
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

_last_alert_at = 0.0
_seen_signatures: dict[str, float] = {}  # signature -> last_seen_ts
_log_last_alert_at = 0.0
_log_seen: dict[str, float] = {}  # signature -> last_seen_ts


def _sig_from_line(line: str) -> str:
    # Normalize noisy parts (timestamps / counters) to reduce duplicates
    s = (line or "").strip()
    s = re.sub(r"\[\d{2}-\d{2}-\d{2}.*?\]", "[ts]", s)            # [yy-mm-dd ...]
    s = re.sub(r"\bt:\d+\b", "t:?", s)                            # t:17700...
    s = re.sub(r"\bf:\d+\b", "f:?", s)                            # f:0
    s = re.sub(r"\bst:[0-9,]+\b", "st:?", s)                      # st:380,483,474
    s = s[:400]
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()


async def monitor_console_loop():
    global _last_alert_at, _seen_signatures

    await client.wait_until_ready()

    # Warm-up scan: establishes offset/buckets without posting alerts
    try:
        await run_logscan()
        logger.info("logscan warm-up done (no alert).")
    except Exception as e:
        logger.exception("logscan warm-up failed: %s", e)

    while not client.is_closed():
        try:
            code, out = await run_logscan()
            if code != 0:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            data = json.loads(out)
            crit = int(data.get("new_critical_count", 0))
            if crit <= 0:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            now = time.time()
            # Anti-spam: one alert per cooldown window
            if (now - _last_alert_at) < cfg.LOGSCAN_ALERT_COOLDOWN_SECONDS:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            lines: list[str] = data.get("new_critical_lines", []) or []
            if not lines:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            # Dedup within a time window
            kept: list[str] = []
            for line in lines:
                sig = _sig_from_line(line)
                last_seen = _seen_signatures.get(sig, 0.0)
                if now - last_seen >= cfg.LOGSCAN_DEDUP_SECONDS:
                    _seen_signatures[sig] = now
                    kept.append(line)

            # Cleanup old signatures (keep memory bounded)
            cutoff = now - max(cfg.LOGSCAN_DEDUP_SECONDS * 2, 1800)
            _seen_signatures = {k: v for k, v in _seen_signatures.items() if v >= cutoff}

            if not kept:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            ch = client.get_channel(cfg.BUGS_CHANNEL_ID)
            if ch is None:
                ch = await client.fetch_channel(cfg.BUGS_CHANNEL_ID)

            s1 = data.get("stats_1h", {})
            s24 = data.get("stats_24h", {})
            s30 = data.get("stats_30d", {})

            preview = "\n".join(kept[:8])[:1800]

            desc = (
                f"**New critical events:** `{crit}` (dedup sent `{len(kept)}`)\n"
                f"**New WARN:** `{data.get('new_warn', 0)}`  "
                f"**ERROR:** `{data.get('new_error', 0)}`  "
                f"**STACK:** `{data.get('new_stack', 0)}`\n\n"
                f"```{preview}```\n"
                f"**Last 1h** — WARN `{s1.get('warn',0)}`, ERROR `{s1.get('error',0)}`, STACK `{s1.get('stack',0)}`\n"
                f"**Last 24h** — WARN `{s24.get('warn',0)}`, ERROR `{s24.get('error',0)}`, STACK `{s24.get('stack',0)}`\n"
                f"**Last 30d** — WARN `{s30.get('warn',0)}`, ERROR `{s30.get('error',0)}`, STACK `{s30.get('stack',0)}`\n"
                f"\n**Log:** `{data.get('log_path','')}`"
            )

            await ch.send(embed=make_embed("PZ — Console Alert", desc, ok=False))
            _last_alert_at = now

        except Exception as e:
            logger.exception("monitor_console_loop error: %s", e)

        await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)


def log_action(i: discord.Interaction, action: str, exit_code: int, out: str):
    g = i.guild.id if i.guild else 0
    ch = i.channel.id if i.channel else 0
    line = f"action={action} user={user_tag(i)} guild={g} channel={ch} exit={exit_code} out={out.replace('\n','\\n')[:200]}"
    logger.info(line)
    audit_log(cfg, line)

def _log_sig(text: str) -> str:
    s = (text or "").strip()
    # normalize noise
    s = re.sub(r"\[\d{2}-\d{2}-\d{2}.*?\]", "[ts]", s)
    s = re.sub(r"\bt:\d+\b", "t:?", s)
    s = re.sub(r"\bf:\d+\b", "f:?", s)
    s = re.sub(r"\bst:[0-9,]+\b", "st:?", s)
    s = s[:600]
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()

async def monitor_console_loop():
    global _log_last_alert_at, _log_seen
    await client.wait_until_ready()

    # warm-up: set offset without alerting
    try:
        await run_logscan()
        logger.info("logscan warm-up done (no alert).")
    except Exception as e:
        logger.exception("logscan warm-up failed: %s", e)

    while not client.is_closed():
        try:
            code, out = await run_logscan()
            if code != 0:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            data = json.loads(out)

            crit = int(data.get("new_critical_count", 0))
            ignored = int(data.get("ignored_total", 0))
            effective = max(0, crit - ignored)

            if effective <= 0:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            now = time.time()
            if (now - _log_last_alert_at) < cfg.LOGSCAN_ALERT_COOLDOWN_SECONDS:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            lines = data.get("new_critical_lines", []) or []
            if not lines:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            # dedup
            kept = []
            for item in lines:
                sig = _log_sig(item)
                last = _log_seen.get(sig, 0.0)
                if now - last >= cfg.LOGSCAN_DEDUP_SECONDS:
                    _log_seen[sig] = now
                    kept.append(item)

            # cleanup dedup map
            cutoff = now - max(cfg.LOGSCAN_DEDUP_SECONDS * 2, 1800)
            _log_seen = {k: v for k, v in _log_seen.items() if v >= cutoff}

            if not kept:
                await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)
                continue

            ch = client.get_channel(cfg.BUGS_CHANNEL_ID)
            if ch is None:
                ch = await client.fetch_channel(cfg.BUGS_CHANNEL_ID)

            s1 = data.get("stats_1h", {})
            s24 = data.get("stats_24h", {})
            s30 = data.get("stats_30d", {})

            preview = "\n\n".join(kept[:2])  # 2 blocks max
            preview = preview[:1800]

            desc = (
                f"**New critical:** `{crit}`  | **Ignored:** `{ignored}`  | **Sent:** `{len(kept)}`\n"
                f"**New WARN:** `{data.get('new_warn',0)}`  "
                f"**New ERROR:** `{data.get('new_error',0)}`  "
                f"**New STACK:** `{data.get('new_stack',0)}`\n\n"
                f"**Ignored WARN:** `{data.get('ignored_warn',0)}`  "
                f"**Ignored ERROR:** `{data.get('ignored_error',0)}`  "
                f"**Ignored STACK:** `{data.get('ignored_stack',0)}`\n"
                f"```{preview}```\n"
                f"**Last 1h** — WARN `{s1.get('warn',0)}`, ERROR `{s1.get('error',0)}`, STACK `{s1.get('stack',0)}`\n"
                f"**Last 24h** — WARN `{s24.get('warn',0)}`, ERROR `{s24.get('error',0)}`, STACK `{s24.get('stack',0)}`\n"
                f"**Last 30d** — WARN `{s30.get('warn',0)}`, ERROR `{s30.get('error',0)}`, STACK `{s30.get('stack',0)}`\n"
                f"**Log:** `{data.get('log_path','')}`\n"
            )

            await ch.send(embed=make_embed("PZ — Console Alert", desc, ok=False))
            _log_last_alert_at = now

        except Exception as e:
            logger.exception("monitor_console_loop error: %s", e)

        await asyncio.sleep(cfg.LOGSCAN_INTERVAL_SECONDS)

# ------------------ Commands ------------------
@tree.command(name="pz_ping", description="Bot healthcheck", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.send_message(embed=make_embed("PZ — Ping", "✅ Pong.", ok=True), ephemeral=True)


@tree.command(name="pz_help", description="Command list + access rules", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        "**Commands**\n"
        "• `/pz_status` — server status + online player count\n"
        "• `/pz_players` — list online players\n"
        "• `/pz_save` — save world (sensitive)\n"
        "• `/pz_stop` — stop server (sensitive, confirmation)\n"
        "• `/pz_start` — start server (sensitive, confirmation)\n"
        "• `/pz_restart` — restart server (sensitive, confirmation)\n"
        "• `/pz_workshop_check` — check Workshop updates (webhook)\n"
        "• `/pz_grant @user` — grant PZ role\n"
        "• `/pz_revoke @user` — revoke PZ role\n"
        "• `/pz_say <message>` — broadcast a message in-game\n"
        "• `/pz_logstats` — Console log stats\n"
        "• `/pz_ping` — bot healthcheck\n\n"
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

    log_action(i, "status", code, out)
    await i.followup.send(embed=make_embed("PZ — Status", desc, ok=ok), ephemeral=True)


@tree.command(name="pz_players", description="List online players", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_players(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_control("players")
    t = (out or "").strip()

    if "STOPPED" in t.upper():
        log_action(i, "players", code, out)
        await i.followup.send(embed=make_embed("PZ — Players", "🛑 Server is stopped.", ok=False), ephemeral=True)
        return

    if t == "(none)" or t == "":
        log_action(i, "players", code, out)
        await i.followup.send(embed=make_embed("PZ — Players", "No players online.", ok=True), ephemeral=True)
        return

    names = [line.strip() for line in t.splitlines() if line.strip()]
    bullet_list = "\n".join([f"• `{n}`" for n in names])

    desc = f"**{len(names)} player(s) online:**\n{bullet_list}"
    log_action(i, "players", code, out)
    await i.followup.send(embed=make_embed("PZ — Players", desc, ok=True), ephemeral=True)


@tree.command(name="pz_save", description="Save world now (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_save(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "save"):
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Please wait before using `/pz_save` again.", ok=False), ephemeral=True)
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
        await i.response.send_message(embed=make_embed("Cooldown", f"⏳ Please wait before using `{action}` again.", ok=False), ephemeral=True)
        return

    pending = PendingAction(action=action, created_at=time.time(), interaction_user_id=i.user.id)

    async def on_confirm(inter2: discord.Interaction):
        await inter2.response.defer(ephemeral=True)
        code, out = await run_control(action)
        ok = (code == 0) and ("ERROR" not in out.upper())
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
    await i.followup.send(embed=make_embed("Workshop Check", "✅ Check triggered via webhook." if ok else f"❌ Error: `{out}`", ok=ok), ephemeral=True)


@tree.command(name="pz_grant", description="Grant PZ role to a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
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


@tree.command(name="pz_revoke", description="Revoke PZ role from a user", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to revoke")
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

@tree.command(
    name="pz_say",
    description="Broadcast a message in-game to all players (admin)",
    guild=discord.Object(id=cfg.DISCORD_GUILD_ID),
)
@app_commands.describe(message="Message to broadcast in-game")
async def pz_say(i: discord.Interaction, message: str):
    if await require_admin(cfg, i) is None:
        return

    await i.response.defer(ephemeral=True)

    # Optional: limit message length
    if len(message) > 200:
        await i.followup.send(embed=make_embed("PZ — Say", "Message too long (max 200 chars).", ok=False), ephemeral=True)
        return

    code, out = await run_control("say", ["-Message", message])
    ok = (code == 0) and ("ERROR" not in out.upper())
    log_action(i, "say", code, out)

    await i.followup.send(
        embed=make_embed("PZ — Say", "✅ Message sent in-game." if ok else f"❌ Failed: `{out}`", ok=ok),
        ephemeral=True,
    )

@tree.command(
    name="pz_logstats",
    description="Console log stats (WARN/ERROR/STACK) for 1h/24h/30d",
    guild=discord.Object(id=cfg.DISCORD_GUILD_ID),
)
async def pz_logstats(i: discord.Interaction):
    await i.response.defer(ephemeral=True)

    code, out = await run_logscan()
    if code != 0:
        await i.followup.send(embed=make_embed("PZ — Log Stats", f"❌ `{out}`", ok=False), ephemeral=True)
        return

    data = json.loads(out)
    s1 = data["stats_1h"]; s24 = data["stats_24h"]; s30 = data["stats_30d"]

    desc = (
        f"**Last 1h** — WARN `{s1['warn']}`, ERROR `{s1['error']}`, STACK `{s1['stack']}`\n"
        f"**Last 24h** — WARN `{s24['warn']}`, ERROR `{s24['error']}`, STACK `{s24['stack']}`\n"
        f"**Last 30d** — WARN `{s30['warn']}`, ERROR `{s30['error']}`, STACK `{s30['stack']}`\n"
        f"\n**Log:** `{data.get('log_path','')}`"
    )
    warn = stats1h.get("warn", 0)
    error = stats1h.get("error", 0)
    stack = stats1h.get("stack", 0)

    color, emoji = severity_style(warn, error, stack)

    emb = discord.Embed(
        title=f"{emoji} PZ — Log Stats",
        description=desc,
        color=color,
    )
    emb.timestamp = discord.utils.utcnow()

    await i.followup.send(embed=emb, ephemeral=True)


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
    client.loop.create_task(monitor_console_loop())


# ------------------ Run ------------------
client.run(cfg.DISCORD_BOT_TOKEN)