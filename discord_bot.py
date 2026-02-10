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


# ------------------ Config ------------------
cfg = load_config()

# ------------------ Logging ------------------
def setup_logging(cfg: Config) -> logging.Logger:
    os.makedirs(cfg.LOG_DIR, exist_ok=True)

    logger = logging.getLogger("pzbot")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on restarts
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


logger = setup_logging(cfg)


def audit_log(line: str) -> None:
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

    timeout_s = int(os.environ.get("PZ_PS_TIMEOUT_SECONDS", "120"))
    try:
        out, _ = await asyncio.wait_for(p.communicate(), timeout=max(5, timeout_s))
    except asyncio.TimeoutError:
        try:
            p.kill()
        except Exception:
            pass
        return 124, f"Timed out after {timeout_s}s"

    text = (out or b"").decode("utf-8", errors="replace").strip()
    if not text:
        text = "(no output)"
    return p.returncode, text[:1800]


SEV_GREEN = 0x2ecc71
SEV_ORANGE = 0xF1C40F
SEV_RED = 0xE74C3C
SEV_BLUE = 0x3498DB


def make_embed(title: str, desc: str, color: int) -> discord.Embed:
    return discord.Embed(title=title, description=desc, color=color)


def user_tag(i: discord.Interaction) -> str:
    u = i.user
    return f"{u.name}#{u.discriminator}" if getattr(u, "discriminator", None) else u.name


def parse_status_with_players(out: str) -> tuple[str, str]:
    """
    Matches pz_control.ps1 output:
      RUNNING | players=3
      STOPPED | players=0
      RUNNING | players=?
      STOPPED
    """
    s = (out or "").strip()

    # Status is first token before space or |
    status = "UNKNOWN"
    m = re.match(r"^([A-Z_]+)", s)
    if m:
        status = m.group(1).strip()

    players = "?"
    m = re.search(r"players\s*=\s*(\d+|\?)", s, flags=re.I)
    if m:
        players = m.group(1)
    return status, players


# ------------------ Permissions ------------------
async def require_admin(cfg: Config, i: discord.Interaction) -> Optional[discord.Embed]:
    """
    Returns:
      None if allowed
      Embed (error) if denied
    """
    if not i.guild or not isinstance(i.user, discord.Member):
        return make_embed("No guild context", "This command can only be used in a server.", SEV_RED)

    member: discord.Member = i.user
    perms = member.guild_permissions

    if perms.administrator:
        return None

    if cfg.PZ_ADMIN_ROLE_ID and any(r.id == cfg.PZ_ADMIN_ROLE_ID for r in member.roles):
        return None

    if cfg.ALLOW_CHANNEL_PERMS:
        cp = i.channel.permissions_for(member) if i.channel else perms
        if cp.manage_guild or cp.manage_channels or cp.manage_messages:
            return None

    return make_embed(
        "Access denied",
        f"Required role: <@&{cfg.PZ_ADMIN_ROLE_ID}> or Discord Administrator.",
        SEV_RED,
    )


async def deny_if_needed(i: discord.Interaction, m: Optional[discord.Embed]) -> bool:
    """Returns True if denied (and responded), False if OK."""
    if m is None:
        return False
    if i.response.is_done():
        await i.followup.send(embed=m, ephemeral=True)
    else:
        await i.response.send_message(embed=m, ephemeral=True)
    return True


# ------------------ Cooldown / Confirm ------------------
class Cooldown:
    def __init__(self, seconds: int):
        self.seconds = max(0, int(seconds))
        self._last: dict[int, float] = {}

    def check(self, user_id: int) -> bool:
        if self.seconds <= 0:
            return True
        now = time.time()
        last = self._last.get(user_id, 0.0)
        if now - last < self.seconds:
            return False
        self._last[user_id] = now
        return True


@dataclass
class PendingAction:
    action: str
    created_ts: float
    owner_user_id: int


class ConfirmView(discord.ui.View):
    def __init__(self, cfg: Config, pending: PendingAction, on_confirm):
        super().__init__(timeout=cfg.CONFIRM_SECONDS)
        self.cfg = cfg
        self.pending = pending
        self.on_confirm = on_confirm

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.pending.owner_user_id:
            await interaction.response.send_message("Not your confirmation.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if time.time() - self.pending.created_ts > self.cfg.CONFIRM_SECONDS:
            await interaction.response.edit_message(
                embed=make_embed("Expired", "Confirmation window expired.", SEV_RED),
                view=None,
            )
            self.stop()
            return

        await self.on_confirm(interaction)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(
            embed=make_embed("Cancelled", "Action cancelled.", SEV_BLUE),
            view=None,
        )
        self.stop()


cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

IGNORE_FILE = Path(cfg.PZ_IGNORE_FILE) if str(cfg.PZ_IGNORE_FILE).strip() else (Path(cfg.LOG_DIR) / "pz_ignore_regex.txt")
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
        return out
    except Exception:
        logger.exception("Failed reading ignore file: %s", IGNORE_FILE)
        return []


def save_ignore_patterns(patterns: list[str]) -> None:
    IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    txt = "\n".join(patterns) + ("\n" if patterns else "")
    IGNORE_FILE.write_text(txt, encoding="utf-8")


def validate_regex(rx: str) -> Optional[str]:
    try:
        re.compile(rx)
        return None
    except re.error as e:
        return str(e)


# ------------------ Dedup helpers ------------------
def dedup_load() -> dict:
    try:
        if not DEDUP_FILE.exists():
            return {}
        return json.loads(DEDUP_FILE.read_text(encoding="utf-8", errors="replace") or "{}")
    except Exception:
        return {}


def dedup_save(data: dict) -> None:
    DEDUP_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEDUP_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ------------------ Runners ------------------
async def run_control(action: str) -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, ["-Action", action])


async def run_workshop_check() -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [])


async def run_logscan() -> tuple[int, str]:
    args = ["-LogPath", cfg.PZ_CONSOLE_LOG, "-IgnoreFile", str(IGNORE_FILE)]
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_LOGSCAN_PS1, args)


# ------------------ Discord Client ------------------
class PZBotClient(discord.Client):
    async def setup_hook(self):
        # Sync slash commands to one guild (fast propagation)
        try:
            guild = discord.Object(id=cfg.DISCORD_GUILD_ID)
            tree.copy_global_to(guild=guild)
            await tree.sync(guild=guild)
            logger.info("Slash commands synced to guild %s", cfg.DISCORD_GUILD_ID)
        except Exception as e:
            logger.exception("Slash sync failed: %s", e)


intents = discord.Intents.default()
intents.members = True

client = PZBotClient(intents=intents)
tree = app_commands.CommandTree(client)


@client.event
async def on_ready():
    logger.info("Logged in as %s (id=%s)", client.user, client.user.id)


# ------------------ Commands ------------------
@tree.command(name="pz_help", description="Show PZBot commands", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        "**Core**\n"
        "• `/pz_status` — Server status (with latency)\n"
        "• `/pz_players` — Online players (with latency)\n"
        "• `/pz_ping` — Bot ping (and server quick status)\n"
        "• `/pz_version` — Bot version\n\n"
        "**Chat**\n"
        "• `/pz_say <message>` — Send a message to in-game chat (admin)\n\n"
        "**Admin**\n"
        "• `/pz_start` `/pz_stop` `/pz_restart`\n"
        "• `/pz_save` — Save world (sensitive)\n"
        "• `/pz_workshop_check` — Run workshop check now\n"
        "• `/pz_grant @user` — Grant PZ role\n"
        "• `/pz_revoke @user` — Revoke PZ role\n\n"
        "**Logs**\n"
        "• `/pz_logstats` — Log stats\n"
        "• `/pz_logs_recent` — Recent critical excerpts\n"
        "• `/pz_logs_top` — Top signatures\n\n"
        "**Ignore list**\n"
        "• `/pz_ignore_add <regex>`\n"
        "• `/pz_ignore_remove <regex>`\n"
        "• `/pz_ignore_list`\n\n"
        f"**Cooldown:** {cfg.COOLDOWN_SECONDS}s  |  **Confirm window:** {cfg.CONFIRM_SECONDS}s\n"
    )
    await i.response.send_message(embed=make_embed("PZ — Help", desc, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_version", description="Show bot version", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_version(i: discord.Interaction):
    env_ver = (os.environ.get("PZBOT_VERSION") or "").strip()
    if env_ver and env_ver != cfg.BOT_VERSION:
        desc = f"Config version: `{cfg.BOT_VERSION}`\nEnv override (PZBOT_VERSION): `{env_ver}`"
    else:
        desc = f"`{cfg.BOT_VERSION}`"
    await i.response.send_message(embed=make_embed("PZ — Version", desc, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_ping", description="Bot ping (and server status)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.defer(ephemeral=True, thinking=True)

    bot_ms = int(client.latency * 1000)

    t0 = time.perf_counter()
    code, out = await run_control("status")
    srv_ms = int((time.perf_counter() - t0) * 1000)

    status, players = parse_status_with_players(out)
    color = SEV_GREEN if code == 0 else SEV_RED

    desc = (
        f"**Bot WS latency:** `{bot_ms}ms`\n"
        f"**Server status:** `{status}` | **Players:** `{players}`\n"
        f"**Server check latency:** `{srv_ms}ms`"
    )
    await i.followup.send(embed=make_embed("PZ — Ping", desc, color), ephemeral=True)


@tree.command(name="pz_status", description="Show PZ server status", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_status(i: discord.Interaction):
    await i.response.defer(ephemeral=True, thinking=True)

    t0 = time.perf_counter()
    code, out = await run_control("status")
    dt_ms = int((time.perf_counter() - t0) * 1000)

    status, players = parse_status_with_players(out)
    color = SEV_GREEN if code == 0 else SEV_RED

    desc = (
        f"**Status:** `{status}` | **Players:** `{players}`\n"
        f"**Latency:** `{dt_ms}ms`\n\n"
        f"```{out}```"
    )
    await i.followup.send(embed=make_embed("PZ — Status", desc, color), ephemeral=True)


@tree.command(name="pz_players", description="Show online players", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_players(i: discord.Interaction):
    await i.response.defer(ephemeral=True, thinking=True)

    t0 = time.perf_counter()
    code, out = await run_control("players")
    dt_ms = int((time.perf_counter() - t0) * 1000)

    # If script returns "(none)" that's fine; show it.
    color = SEV_GREEN if code == 0 else SEV_RED
    desc = f"**Latency:** `{dt_ms}ms`\n\n```{out}```"
    await i.followup.send(embed=make_embed("PZ — Players", desc, color), ephemeral=True)


@tree.command(name="pz_say", description="Send a message to in-game chat (admin)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(message="Message to send to in-game chat")
async def pz_say(i: discord.Interaction, message: str):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    message = (message or "").strip()
    if not message:
        await i.response.send_message(embed=make_embed("PZ — Say", "Message cannot be empty.", SEV_RED), ephemeral=True)
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, ["-Action", "say", "-Message", message])
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(embed=make_embed("PZ — Say", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_workshop_check", description="Run workshop check now", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_workshop_check(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_workshop_check()
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(embed=make_embed("PZ — Workshop Check", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_save", description="Save world (sensitive)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_save(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    pending = PendingAction("save", time.time(), i.user.id)

    async def do_confirm(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        code, out = await run_control("save")
        color = SEV_GREEN if code == 0 else SEV_RED
        await interaction.edit_original_response(embed=make_embed("PZ — Save", f"```{out}```", color), view=None)

    await i.response.send_message(
        embed=make_embed("Confirm", "Save the world now?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
    )


@tree.command(name="pz_start", description="Start the PZ server (admin)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_start(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_control("start")
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(embed=make_embed("PZ — Start", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_stop", description="Stop the PZ server (admin)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_stop(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    pending = PendingAction("stop", time.time(), i.user.id)

    async def do_confirm(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        code, out = await run_control("stop")
        color = SEV_GREEN if code == 0 else SEV_RED
        await interaction.edit_original_response(embed=make_embed("PZ — Stop", f"```{out}```", color), view=None)

    await i.response.send_message(
        embed=make_embed("Confirm", "Stop the server?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
    )


@tree.command(name="pz_restart", description="Restart the PZ server (admin)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_restart(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    pending = PendingAction("restart", time.time(), i.user.id)

    async def do_confirm(interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        code, out = await run_control("restart")
        color = SEV_GREEN if code == 0 else SEV_RED
        await interaction.edit_original_response(embed=make_embed("PZ — Restart", f"```{out}```", color), view=None)

    await i.response.send_message(
        embed=make_embed("Confirm", "Restart the server?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
    )

@tree.command(name="pz_grant", description="Grant PZ role", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to grant the role to")
async def pz_grant(i: discord.Interaction, user: discord.Member):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    if cfg.PZ_ADMIN_ROLE_ID <= 0 or i.guild is None:
        await i.response.send_message(embed=make_embed("PZ — Grant", "PZ_ADMIN_ROLE_ID is not set.", SEV_RED), ephemeral=True)
        return

    role = i.guild.get_role(cfg.PZ_ADMIN_ROLE_ID)
    if role is None:
        await i.response.send_message(embed=make_embed("PZ — Grant", "Role not found in this guild.", SEV_RED), ephemeral=True)
        return

    await i.response.defer(ephemeral=True, thinking=True)
    try:
        await user.add_roles(role, reason=f"PZBot grant by {user_tag(i)}")
        await i.followup.send(embed=make_embed("PZ — Grant", f"Granted {role.mention} to {user.mention}", SEV_GREEN), ephemeral=True)
    except discord.Forbidden:
        await i.followup.send(embed=make_embed("PZ — Grant", "Forbidden: permission/role hierarchy issue.", SEV_RED), ephemeral=True)


@tree.command(name="pz_revoke", description="Revoke PZ role", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="User to revoke the role from")
async def pz_revoke(i: discord.Interaction, user: discord.Member):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    if cfg.PZ_ADMIN_ROLE_ID <= 0 or i.guild is None:
        await i.response.send_message(embed=make_embed("PZ — Revoke", "PZ_ADMIN_ROLE_ID is not set.", SEV_RED), ephemeral=True)
        return

    role = i.guild.get_role(cfg.PZ_ADMIN_ROLE_ID)
    if role is None:
        await i.response.send_message(embed=make_embed("PZ — Revoke", "Role not found in this guild.", SEV_RED), ephemeral=True)
        return

    await i.response.defer(ephemeral=True, thinking=True)
    try:
        await user.remove_roles(role, reason=f"PZBot revoke by {user_tag(i)}")
        await i.followup.send(embed=make_embed("PZ — Revoke", f"Revoked {role.mention} from {user.mention}", SEV_GREEN), ephemeral=True)
    except discord.Forbidden:
        await i.followup.send(embed=make_embed("PZ — Revoke", "Forbidden: permission/role hierarchy issue.", SEV_RED), ephemeral=True)


# ------------------ Ignore list ------------------
@tree.command(name="pz_ignore_list", description="List ignore regex patterns", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ignore_list(i: discord.Interaction):
    patterns = load_ignore_patterns()
    if not patterns:
        await i.response.send_message(embed=make_embed("PZ — Ignore List", "(empty)", SEV_BLUE), ephemeral=True)
        return

    txt = "\n".join(f"{idx+1}. `{p}`" for idx, p in enumerate(patterns))
    await i.response.send_message(embed=make_embed("PZ — Ignore List", txt, SEV_BLUE), ephemeral=True)


@tree.command(name="pz_ignore_add", description="Add ignore regex pattern", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(regex="Regex pattern to ignore")
async def pz_ignore_add(i: discord.Interaction, regex: str):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    regex = (regex or "").strip()
    if not regex:
        await i.response.send_message(embed=make_embed("PZ — Ignore Add", "Regex cannot be empty.", SEV_RED), ephemeral=True)
        return

    err = validate_regex(regex)
    if err:
        await i.response.send_message(embed=make_embed("PZ — Ignore Add", f"Invalid regex: `{err}`", SEV_RED), ephemeral=True)
        return

    patterns = load_ignore_patterns()
    if regex in patterns:
        await i.response.send_message(embed=make_embed("PZ — Ignore Add", "Already exists.", SEV_BLUE), ephemeral=True)
        return

    patterns.append(regex)
    save_ignore_patterns(patterns)
    await i.response.send_message(embed=make_embed("PZ — Ignore Add", f"Added: `{regex}`", SEV_GREEN), ephemeral=True)


@tree.command(name="pz_ignore_remove", description="Remove ignore regex pattern", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(regex="Regex pattern to remove")
async def pz_ignore_remove(i: discord.Interaction, regex: str):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    regex = (regex or "").strip()
    patterns = load_ignore_patterns()

    if regex not in patterns:
        await i.response.send_message(embed=make_embed("PZ — Ignore Remove", "Not found.", SEV_RED), ephemeral=True)
        return

    patterns = [p for p in patterns if p != regex]
    save_ignore_patterns(patterns)
    await i.response.send_message(embed=make_embed("PZ — Ignore Remove", f"Removed: `{regex}`", SEV_GREEN), ephemeral=True)


# ------------------ Logs ------------------
@tree.command(name="pz_logstats", description="Log stats", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logstats(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_logscan()
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(embed=make_embed("PZ — Log Stats", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_logs_recent", description="Recent critical excerpts", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logs_recent(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_logscan()
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(embed=make_embed("PZ — Recent Logs", f"```{out}```", color), ephemeral=True)


@tree.command(name="pz_logs_top", description="Top signatures", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logs_top(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_logscan()
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(embed=make_embed("PZ — Top Signatures", f"```{out}```", color), ephemeral=True)


# ------------------ Presence loop (optional) ------------------
async def update_presence_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_control("status")
            status, players = parse_status_with_players(out)
            if status == "RUNNING":
                await client.change_presence(activity=discord.Game(name=f"PZ RUNNING • {players} players"))
            else:
                await client.change_presence(activity=discord.Game(name=f"PZ {status}"))
        except Exception:
            logger.exception("Presence update failed")
        await asyncio.sleep(max(10, int(cfg.STATUS_REFRESH_SECONDS)))


@client.event
async def on_connect():
    # Start after connect
    try:
        client.loop.create_task(update_presence_loop())
    except Exception:
        pass


# ------------------ Entrypoint ------------------
def main():
    if not cfg.DISCORD_BOT_TOKEN:
        raise RuntimeError("DISCORD_BOT_TOKEN is missing.")
    client.run(cfg.DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    main()
