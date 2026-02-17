# discord_bot.py
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

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
async def run_powershell_script(ps_exe: str, script_path: str, args: List[str]) -> Tuple[int, str]:
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

    # IMPORTANT: do NOT hard-truncate to 1800 chars (logscan returns JSON and can exceed that)
    max_chars = int(os.environ.get("PZ_PS_MAX_CHARS", "200000"))
    if len(text) > max_chars:
        text = text[:max_chars] + "\n…(truncated)…"

    return p.returncode, text


SEV_GREEN = 0x2ecc71
SEV_ORANGE = 0xF1C40F
SEV_RED = 0xE74C3C
SEV_BLUE = 0x3498DB


def _no_mentions() -> discord.AllowedMentions:
    return discord.AllowedMentions.none()


def make_embed(title: str, desc: str, color: int) -> discord.Embed:
    e = discord.Embed(title=title, description=desc, color=color)
    e.set_footer(text=f"PZBot v{cfg.BOT_VERSION}")
    return e


def _now_unix() -> int:
    return int(time.time())


def _fmt_dt(ts: int) -> str:
    real_dt = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
    return f"{discord.utils.format_dt(real_dt, style='f')} ({discord.utils.format_dt(real_dt, style='R')})"


def parse_status_with_players(out: str) -> Tuple[str, str]:
    s = (out or "").strip()

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
    if not i.guild or not isinstance(i.user, discord.Member):
        return make_embed("❌ No guild context", "This command can only be used in a server.", SEV_RED)

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
        "⛔ Access denied",
        f"Required role: <@&{cfg.PZ_ADMIN_ROLE_ID}> or Discord Administrator.",
        SEV_RED,
    )


async def deny_if_needed(i: discord.Interaction, m: Optional[discord.Embed]) -> bool:
    if m is None:
        return False
    if i.response.is_done():
        await i.followup.send(embed=m, ephemeral=True, allowed_mentions=_no_mentions())
    else:
        await i.response.send_message(embed=m, ephemeral=True, allowed_mentions=_no_mentions())
    return True


# ------------------ Confirm ------------------
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
            await interaction.response.send_message(
                "Not your confirmation.",
                ephemeral=True,
                allowed_mentions=_no_mentions(),
            )
            return False
        return True

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger, emoji="⚠️")
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if time.time() - self.pending.created_ts > self.cfg.CONFIRM_SECONDS:
            await interaction.response.edit_message(
                embed=make_embed("⌛ Expired", "Confirmation window expired.", SEV_RED),
                view=None,
            )
            self.stop()
            return

        await self.on_confirm(interaction)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary, emoji="🛑")
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(
            embed=make_embed("Cancelled", "Action cancelled.", SEV_BLUE),
            view=None,
        )
        self.stop()


# ------------------ Files ------------------
IGNORE_FILE = Path(cfg.PZ_IGNORE_FILE) if str(cfg.PZ_IGNORE_FILE).strip() else (Path(cfg.LOG_DIR) / "pz_ignore_regex.txt")


def load_ignore_patterns() -> List[str]:
    try:
        if not IGNORE_FILE.exists():
            return []
        lines = IGNORE_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        out: List[str] = []
        for ln in lines:
            t = ln.strip()
            if not t or t.startswith("#"):
                continue
            out.append(t)
        return out
    except Exception:
        logger.exception("Failed reading ignore file: %s", IGNORE_FILE)
        return []


def save_ignore_patterns(patterns: List[str]) -> None:
    IGNORE_FILE.parent.mkdir(parents=True, exist_ok=True)
    txt = "\n".join(patterns) + ("\n" if patterns else "")
    IGNORE_FILE.write_text(txt, encoding="utf-8")


def validate_regex(rx: str) -> Optional[str]:
    try:
        re.compile(rx)
        return None
    except re.error as e:
        return str(e)


# ------------------ Runners ------------------
async def run_control(action: str) -> Tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, ["-Action", action])


async def run_workshop_check() -> Tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [])


# Small logscan cache
_LOGSCAN_LAST: Tuple[float, int, str] = (0.0, 0, "")

async def run_logscan() -> Tuple[int, str]:
    """
    IMPORTANT: Always pass -StateDir so /pz_logstats reads the same persisted buckets/events.
    Adds timing logs to confirm if /pz_logs_recent is simply slower.
    """
    global _LOGSCAN_LAST
    now = time.time()
    last_ts, last_code, last_out = _LOGSCAN_LAST
    if now - last_ts < 2.0 and last_out:
        return last_code, last_out

    state_dir = os.path.expandvars(getattr(cfg, "PZ_LOGSCAN_STATE_DIR", r"C:\PZ_MaintenanceLogs\PZLogScan"))

    args = [
        "-LogPath", os.path.expandvars(cfg.PZ_CONSOLE_LOG),
        "-StateDir", state_dir,
        "-IgnoreFile", str(IGNORE_FILE),
    ]

    t0 = time.perf_counter()
    code, out = await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_LOGSCAN_PS1, args)
    ms = int((time.perf_counter() - t0) * 1000)
    logger.info("logscan finished: code=%s, ms=%s, chars=%s, state_dir=%s", code, ms, len(out), state_dir)

    _LOGSCAN_LAST = (now, code, out)
    return code, out


# ------------------ Log embeds + refresh ------------------
def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _fmt_triplet(d: Dict[str, Any]) -> str:
    w = _safe_int(d.get("warn", 0))
    e = _safe_int(d.get("error", 0))
    s = _safe_int(d.get("stack", 0))
    return f"W:{w}  E:{e}  S:{s}"


def parse_logscan_json(raw: str) -> Dict[str, Any]:
    s = (raw or "").strip()
    if not s:
        return {}

    # First try full parse
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        pass

    # Fallback: try salvage JSON object if extra text exists
    try:
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            obj = json.loads(s[start:end + 1])
            return obj if isinstance(obj, dict) else {}
    except Exception:
        pass

    return {}


def build_log_embed(mode: str, data: Dict[str, Any]) -> discord.Embed:
    ts = (data.get("timestamp") or "").strip()
    scanned = _safe_int(data.get("scanned_new_lines", 0))
    new_warn = _safe_int(data.get("new_warn", 0))
    new_err = _safe_int(data.get("new_error", 0))
    new_stack = _safe_int(data.get("new_stack", 0))
    ignored = _safe_int(data.get("ignored_total", 0))

    sev = new_err + new_stack
    color = SEV_GREEN if sev == 0 else (SEV_ORANGE if sev < 3 else SEV_RED)

    title_map = {
        "stats": "📊 PZ — Log Stats",
        "recent": "🧾 PZ — Recent Logs",
        "top": "🏆 PZ — Top Signatures",
    }
    title = title_map.get(mode, "🧩 PZ — Logs")

    header = (
        f"**Scanned:** `{scanned}` new lines\n"
        f"**New:** ⚠️ `{new_warn}`  |  ❌ `{new_err}`  |  💥 `{new_stack}`   •   **Ignored:** `{ignored}`\n"
        + (f"**Timestamp:** `{ts}`\n" if ts else "")
    )

    e = make_embed(title, header, color)

    # Show Stats fields ONLY on /pz_logstats
    if mode == "stats":
        s1h = data.get("stats_1h", {}) or {}
        s24 = data.get("stats_24h", {}) or {}
        s7d = data.get("stats_7d", {}) or {}
        s30 = data.get("stats_30d", {}) or {}
        e.add_field(name="⏱️ Stats (1h)", value=f"`{_fmt_triplet(s1h)}`", inline=True)
        e.add_field(name="🕛 Stats (24h)", value=f"`{_fmt_triplet(s24)}`", inline=True)
        e.add_field(name="📆 Stats (7d)", value=f"`{_fmt_triplet(s7d)}`", inline=True)
        e.add_field(name="🗓️ Stats (30d)", value=f"`{_fmt_triplet(s30)}`", inline=True)

        crit = data.get("new_critical_lines", []) or []
        if crit:
            excerpt = "\n\n".join(str(x) for x in crit[:3])
            if len(excerpt) > 900:
                excerpt = excerpt[:900] + "…"
            e.add_field(name="💥 New critical excerpts", value=f"```{excerpt}```", inline=False)

    # /pz_logs_recent: only show recent critical (keep under embed limits)
    if mode == "recent":
        rec = data.get("recent_critical", []) or []
        if not rec:
            e.add_field(name="🧾 Recent critical", value="`(none)`", inline=False)
        else:
            lines: List[str] = []
            for item in rec[-15:]:
                t = (item.get("ts") or "")
                t = t[-8:] if len(t) >= 8 else t
                typ = (item.get("type") or "evt").upper()
                sig = (item.get("signature") or "").strip()
                if len(sig) > 90:
                    sig = sig[:90] + "…"
                lines.append(f"• `{t}` **{typ}** — {sig}")

            text = "\n".join(lines)
            # Field value limit safety (Discord embed field value is strict)
            if len(text) > 900:
                text = text[:900] + "\n…"

            e.add_field(name="🧾 Recent critical (last 15)", value=text, inline=False)

    # /pz_logs_top: only show top signatures
    if mode == "top":
        top24 = data.get("top_24h", []) or []
        top7 = data.get("top_7d", []) or []

        def fmt_top(arr: List[Dict[str, Any]]) -> str:
            if not arr:
                return "`(none)`"
            out: List[str] = []
            for it in arr[:10]:
                c = _safe_int(it.get("count", 0))
                sig = (it.get("signature") or "").strip()
                if len(sig) > 95:
                    sig = sig[:95] + "…"
                out.append(f"• `{c:>3}` — {sig}")
            return "\n".join(out)

        e.add_field(name="🏆 Top signatures (24h)", value=fmt_top(top24), inline=False)
        e.add_field(name="🏅 Top signatures (7d)", value=fmt_top(top7), inline=False)

    return e


# ------------------ /pz_players parsing ------------------
_PLAYERS_HEADER_RE = re.compile(r"^(players?|online|name|id)\b", re.I)

def parse_players_output(raw: str) -> Tuple[int, str]:
    s = (raw or "").strip()
    if not s or s.lower() in {"(none)", "none", "no players", "no players connected"}:
        return 0, "(none)"

    lines = [ln.strip() for ln in s.splitlines() if ln.strip()]
    lines2 = [ln for ln in lines if not _PLAYERS_HEADER_RE.match(ln)]
    cand = lines2 if lines2 else lines

    clean: List[str] = []
    for ln in cand:
        if ln.strip("-=*_") == "":
            continue
        clean.append(ln)

    count = len(clean)
    max_lines = 25
    shown = clean[:max_lines]
    body = "\n".join(shown)
    if len(clean) > max_lines:
        body += f"\n… ({len(clean) - max_lines} more)"

    return max(0, count), body


# ------------------ Status/Players embeds ------------------
def build_status_embed(status: str, players: str, latency_ms: int, raw: str, updated_ts: int) -> discord.Embed:
    display_status = "ONLINE" if status == "RUNNING" else status

    if display_status == "ONLINE":
        color = SEV_GREEN
    elif display_status in {"STARTING", "RESTARTING"}:
        color = SEV_ORANGE
    else:
        color = SEV_RED

    e = discord.Embed(title="🛰️ PZ — Status", color=color)
    e.add_field(name="🟢 Server", value=f"`{display_status}`", inline=True)
    e.add_field(name="👥 Players", value=f"`{players}`", inline=True)
    e.add_field(name="⏱️ Latency", value=f"`{latency_ms}ms`", inline=True)
    e.add_field(name="🕒 Last updated", value=_fmt_dt(updated_ts), inline=False)

    raw = (raw or "").strip()
    if raw:
        if len(raw) > 900:
            raw = raw[:900] + "…"
        e.add_field(name="📄 Raw output", value=f"```{raw}```", inline=False)

    e.set_footer(text=f"PZBot v{cfg.BOT_VERSION}")
    return e


def build_players_embed(count: int, body: str, latency_ms: int, updated_ts: int) -> discord.Embed:
    color = SEV_GREEN if count > 0 else SEV_BLUE

    e = discord.Embed(title="👥 PZ — Players", color=color)
    e.add_field(name="👥 Online", value=f"`{count}`", inline=True)
    e.add_field(name="⏱️ Latency", value=f"`{latency_ms}ms`", inline=True)
    e.add_field(name="🕒 Last updated", value=_fmt_dt(updated_ts), inline=False)

    body = (body or "").strip() or "(none)"
    if len(body) > 1500:
        body = body[:1500] + "…"
    e.add_field(name="📋 List", value=f"```{body}```", inline=False)

    e.set_footer(text=f"PZBot v{cfg.BOT_VERSION}")
    return e


# ------------------ Refresh views (mini rate-limit) ------------------
class BaseRefreshView(discord.ui.View):
    def __init__(self, *, owner_user_id: int, min_interval_sec: float = 2.0):
        super().__init__(timeout=180)
        self.owner_user_id = owner_user_id
        self.min_interval_sec = float(min_interval_sec)
        self._last_refresh = 0.0

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_user_id:
            await interaction.response.send_message("Not your panel.", ephemeral=True, allowed_mentions=_no_mentions())
            return False
        return True

    def _rate_limit_ok(self) -> bool:
        now = time.time()
        if now - self._last_refresh < self.min_interval_sec:
            return False
        self._last_refresh = now
        return True


class StatusRefreshView(BaseRefreshView):
    @discord.ui.button(label="Refresh", emoji="🔄", style=discord.ButtonStyle.secondary)
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._rate_limit_ok():
            await interaction.response.send_message(
                "Slow down — try again in a second.",
                ephemeral=True,
                allowed_mentions=_no_mentions(),
            )
            return

        loading = make_embed("🔄 Refreshing…", "Updating status…", SEV_BLUE)
        await interaction.response.edit_message(embed=loading, view=self)

        t0 = time.perf_counter()
        code, out = await run_control("status")
        latency_ms = int((time.perf_counter() - t0) * 1000)
        updated_ts = _now_unix()

        if code != 0:
            emb = make_embed("🛰️ PZ — Status", f"```{out}```", SEV_RED)
        else:
            status, players = parse_status_with_players(out)
            emb = build_status_embed(status, players, latency_ms, out, updated_ts)

        await interaction.edit_original_response(embed=emb, view=self)


class PlayersRefreshView(BaseRefreshView):
    @discord.ui.button(label="Refresh", emoji="🔄", style=discord.ButtonStyle.secondary)
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self._rate_limit_ok():
            await interaction.response.send_message(
                "Slow down — try again in a second.",
                ephemeral=True,
                allowed_mentions=_no_mentions(),
            )
            return

        loading = make_embed("🔄 Refreshing…", "Updating players…", SEV_BLUE)
        await interaction.response.edit_message(embed=loading, view=self)

        t0 = time.perf_counter()
        code, out = await run_control("players")
        latency_ms = int((time.perf_counter() - t0) * 1000)
        updated_ts = _now_unix()

        if code != 0:
            emb = make_embed("👥 PZ — Players", f"```{out}```", SEV_RED)
        else:
            n, body = parse_players_output(out)
            emb = build_players_embed(n, body, latency_ms, updated_ts)

        await interaction.edit_original_response(embed=emb, view=self)


class LogRefreshView(discord.ui.View):
    def __init__(self, *, owner_user_id: int, mode: str):
        super().__init__(timeout=180)
        self.owner_user_id = owner_user_id
        self.mode = mode
        self._last_refresh = 0.0

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.owner_user_id:
            await interaction.response.send_message(
                "Not your log panel.",
                ephemeral=True,
                allowed_mentions=_no_mentions(),
            )
            return False
        return True

    @discord.ui.button(label="Refresh", emoji="🔄", style=discord.ButtonStyle.secondary)
    async def refresh(self, interaction: discord.Interaction, button: discord.ui.Button):
        now = time.time()
        if now - self._last_refresh < 2.0:
            await interaction.response.send_message(
                "Too fast — try again in a second.",
                ephemeral=True,
                allowed_mentions=_no_mentions(),
            )
            return
        self._last_refresh = now

        loading = make_embed("🔄 Refreshing…", "Updating logs…", SEV_BLUE)
        await interaction.response.edit_message(embed=loading, view=self)

        code, out = await run_logscan()
        if code != 0:
            emb = make_embed("🧩 PZ — Logs", f"```{out}```", SEV_RED)
        else:
            data = parse_logscan_json(out)
            emb = build_log_embed(self.mode, data)

        await interaction.edit_original_response(embed=emb, view=self)


# ------------------ Discord client ------------------
intents = discord.Intents.default()
intents.members = True


class PZBotClient(discord.Client):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._presence_task_started = False

    async def setup_hook(self):
        # Sync commands to one guild (fast propagation)
        try:
            guild = discord.Object(id=cfg.DISCORD_GUILD_ID)
            tree.copy_global_to(guild=guild)
            await tree.sync(guild=guild)
            logger.info("Slash commands synced to guild %s", cfg.DISCORD_GUILD_ID)
        except Exception:
            logger.exception("Slash sync failed")

        # Start presence loop once (fixes "stuck presence")
        if not self._presence_task_started:
            self._presence_task_started = True
            asyncio.create_task(update_presence_loop())
            logger.info("Presence loop started")


client = PZBotClient(intents=intents)
tree = app_commands.CommandTree(client)


@client.event
async def on_ready():
    logger.info("Logged in as %s (id=%s)", client.user, client.user.id)


# ------------------ Presence loop (ROTATE COMMANDS + PLAYERS every 30s) ------------------
async def update_presence_loop():
    await client.wait_until_ready()

    interval = max(10, int(cfg.STATUS_REFRESH_SECONDS))
    idx = 0

    while not client.is_closed():
        try:
            code, out = await run_control("status")
            status, players = parse_status_with_players(out)

            if code != 0:
                await client.change_presence(activity=discord.Game(name="⚠️ PZ ERROR"))
                await asyncio.sleep(interval)
                continue

            normalized = "ONLINE" if status == "RUNNING" else status
            players_display = players if players != "?" else "?"

            if normalized == "ONLINE":
                lines = [
                    f"🟢 ONLINE : /pz_help",
                    f"🟢 ONLINE : 👥 {players_display}",
                    f"🟢 ONLINE : /pz_status",
                    f"🟢 ONLINE : 👥 {players_display}",
                    f"🟢 ONLINE : /pz_version",
                    f"🟢 ONLINE : 👥 {players_display}",
                ]
            else:
                lines = [
                    f"🔴 {normalized} : /pz_status",
                    f"🔴 {normalized} : 👥 {players_display}",
                    f"🔴 {normalized} : /pz_help",
                    f"🔴 {normalized} : 👥 {players_display}",
                    f"🔴 {normalized} : /pz_version",
                    f"🔴 {normalized} : 👥 {players_display}",
                ]

            await client.change_presence(activity=discord.Game(name=lines[idx % len(lines)]))
            idx += 1

        except Exception:
            logger.exception("Presence update failed")

        await asyncio.sleep(interval)


# ------------------ Commands ------------------
@tree.command(name="pz_help", description="Show PZBot commands", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        "**Core**\n"
        "• `/pz_status` — Server status (refreshable)\n"
        "• `/pz_players` — Online players (refreshable)\n"
        "• `/pz_ping` — Bot ping\n"
        "• `/pz_version` — Bot version\n\n"
        "**Admin**\n"
        "• `/pz_start` `/pz_stop` `/pz_restart`\n"
        "• `/pz_save` — Save world (confirm)\n"
        "• `/pz_workshop_check` — Run workshop check\n\n"
        "**Logs**\n"
        "• `/pz_logstats` — Log stats (refresh)\n"
        "• `/pz_logs_recent` — Recent critical (refresh)\n"
        "• `/pz_logs_top` — Top signatures (refresh)\n\n"
        "**Ignore**\n"
        "• `/pz_ignore_add <regex>`\n"
        "• `/pz_ignore_remove <regex>`\n"
        "• `/pz_ignore_list`\n\n"
        f"**Confirm:** {cfg.CONFIRM_SECONDS}s"
    )
    await i.response.send_message(
        embed=make_embed("🧩 PZ — Help", desc, SEV_BLUE),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_version", description="Show bot version", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_version(i: discord.Interaction):
    await i.response.send_message(
        embed=make_embed("🏷️ PZ — Version", f"`{cfg.BOT_VERSION}`", SEV_BLUE),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_ping", description="Bot ping", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.defer(ephemeral=True, thinking=True)
    bot_ms = int(client.latency * 1000)
    await i.followup.send(
        embed=make_embed("📶 PZ — Ping", f"🤖 Bot WS latency: `{bot_ms}ms`", SEV_BLUE),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_status", description="Show PZ server status", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_status(i: discord.Interaction):
    await i.response.defer(ephemeral=True, thinking=True)

    t0 = time.perf_counter()
    code, out = await run_control("status")
    latency_ms = int((time.perf_counter() - t0) * 1000)
    updated_ts = _now_unix()

    if code != 0:
        emb = make_embed("🛰️ PZ — Status", f"```{out}```", SEV_RED)
        await i.followup.send(embed=emb, ephemeral=True, allowed_mentions=_no_mentions())
        return

    status, players = parse_status_with_players(out)
    emb = build_status_embed(status, players, latency_ms, out, updated_ts)

    await i.followup.send(
        embed=emb,
        view=StatusRefreshView(owner_user_id=i.user.id, min_interval_sec=2.0),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_players", description="Show online players", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_players(i: discord.Interaction):
    await i.response.defer(ephemeral=True, thinking=True)

    t0 = time.perf_counter()
    code, out = await run_control("players")
    latency_ms = int((time.perf_counter() - t0) * 1000)
    updated_ts = _now_unix()

    if code != 0:
        emb = make_embed("👥 PZ — Players", f"```{out}```", SEV_RED)
        await i.followup.send(embed=emb, ephemeral=True, allowed_mentions=_no_mentions())
        return

    n, body = parse_players_output(out)
    emb = build_players_embed(n, body, latency_ms, updated_ts)

    await i.followup.send(
        embed=emb,
        view=PlayersRefreshView(owner_user_id=i.user.id, min_interval_sec=2.0),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_workshop_check", description="Run workshop check now", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_workshop_check(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_workshop_check()
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(
        embed=make_embed("🧰 PZ — Workshop Check", f"```{out}```", color),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


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
        await interaction.edit_original_response(
            embed=make_embed("💾 PZ — Save", f"```{out}```", color),
            view=None,
        )

    await i.response.send_message(
        embed=make_embed("⚠️ Confirm", "Save the world now?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_start", description="Start the PZ server (admin)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_start(i: discord.Interaction):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)
    code, out = await run_control("start")
    color = SEV_GREEN if code == 0 else SEV_RED
    await i.followup.send(
        embed=make_embed("🟢 PZ — Start", f"```{out}```", color),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


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
        await interaction.edit_original_response(
            embed=make_embed("🛑 PZ — Stop", f"```{out}```", color),
            view=None,
        )

    await i.response.send_message(
        embed=make_embed("⚠️ Confirm", "Stop the server?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
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
        await interaction.edit_original_response(
            embed=make_embed("🔁 PZ — Restart", f"```{out}```", color),
            view=None,
        )

    await i.response.send_message(
        embed=make_embed("⚠️ Confirm", "Restart the server?", SEV_ORANGE),
        view=ConfirmView(cfg, pending, do_confirm),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_ignore_list", description="List ignore regex patterns", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ignore_list(i: discord.Interaction):
    patterns = load_ignore_patterns()
    if not patterns:
        await i.response.send_message(
            embed=make_embed("🧹 PZ — Ignore List", "(empty)", SEV_BLUE),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )
        return

    txt = "\n".join(f"{idx + 1}. `{p}`" for idx, p in enumerate(patterns))
    await i.response.send_message(
        embed=make_embed("🧹 PZ — Ignore List", txt, SEV_BLUE),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_ignore_add", description="Add ignore regex pattern", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(regex="Regex pattern to ignore")
async def pz_ignore_add(i: discord.Interaction, regex: str):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    regex = (regex or "").strip()
    if not regex:
        await i.response.send_message(
            embed=make_embed("🧹 PZ — Ignore Add", "Regex cannot be empty.", SEV_RED),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )
        return

    err = validate_regex(regex)
    if err:
        await i.response.send_message(
            embed=make_embed("🧹 PZ — Ignore Add", f"Invalid regex: `{err}`", SEV_RED),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )
        return

    patterns = load_ignore_patterns()
    if regex in patterns:
        await i.response.send_message(
            embed=make_embed("🧹 PZ — Ignore Add", "Already exists.", SEV_BLUE),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )
        return

    patterns.append(regex)
    save_ignore_patterns(patterns)
    await i.response.send_message(
        embed=make_embed("✅ PZ — Ignore Add", f"Added: `{regex}`", SEV_GREEN),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


@tree.command(name="pz_ignore_remove", description="Remove ignore regex pattern", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(regex="Regex pattern to remove")
async def pz_ignore_remove(i: discord.Interaction, regex: str):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    regex = (regex or "").strip()
    patterns = load_ignore_patterns()

    if regex not in patterns:
        await i.response.send_message(
            embed=make_embed("🧹 PZ — Ignore Remove", "Not found.", SEV_RED),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )
        return

    patterns = [p for p in patterns if p != regex]
    save_ignore_patterns(patterns)
    await i.response.send_message(
        embed=make_embed("✅ PZ — Ignore Remove", f"Removed: `{regex}`", SEV_GREEN),
        ephemeral=True,
        allowed_mentions=_no_mentions(),
    )


async def _send_log_panel(i: discord.Interaction, mode: str):
    m = await require_admin(cfg, i)
    if await deny_if_needed(i, m):
        return

    await i.response.defer(ephemeral=True, thinking=True)

    try:
        code, out = await run_logscan()
        if code != 0:
            await i.followup.send(
                embed=make_embed("🧩 PZ — Logs", f"```{out}```", SEV_RED),
                ephemeral=True,
                allowed_mentions=_no_mentions(),
            )
            return

        data = parse_logscan_json(out)
        emb = build_log_embed(mode, data)
        await i.followup.send(
            embed=emb,
            view=LogRefreshView(owner_user_id=i.user.id, mode=mode),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )

    except Exception as e:
        logger.exception("Failed /pz_logs_%s", mode)
        await i.followup.send(
            embed=make_embed("❌ PZ — Logs", f"Error while building panel: `{type(e).__name__}`", SEV_RED),
            ephemeral=True,
            allowed_mentions=_no_mentions(),
        )


@tree.command(name="pz_logstats", description="Log stats", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logstats(i: discord.Interaction):
    await _send_log_panel(i, "stats")


@tree.command(name="pz_logs_recent", description="Recent critical excerpts", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logs_recent(i: discord.Interaction):
    await _send_log_panel(i, "recent")


@tree.command(name="pz_logs_top", description="Top signatures", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_logs_top(i: discord.Interaction):
    await _send_log_panel(i, "top")


# ------------------ Entrypoint ------------------
def main():
    if not cfg.DISCORD_BOT_TOKEN:
        raise RuntimeError("DISCORD_BOT_TOKEN is missing.")
    client.run(cfg.DISCORD_BOT_TOKEN)


if __name__ == "__main__":
    main()
