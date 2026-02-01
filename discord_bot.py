# discord_bot.py
from __future__ import annotations

import asyncio
import logging
import os
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
    # No explicit colors requested; Discord default is fine; but embeds look better with color.
    # We'll use minimal, predictable colors without being flashy.
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
            embed=make_embed("Accès refusé", "Impossible de résoudre le membre. Vérifie **Server Members Intent**.", ok=False),
            ephemeral=True,
        )
        return None

    if has_admin_role(cfg, m) or has_discord_admin_perm(m) or has_channel_permission(cfg, i, m):
        return m

    await i.response.send_message(
        embed=make_embed("Accès refusé", "Tu n’as pas les permissions requises pour cette commande.", ok=False),
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
        # Only the same user can confirm
        if interaction.user.id != self.pending.interaction_user_id:
            await interaction.response.send_message(
                embed=make_embed("Confirmation", "Seul l’auteur de la commande peut confirmer.", ok=False),
                ephemeral=True,
            )
            return False
        return True

    @discord.ui.button(label="Confirmer", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.on_confirm(interaction)
        self.stop()

    @discord.ui.button(label="Annuler", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.edit_message(
            embed=make_embed("Annulé", "Action annulée.", ok=None),
            view=None,
        )
        self.stop()

    async def on_timeout(self):
        # If message still exists, it will just show view disabled.
        pass


# ------------------ Bot ------------------
cfg = load_config()
logger = setup_logging(cfg)
cooldown = Cooldown(cfg.COOLDOWN_SECONDS)

intents = discord.Intents.default()
intents.members = True  # required for roles checks
client = discord.Client(intents=intents)
tree = app_commands.CommandTree(client)


async def run_control(action: str) -> tuple[int, str]:
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.PZ_CONTROL_PS1, ["-Action", action])


async def run_workshop_check() -> tuple[int, str]:
    # workshop script uses DISCORD_WEBHOOK_URL env var
    return await run_powershell_script(cfg.POWERSHELL_EXE, cfg.WORKSHOP_CHECK_PS1, [])


async def update_presence_loop():
    await client.wait_until_ready()
    while not client.is_closed():
        try:
            code, out = await run_control("status")
            status = (out or "").strip().upper()
            if "RUNNING" in status:
                await client.change_presence(activity=discord.Game("PZ: RUNNING"), status=discord.Status.online)
            elif "STOPPED" in status:
                await client.change_presence(activity=discord.Game("PZ: STOPPED"), status=discord.Status.idle)
            else:
                # unknown
                await client.change_presence(activity=discord.Game("PZ: ?"), status=discord.Status.dnd)
        except Exception:
            # don’t spam logs here
            pass
        await asyncio.sleep(cfg.STATUS_REFRESH_SECONDS)


def log_action(i: discord.Interaction, action: str, exit_code: int, out: str):
    g = i.guild.id if i.guild else 0
    ch = i.channel.id if i.channel else 0
    line = f"action={action} user={user_tag(i)} guild={g} channel={ch} exit={exit_code} out={out.replace('\n','\\n')[:200]}"
    logger.info(line)
    audit_log(cfg, line)


# ------------------ Commands ------------------
@tree.command(name="pz_ping", description="Healthcheck du bot", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_ping(i: discord.Interaction):
    await i.response.send_message(embed=make_embed("PZ — Ping", "✅ Pong.", ok=True), ephemeral=True)


@tree.command(name="pz_help", description="Liste des commandes + règles d’accès", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_help(i: discord.Interaction):
    desc = (
        "**Commandes**\n"
        "• `/pz_status` — affiche l’état du serveur\n"
        "• `/pz_save` — save world (sensitif)\n"
        "• `/pz_stop` — arrêt serveur (sensitif, confirmation)\n"
        "• `/pz_start` — démarrer serveur (sensitif, confirmation)\n"
        "• `/pz_restart` — restart serveur (sensitif, confirmation)\n"
        "• `/pz_workshop_check` — vérifie updates workshop (via webhook)\n"
        "• `/pz_grant @user` — donne le rôle PZ\n"
        "• `/pz_revoke @user` — retire le rôle PZ\n"
        "• `/pz_ping` — healthcheck bot\n\n"
        "**Accès**\n"
        f"• Rôle requis: <@&{cfg.PZ_ADMIN_ROLE_ID}>\n"
        "• OU permission Discord `Administrator`\n"
        "• OU (si activé) permissions de channel: `manage_guild` / `manage_channels` / `manage_messages`\n\n"
        f"**Cooldown**: {cfg.COOLDOWN_SECONDS}s (commandes sensibles)\n"
        f"**Confirmation**: {cfg.CONFIRM_SECONDS}s (stop/start/restart/grant/revoke)\n"
    )
    await i.response.send_message(embed=make_embed("PZ — Help", desc, ok=None), ephemeral=True)


@tree.command(name="pz_status", description="Status du serveur Project Zomboid", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_status(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    code, out = await run_control("status")
    ok = (code == 0) and ("RUNNING" in out.upper() or "STOPPED" in out.upper())
    emb = make_embed("PZ — Status", f"**Résultat:** `{out}`", ok=ok)
    log_action(i, "status", code, out)
    await i.followup.send(embed=emb, ephemeral=True)


@tree.command(name="pz_save", description="Save world maintenant (sensitif)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_save(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "save"):
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Attends un peu avant de refaire `/pz_save`.", ok=False), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_control("save")
    ok = (code == 0) and ("OK" in out.upper() or "SAVED" in out.upper() or "STOPPED" in out.upper())
    log_action(i, "save", code, out)
    await i.followup.send(embed=make_embed("PZ — Save", f"**Résultat:** `{out}`", ok=ok), ephemeral=True)


async def _confirm_and_run(i: discord.Interaction, action: str, title: str):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, action):
        await i.response.send_message(embed=make_embed("Cooldown", f"⏳ Attends un peu avant de refaire `{action}`.", ok=False), ephemeral=True)
        return

    pending = PendingAction(action=action, created_at=time.time(), interaction_user_id=i.user.id)

    async def on_confirm(inter2: discord.Interaction):
        await inter2.response.defer(ephemeral=True)
        code, out = await run_control(action)
        ok = (code == 0) and ("ERROR" not in out.upper())
        log_action(i, action, code, out)
        await inter2.followup.send(embed=make_embed(title, f"**Résultat:** `{out}`", ok=ok), ephemeral=True)

    view = ConfirmView(cfg, pending, on_confirm)
    await i.response.send_message(
        embed=make_embed("Confirmation requise", f"Confirme l’action: **{action.upper()}**", ok=None),
        view=view,
        ephemeral=True,
    )


@tree.command(name="pz_stop", description="Stop serveur (sensitif)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_stop(i: discord.Interaction):
    await _confirm_and_run(i, "stop", "PZ — Stop")


@tree.command(name="pz_start", description="Start serveur (sensitif)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_start(i: discord.Interaction):
    await _confirm_and_run(i, "start", "PZ — Start")


@tree.command(name="pz_restart", description="Restart serveur (sensitif)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_restart(i: discord.Interaction):
    await _confirm_and_run(i, "restart", "PZ — Restart")


@tree.command(name="pz_workshop_check", description="Vérifie updates Workshop (webhook)", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
async def pz_workshop_check(i: discord.Interaction):
    if await require_admin(cfg, i) is None:
        return
    if not cooldown.check(i.user.id, "workshop_check"):
        await i.response.send_message(embed=make_embed("Cooldown", "⏳ Attends un peu avant de relancer le check.", ok=False), ephemeral=True)
        return

    await i.response.defer(ephemeral=True)
    code, out = await run_workshop_check()
    # IMPORTANT: ce script PS envoie déjà les embeds dans Discord via webhook.
    # Ici on renvoie juste un résumé propre.
    ok = (code == 0)
    log_action(i, "workshop_check", code, out)
    await i.followup.send(embed=make_embed("Workshop Check", "✅ Check lancé via webhook." if ok else f"❌ Erreur: `{out}`", ok=ok), ephemeral=True)


@tree.command(name="pz_grant", description="Donne le rôle PZ à un utilisateur", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="Utilisateur à autoriser")
async def pz_grant(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_grant(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Grant", "❌ Rôle introuvable (ID incorrect?).", ok=False), ephemeral=True)
            return
        await user.add_roles(role, reason=f"pz_grant by {user_tag(i)}")
        logger.info("grant role=%s(%s) target=%s(%s) by=%s", role.name, role.id, user.name, user.id, user_tag(i))
        audit_log(cfg, f"grant role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Grant", f"✅ Rôle **{role.name}** donné à {user.mention}.", ok=True), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("grant", time.time(), i.user.id), do_grant)
    await i.response.send_message(
        embed=make_embed("Confirmation requise", f"Donner le rôle PZ à {user.mention} ?", ok=None),
        view=view,
        ephemeral=True,
    )


@tree.command(name="pz_revoke", description="Retire le rôle PZ d’un utilisateur", guild=discord.Object(id=cfg.DISCORD_GUILD_ID))
@app_commands.describe(user="Utilisateur à retirer")
async def pz_revoke(i: discord.Interaction, user: discord.Member):
    if await require_admin(cfg, i) is None:
        return

    async def do_revoke(inter2: discord.Interaction):
        role = inter2.guild.get_role(cfg.PZ_ADMIN_ROLE_ID) if inter2.guild else None
        if role is None:
            await inter2.response.send_message(embed=make_embed("Revoke", "❌ Rôle introuvable (ID incorrect?).", ok=False), ephemeral=True)
            return
        await user.remove_roles(role, reason=f"pz_revoke by {user_tag(i)}")
        logger.info("revoke role=%s(%s) target=%s(%s) by=%s", role.name, role.id, user.name, user.id, user_tag(i))
        audit_log(cfg, f"revoke role={role.id} target={user.id} by={i.user.id}")
        await inter2.response.send_message(embed=make_embed("Revoke", f"✅ Rôle **{role.name}** retiré à {user.mention}.", ok=True), ephemeral=True)

    view = ConfirmView(cfg, PendingAction("revoke", time.time(), i.user.id), do_revoke)
    await i.response.send_message(
        embed=make_embed("Confirmation requise", f"Retirer le rôle PZ à {user.mention} ?", ok=None),
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

    # presence loop
    client.loop.create_task(update_presence_loop())


# ------------------ Run ------------------
client.run(cfg.DISCORD_BOT_TOKEN)
