"""
Discord anti-raid & anti-spam bot (single-file)

Instrucțiuni rapide:
- Setează în env var: DISCORD_TOKEN
- Opțional: modificați CONFIG la început (whitelist_ids, thresholds, log_channel_id etc.)
- Cere permisiuni: Manage Roles, Kick Members, Ban Members, Moderate Members, View Audit Log, Send Messages
- Rulare: python discord_anti_raid_bot.py

Funcționalități:
- Detectează valuri de join (raid) și aplică acțiuni pe membrii recenți
- Detectează spam pe utilizator (mesaje multiple într-o fereastră) și aplică timeout/kick/ban
- Blochează "boti externi" (conturi cu member.bot True) care nu sunt în whitelist
- Canal de log configurabil

Notă: folosiți cu atenție. Testați pe un server de test înainte de a activa pe servere reale.
"""

import os
import asyncio
import time
from collections import deque, defaultdict
from datetime import datetime, timedelta
import logging

import discord
from discord import Option
from discord.ext import commands, tasks
import sys
import types

# Patch pentru lipsa audioop in Python 3.13+
if sys.version_info >= (3, 13):
    sys.modules["audioop"] = types.ModuleType("audioop")

# -------------------- CONFIG --------------------
# Modificați după nevoie.
CONFIG = {
    # Lista de user IDs (int) sau bot IDs permise explicit (owner, bot-accounts, etc.)
    "whitelist_ids": [],

    # ID canal pentru log-uri (setati None pentru DM la owner). Example: 123456789012345678
    "log_channel_id": None,

    # Raid detection (join flood)
    "raid_window_seconds": 10,       # fereastra de timp pentru a conta join-urile
    "raid_join_threshold": 6,        # daca >= acest numar de join-uri in fereastra -> raid
    "raid_action_on_bot": "ban",   # action for bots in raid: "ban" / "kick" / "timeout" / "none"
    "raid_action_on_human": "timeout",  # action for humans in raid
    "raid_timeout_seconds": 60 * 60, # timeout length for humans (seconds) - 1h default

    # Per-user spam detection
    "spam_window_seconds": 7,  # fereastra in secunde
    "spam_message_threshold": 6,  # mesaje in fereastra care declanseaza actiunea
    "spam_action": "timeout",  # "timeout" / "kick" / "ban" / "none"
    "spam_timeout_seconds": 15 * 60,  # 15 minute timeout

    # Kick/ban reasons
    "moderation_reason_prefix": "AntiRaid/AntiSpam",

    # Role name used as mute (optional). If not found, we'll try to timeout members instead.
    "mute_role_name": "Muted",

    # Bot owner for emergency messages (set your user id)
    "owner_id": None,
}

# -------------------- LOGGING --------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("anti-raid-bot")

# -------------------- BOT SETUP --------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.messages = True

bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# In-memory structures
recent_joins = deque()  # each item: (timestamp, guild_id, member_id)
user_message_times = defaultdict(deque)  # user_id -> deque of timestamps

# -------------------- HELPERS --------------------

def is_whitelisted(member: discord.Member):
    if member.id in CONFIG["whitelist_ids"]:
        return True
    if CONFIG["owner_id"] and member.id == CONFIG["owner_id"]:
        return True
    return False

async def send_log(guild: discord.Guild, content: str):
    logger.info(f"[{guild.name}] {content}")
    if CONFIG["log_channel_id"]:
        chan = guild.get_channel(CONFIG["log_channel_id"]) or bot.get_channel(CONFIG["log_channel_id"]) 
        if chan:
            try:
                await chan.send(content)
                return
            except Exception:
                pass
    # fallback: DM to owner if available
    if CONFIG["owner_id"]:
        owner = bot.get_user(CONFIG["owner_id"]) or await bot.fetch_user(CONFIG["owner_id"])
        try:
            await owner.send(f"[{guild.name}] {content}")
        except Exception:
            pass

async def safe_action_member(guild: discord.Guild, member: discord.Member, action: str, reason: str = ""):
    reason_full = f"{CONFIG['moderation_reason_prefix']}: {reason}" if reason else CONFIG['moderation_reason_prefix']
    try:
        if action == "ban":
            await guild.ban(member, reason=reason_full)
            await send_log(guild, f"Banned {member} ({member.id}). Reason: {reason}")
        elif action == "kick":
            await member.kick(reason=reason_full)
            await send_log(guild, f"Kicked {member} ({member.id}). Reason: {reason}")
        elif action == "timeout":
            # discord.py supports member.edit(timeout=duration) with datetime
            until = datetime.utcnow() + timedelta(seconds=CONFIG.get("raid_timeout_seconds", CONFIG.get("spam_timeout_seconds", 3600)))
            await member.timeout(until, reason=reason_full)
            await send_log(guild, f"Timed out {member} ({member.id}) until {until.isoformat()}. Reason: {reason}")
        elif action == "none":
            await send_log(guild, f"No action taken for {member} ({member.id}). Reason: {reason}")
        else:
            await send_log(guild, f"Unknown action '{action}' for {member} ({member.id}).")
    except Exception as e:
        await send_log(guild, f"Failed to {action} {member} ({member.id}): {e}")

# -------------------- EVENT HANDLERS --------------------

@bot.event
async def on_ready():
    logger.info(f"Bot ready. Logged in as {bot.user} (id: {bot.user.id})")
    if bot.user:
        # start background cleanup if needed
        cleanup_old_joins.start()

@bot.event
async def on_guild_join(guild: discord.Guild):
    await send_log(guild, f"Joined guild: {guild.name} ({guild.id})")

@bot.event
async def on_member_join(member: discord.Member):
    now = time.time()
    recent_joins.append((now, member.guild.id, member.id, member.bot))

    # purge old
    window = CONFIG["raid_window_seconds"]
    cutoff = now - window
    while recent_joins and recent_joins[0][0] < cutoff:
        recent_joins.popleft()

    # count joins for this guild in window
    count = sum(1 for t, gid, mid, isbot in recent_joins if gid == member.guild.id)

    if count >= CONFIG["raid_join_threshold"]:
        # raid detected
        await send_log(member.guild, f"Raid detected: {count} joins within {window}s")
        # iterate through recent joins for this guild
        for t, gid, mid, isbot in list(recent_joins):
            if gid != member.guild.id:
                continue
            try:
                m = member.guild.get_member(mid)
                if not m:
                    # try fetch
                    m = await member.guild.fetch_member(mid)
            except Exception:
                continue

            if is_whitelisted(m):
                await send_log(member.guild, f"Whitelisted member {m} skipped")
                continue

            if m.bot:
                action = CONFIG["raid_action_on_bot"]
                await safe_action_member(member.guild, m, action, reason=f"Auto-action on bot during raid")
            else:
                action = CONFIG["raid_action_on_human"]
                await safe_action_member(member.guild, m, action, reason=f"Auto-action on human during raid")

        # clear recent joins for this guild so we don't repeatedly trigger
        for i in range(len(recent_joins) - 1, -1, -1):
            if recent_joins[i][1] == member.guild.id:
                recent_joins.remove(recent_joins[i])

@tasks.loop(seconds=60)
async def cleanup_old_joins():
    # purge entries older than max window to keep memory small
    now = time.time()
    max_window = max(CONFIG["raid_window_seconds"], CONFIG["spam_window_seconds"]) + 5
    cutoff = now - max_window
    while recent_joins and recent_joins[0][0] < cutoff:
        recent_joins.popleft()

@bot.event
async def on_message(message: discord.Message):
    # ignore bots and DMs
    if not message.guild:
        return
    if message.author.bot:
        return

    user_id = message.author.id
    now = time.time()
    dq = user_message_times[user_id]
    dq.append(now)

    # purge old
    cutoff = now - CONFIG["spam_window_seconds"]
    while dq and dq[0] < cutoff:
        dq.popleft()

    if len(dq) >= CONFIG["spam_message_threshold"]:
        # spam detected
        guild = message.guild
        member = message.author
        if is_whitelisted(member):
            await send_log(guild, f"Whitelisted user {member} exceeded spam but skipped.")
            dq.clear()
            return

        action = CONFIG["spam_action"]
        reason = f"Sent {len(dq)} messages in {CONFIG["spam_window_seconds"]}s"
        await safe_action_member(guild, member, action, reason=reason)
        dq.clear()

    await bot.process_commands(message)

# -------------------- ADMIN COMMANDS --------------------

@bot.slash_command(description="Set a config option (owner only)")
@commands.is_owner()
async def setconfig(ctx, key: Option(str, "Config key"), value: Option(str, "New value as string")):
    # simple setter for quick adjustments
    if key not in CONFIG:
        await ctx.respond(f"Unknown key: {key}")
        return
    # try to cast types in a few common ways
    orig = CONFIG[key]
    new = value
    try:
        if isinstance(orig, bool):
            new_cast = value.lower() in ("1", "true", "yes", "on")
        elif isinstance(orig, int):
            new_cast = int(value)
        elif isinstance(orig, list):
            # assume comma-separated ints
            if value.strip() == "":
                new_cast = []
            else:
                new_cast = [int(x.strip()) for x in value.split(",")]
        else:
            new_cast = value
        CONFIG[key] = new_cast
        await ctx.respond(f"Set {key} = {new_cast}")
    except Exception as e:
        await ctx.respond(f"Failed to set {key}: {e}")

@bot.slash_command(description="Show current config (owner only)")
@commands.is_owner()
async def showconfig(ctx):
    nice = "\n".join(f"{k}: {v}" for k, v in CONFIG.items())
    msg = f"Current config:\n```\\n{nice}\\n```"
    await ctx.respond(msg)

# -------------------- START --------------------

def main():
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        print("Error: set DISCORD_TOKEN environment variable")
        return
    owner = CONFIG.get("owner_id")
    if owner:
        try:
            owner = int(owner)
            CONFIG["owner_id"] = owner
        except Exception:
            CONFIG["owner_id"] = None

    try:
        bot.run(token)
    except Exception as e:
        logger.exception("Bot failed to start:")

if __name__ == "__main__":
    main()


