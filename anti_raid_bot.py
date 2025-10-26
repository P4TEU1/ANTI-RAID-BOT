"""
Discord anti-raid & anti-spam bot cu curățare mesaje (discord.py oficial)

Instrucțiuni rapide:
- Setează env var: DISCORD_TOKEN
- Opțional: modificați CONFIG la început (whitelist_ids, thresholds, log_channel_id etc.)
- Cere permisiuni: Manage Roles, Kick Members, Ban Members, Moderate Members, View Audit Log, Send Messages, Manage Messages
- Rulare: python anti_raid_bot.py
"""

import os
import asyncio
import time
from collections import deque, defaultdict
from datetime import timedelta
import logging

import discord
from discord.ext import commands, tasks
from discord.utils import utcnow

# -------------------- CONFIG --------------------
CONFIG = {
    "whitelist_ids": [],
    "log_channel_id": None,
    "raid_window_seconds": 10,
    "raid_join_threshold": 6,
    "raid_action_on_bot": "ban",
    "raid_action_on_human": "timeout",
    "raid_timeout_seconds": 60 * 60,
    "spam_window_seconds": 7,
    "spam_message_threshold": 6,
    "spam_action": "timeout",
    "spam_timeout_seconds": 15 * 60,
    "moderation_reason_prefix": "AntiRaid/AntiSpam",
    "mute_role_name": "Muted",
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
recent_joins = deque()
user_message_times = defaultdict(deque)

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
    if CONFIG["owner_id"]:
        owner = bot.get_user(CONFIG["owner_id"]) or await bot.fetch_user(CONFIG["owner_id"])
        try:
            await owner.send(f"[{guild.name}] {content}")
        except Exception:
            pass


async def purge_user_messages(guild: discord.Guild, member: discord.Member, seconds: int = 60):
    """Șterge mesajele userului în ultimele `seconds` secunde din toate canalele text."""
    for channel in guild.text_channels:
        try:
            await channel.purge(limit=100, check=lambda m: m.author.id == member.id and (utcnow() - m.created_at).total_seconds() <= seconds)
        except Exception:
            continue


async def safe_action_member(guild: discord.Guild, member: discord.Member, action: str, reason: str = ""):
    reason_full = f"{CONFIG['moderation_reason_prefix']}: {reason}" if reason else CONFIG['moderation_reason_prefix']
    try:
        # Șterge mesajele recent spammate înainte de acțiune
        if action in ["timeout", "kick", "ban"]:
            await purge_user_messages(guild, member, seconds=CONFIG["spam_window_seconds"])

        if action == "ban":
            await guild.ban(member, reason=reason_full)
            await send_log(guild, f"Banned {member} ({member.id}). Reason: {reason}")
        elif action == "kick":
            await member.kick(reason=reason_full)
            await send_log(guild, f"Kicked {member} ({member.id}). Reason: {reason}")
        elif action == "timeout":
            until = utcnow() + timedelta(seconds=CONFIG.get("raid_timeout_seconds", CONFIG.get("spam_timeout_seconds", 3600)))
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
        cleanup_old_joins.start()

@bot.event
async def on_member_join(member: discord.Member):
    now = time.time()
    recent_joins.append((now, member.guild.id, member.id, member.bot))
    window = CONFIG["raid_window_seconds"]
    cutoff = now - window
    while recent_joins and recent_joins[0][0] < cutoff:
        recent_joins.popleft()
    count = sum(1 for t, gid, mid, isbot in recent_joins if gid == member.guild.id)

    if count >= CONFIG["raid_join_threshold"]:
        await send_log(member.guild, f"Raid detected: {count} joins within {window}s")
        for t, gid, mid, isbot in list(recent_joins):
            if gid != member.guild.id:
                continue
            try:
                m = member.guild.get_member(mid) or await member.guild.fetch_member(mid)
            except Exception:
                continue

            if is_whitelisted(m):
                await send_log(member.guild, f"Whitelisted member {m} skipped")
                continue

            if m.bot:
                action = CONFIG["raid_action_on_bot"]
                await safe_action_member(member.guild, m, action, reason="Auto-action on bot during raid")
            else:
                action = CONFIG["raid_action_on_human"]
                await safe_action_member(member.guild, m, action, reason="Auto-action on human during raid")

        for i in range(len(recent_joins)-1, -1, -1):
            if recent_joins[i][1] == member.guild.id:
                recent_joins.remove(recent_joins[i])

@tasks.loop(seconds=60)
async def cleanup_old_joins():
    now = time.time()
    max_window = max(CONFIG["raid_window_seconds"], CONFIG["spam_window_seconds"]) + 5
    cutoff = now - max_window
    while recent_joins and recent_joins[0][0] < cutoff:
        recent_joins.popleft()

@bot.event
async def on_message(message: discord.Message):
    if not message.guild or message.author.bot:
        return

    user_id = message.author.id
    now = time.time()
    dq = user_message_times[user_id]
    dq.append(now)
    cutoff = now - CONFIG["spam_window_seconds"]
    while dq and dq[0] < cutoff:
        dq.popleft()

    if len(dq) >= CONFIG["spam_message_threshold"]:
        guild = message.guild
        member = message.author
        if is_whitelisted(member):
            await send_log(guild, f"Whitelisted user {member} exceeded spam but skipped.")
            dq.clear()
            return

        action = CONFIG["spam_action"]
        reason = f"Sent {len(dq)} messages in {CONFIG['spam_window_seconds']}s"
        await safe_action_member(guild, member, action, reason=reason)
        dq.clear()

    await bot.process_commands(message)

# -------------------- APP COMMANDS --------------------
@bot.tree.command(description="Set a config option (owner only)")
@commands.is_owner()
async def setconfig(interaction: discord.Interaction, key: str, value: str):
    if key not in CONFIG:
        await interaction.response.send_message(f"Unknown key: {key}")
        return
    orig = CONFIG[key]
    try:
        if isinstance(orig, bool):
            new_val = value.lower() in ("1", "true", "yes", "on")
        elif isinstance(orig, int):
            new_val = int(value)
        elif isinstance(orig, list):
            new_val = [int(x.strip()) for x in value.split(",")] if value.strip() else []
        else:
            new_val = value
        CONFIG[key] = new_val
        await interaction.response.send_message(f"Set {key} = {new_val}")
    except Exception as e:
        await interaction.response.send_message(f"Failed to set {key}: {e}")

@bot.tree.command(description="Show current config (owner only)")
@commands.is_owner()
async def showconfig(interaction: discord.Interaction):
    nice = "\n".join(f"{k}: {v}" for k, v in CONFIG.items())
    msg = f"Current config:\n```{nice}```"
    await interaction.response.send_message(msg)

# -------------------- START --------------------
def main():
    token = os.environ.get("DISCORD_TOKEN")
    if not token:
        print("Error: set DISCORD_TOKEN environment variable")
        return

    owner = os.environ.get("OWNER_ID")
    if owner:
        try:
            CONFIG["owner_id"] = int(owner)
        except Exception:
            CONFIG["owner_id"] = None

    log_chan = os.environ.get("LOG_CHANNEL_ID")
    if log_chan:
        try:
            CONFIG["log_channel_id"] = int(log_chan)
        except Exception:
            CONFIG["log_channel_id"] = None

    try:
        bot.run(token)
    except Exception as e:
        logger.exception("Bot failed to start:")

if __name__ == "__main__":
    main()
