# bot.py
import discord
from discord.ext import commands, tasks
import asyncio, secrets, time, os
from db import init_db, create_verification, add_action, quarantine_member, get_quarantined
import aiosqlite

# -----------------------
# Config
# -----------------------
TOKEN = os.getenv('DISCORD_BOT_TOKEN')
if not TOKEN:
    raise RuntimeError('Please set DISCORD_BOT_TOKEN environment variable.')

GUILD_ID = 1416287601677176916
VERIFY_ROLE_ID = 1416287654089068544
QUARANTINE_ROLE_ID = 1416287684514676786
MOD_LOG_CHANNEL_ID = 1416287627128078439

VERIFY_BASE = os.getenv('VERIFY_BASE', 'https://localhost:5000')

intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)

recent_joins = []
surge_mode = False

# -----------------------
# Bot ready
# -----------------------
@bot.event
async def on_ready():
    print('AegisX-S Bot ready as', bot.user)
    await init_db()
    surge_check.start()
    quarantine_check.start()

# -----------------------
# Surge detection
# -----------------------
@tasks.loop(seconds=10)
async def surge_check():
    global surge_mode
    now = time.time()
    window = 30
    while recent_joins and recent_joins[0] < now - window:
        recent_joins.pop(0)
    ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
    if len(recent_joins) >= 3 and not surge_mode:
        surge_mode = True
        if ch:
            await ch.send('⚠️ Surge detected: multiple joins. Entering Surge Mode.')
    elif len(recent_joins) == 0 and surge_mode:
        surge_mode = False
        if ch:
            await ch.send('✅ Surge ended: returning to normal verification.')

# -----------------------
# Quarantine check
# -----------------------
@tasks.loop(seconds=60)
async def quarantine_check():
    rows = await get_quarantined()
    now = int(time.time())
    guild = bot.get_guild(GUILD_ID)
    for row in rows:
        discord_id, until_ts = row
        if until_ts <= now:
            member = guild.get_member(int(discord_id)) if guild else None
            if member:
                qrole = guild.get_role(QUARANTINE_ROLE_ID)
                if qrole in member.roles:
                    try:
                        await member.remove_roles(qrole, reason='Quarantine period expired.')
                    except:
                        pass
            await add_action(discord_id, 'quarantine_expired', 'Auto-unquarantine after time-bomb expiration.')

# -----------------------
# Member join verification
# -----------------------
@bot.event
async def on_member_join(member: discord.Member):
    if member.guild.id != GUILD_ID:
        return
    recent_joins.append(time.time())

    token = secrets.token_urlsafe(18)
    await create_verification(token, str(member.id))
    link = f"{VERIFY_BASE}/start/{token}"

    ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
    if ch:
        await ch.send(f"{member.mention}, welcome! Please verify here: {link}")

# -----------------------
# Manual verification command
# -----------------------
@bot.command()
@commands.has_permissions(manage_guild=True)
async def verifynow(ctx, member: discord.Member):
    token = secrets.token_urlsafe(18)
    await create_verification(token, str(member.id))
    ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
    if ch:
        await ch.send(f"{member.mention}, here is your verification link: {VERIFY_BASE}/start/{token}")
    await ctx.send(f"✅ Verification link sent for {member.mention} in {ch.mention if ch else 'mod channel'}")

# -----------------------
# Quarantine helper
# -----------------------
async def apply_quarantine(member: discord.Member, hours=24, reason='Suspicious verification'):
    guild = member.guild
    qrole = guild.get_role(QUARANTINE_ROLE_ID)
    try:
        if qrole:
            await member.add_roles(qrole, reason=reason)
        until_ts = int(time.time()) + hours*3600
        await quarantine_member(str(member.id), until_ts)
        await add_action(str(member.id), 'quarantine_applied', reason)
        ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
        if ch:
            await ch.send(f'👮 Quarantine applied to {member.mention}: {reason}')
    except Exception as e:
        print('Failed to apply quarantine', e)

bot.run(TOKEN)
