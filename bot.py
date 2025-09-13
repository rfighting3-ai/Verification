# bot.py
import discord
from discord.ext import commands, tasks
import asyncio, secrets, time, os, json
from db import init_db, create_verification, save_dna_profile, add_action, save_fingerprint, quarantine_member, get_quarantined
from detection import compute_risk
import aiosqlite

# Config from you
TOKEN_ENV = 'DISCORD_BOT_TOKEN'
TOKEN = os.getenv(TOKEN_ENV)
if not TOKEN:
    raise RuntimeError(f'Please set the {TOKEN_ENV} environment variable with your bot token.')

GUILD_ID = 1416287601677176916
VERIFY_ROLE_ID = 1416287654089068544
QUARANTINE_ROLE_ID = 1416287684514676786
MOD_LOG_CHANNEL_ID = 1416287627128078439

intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix='!', intents=intents)

recent_joins = []
surge_mode = False

@bot.event
async def on_ready():
    print('AegisX-S Bot ready as', bot.user)
    await init_db()
    surge_check.start()
    quarantine_check.start()
    # no honeypot creation by bot in demo; honeypot is in web page

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
            await ch.send('⚠️ Surge detected: multiple joins. Entering Surge Mode (stricter verification).')
    elif len(recent_joins) == 0 and surge_mode:
        surge_mode = False
        if ch:
            await ch.send('✅ Surge ended: returning to normal verification.')

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
                    except Exception:
                        pass
            await add_action(discord_id, 'quarantine_expired', 'Auto-unquarantine after time-bomb expiration.')

@bot.event
async def on_member_join(member: discord.Member):
    if member.guild.id != GUILD_ID:
        return
    recent_joins.append(time.time())
    token = secrets.token_urlsafe(18)
    await create_verification(token, str(member.id))
    VERIFY_BASE = os.getenv('VERIFY_BASE', 'http://localhost:5000')
    link = f'{VERIFY_BASE}/start/{token}'
    try:
        await member.send(f'Welcome to {member.guild.name}! Please verify here: {link}')
    except Exception:
        ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
        if ch:
            await ch.send(f'Could not DM {member.mention}. Verification link (public): {link}')
    # give limited role if needed (optional)

@bot.command()
@commands.has_permissions(manage_guild=True)
async def verifynow(ctx, member: discord.Member):
    token = secrets.token_urlsafe(18)
    await create_verification(token, str(member.id))
    try:
        await member.send(f'Please verify here: http://localhost:5000/start/{token}')
        await ctx.send(f'Verify link DMd to {member.mention}')
    except Exception:
        await ctx.send('Failed to DM user.')

@bot.command()
@commands.has_permissions(manage_guild=True)
async def scan(ctx, member: discord.Member):
    async with aiosqlite.connect('aegisx_s.db') as db:
        cur = await db.execute(
            'SELECT v.discord_id, f.fp, f.ip, f.asn, f.ua, f.honeypot FROM verifications v LEFT JOIN fingerprints f ON v.token=f.token WHERE v.discord_id = ? ORDER BY f.created_at DESC LIMIT 1',
            (str(member.id),)
        )
        row = await cur.fetchone()
        if not row:
            await ctx.send('No verification/fingerprint found for that user.')
            return
        discord_id, fp, ip, asn, ua, honeypot = row
        embed = discord.Embed(title='Quick Scan', color=discord.Color.orange())
        embed.add_field(name='Discord ID', value=str(discord_id), inline=False)
        embed.add_field(name='Fingerprint', value=str(fp or 'N/A'), inline=True)
        embed.add_field(name='IP', value=str(ip or 'N/A'), inline=True)
        embed.add_field(name='ASN', value=str(asn or 'N/A'), inline=False)
        embed.add_field(name='Honeypot', value='Yes' if honeypot else 'No', inline=True)
        await ctx.send(embed=embed)

# enforced quarantine helper (no auto-ban)
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
