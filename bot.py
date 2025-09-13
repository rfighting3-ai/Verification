# bot.py
"""
AegisX-S Bot (Double-Counter style premium features)
Runs an internal aiohttp webhook on 127.0.0.1:5001 to receive HMAC-signed
notifications from web.py when users submit the verification page.
Processes tokens immediately: DB lookup -> detection -> role assignment.
Includes admin export command to DM a CSV to the caller.

Env vars required:
- DISCORD_BOT_TOKEN
- VERIFY_BASE (public URL used for links)
- VERIFY_SECRET (HMAC secret; must match web.py)
- ADMIN_SECRET (for CSV export protection)
Optional:
- IPQS_KEY (IPQualityScore API key)
- IPINFO_TOKEN (ipinfo.io token)
- QUARANTINE_THRESHOLD (int, default 60)
- QUARANTINE_HOURS (int, default 24)
- AUTO_BAN (set to "1" to enable auto-ban behavior — not recommended until tested)
"""

import os, asyncio, time, json, hmac, hashlib, tempfile
import aiosqlite
import discord
from discord.ext import commands, tasks
from aiohttp import web
import db
import detection
import aiohttp

# -----------------------
# Configuration
# -----------------------
TOKEN = os.getenv('DISCORD_BOT_TOKEN')
if not TOKEN:
    raise RuntimeError("Please set DISCORD_BOT_TOKEN env var.")

GUILD_ID = int(os.getenv('GUILD_ID', '1416287601677176916'))
VERIFY_ROLE_ID = int(os.getenv('VERIFY_ROLE_ID', '1416287654089068544'))
QUARANTINE_ROLE_ID = int(os.getenv('QUARANTINE_ROLE_ID', '1416287684514676786'))
MOD_LOG_CHANNEL_ID = int(os.getenv('MOD_LOG_CHANNEL_ID', '1416287627128078439'))

VERIFY_BASE = os.getenv('VERIFY_BASE', 'http://localhost:5000')
VERIFY_SECRET = os.getenv('VERIFY_SECRET', 'please_set_verify_secret')   # must match web.py
ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'please_set_admin_secret')

QUARANTINE_THRESHOLD = int(os.getenv('QUARANTINE_THRESHOLD', '60'))
QUARANTINE_HOURS = int(os.getenv('QUARANTINE_HOURS', '24'))
AUTO_BAN = os.getenv('AUTO_BAN', '0') == '1'

# -----------------------
# Bot setup
# -----------------------
intents = discord.Intents.default()
intents.members = True
intents.message_content = False
bot = commands.Bot(command_prefix='!', intents=intents)

recent_joins = []
surge_mode = False

# Helper: send to mod log
async def mod_log(text):
    ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
    if ch:
        try:
            await ch.send(text)
        except Exception as e:
            print("mod_log send failed:", e)
    else:
        print("mod_log channel not available; fallback:", text)

# -----------------------
# Internal aiohttp server (bot side)
# -----------------------
async def handle_verify_request(request):
    """
    Expect:
      - JSON body: {"token": "<token>"}
      - Header: X-Signature: hex(hmac_sha256(VERIFY_SECRET, token))
    """
    try:
        body = await request.json()
        token = body.get('token')
        sig = request.headers.get('X-Signature', '')
        if not token:
            return web.json_response({'ok': False, 'error': 'no token'}, status=400)
        expected = hmac.new(VERIFY_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            return web.json_response({'ok': False, 'error': 'invalid signature'}, status=403)
        # schedule processing
        asyncio.create_task(process_verification_token(token))
        return web.json_response({'ok': True})
    except Exception as e:
        print("handle_verify_request error:", e)
        return web.json_response({'ok': False, 'error': str(e)}, status=500)

async def start_internal_server():
    app = web.Application()
    app.router.add_post('/verify', handle_verify_request)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 5001)
    await site.start()
    print("Internal bot webhook listening on http://127.0.0.1:5001/verify")

# -----------------------
# Core verification processor
# -----------------------
async def process_verification_token(token: str):
    """Fetch DB rows, compute ip_info/detection and apply roles."""
    try:
        # fetch verification record
        v = await db.get_verification(token)
        if not v:
            print("Token not found:", token)
            return
        _, discord_id_str, _, status, used, created_at, expires_at = v
        now_ts = int(time.time())
        if expires_at and now_ts > expires_at:
            print("Token expired:", token)
            await db.add_action(discord_id_str, 'token_expired', token)
            return
        if used:
            print("Token already used:", token)
            await db.add_action(discord_id_str, 'token_reuse', token)
            return

        # fetch fingerprints for token
        fp_rows_raw = await db.fetch_fingerprints_by_token(token)  # list of tuples
        fp_rows = []
        for r in fp_rows_raw:
            # r: (id, token, fp_json, ip, asn, ua, honeypot, created_at)
            fp_json = r[2]
            try:
                parsed = json.loads(fp_json) if fp_json else {}
            except Exception:
                parsed = {}
            dna = parsed.get('dna', {})
            ip_info_stored = parsed.get('ip_info', {}) if isinstance(parsed, dict) else {}
            fp_obj = {
                'fp': parsed.get('fp') or parsed,
                'ip': r[3],
                'asn': r[4] or ip_info_stored.get('asn'),
                'ua': r[5],
                'honeypot': bool(r[6]),
                'dna': dna,
                'ip_info': ip_info_stored
            }
            fp_rows.append(fp_obj)

        # compute db_stats (counts of same IP / same FP / previous bans)
        same_ip_count = 0
        same_fp_count = 0
        previous_bans = 0
        if fp_rows:
            # use the first fingerprint as the "current"
            cur_fp = fp_rows[0]
            ip_val = cur_fp.get('ip')
            fp_val = json.dumps(cur_fp.get('fp')) if isinstance(cur_fp.get('fp'), (dict, list)) else str(cur_fp.get('fp'))
            async with aiosqlite.connect('aegisx_s.db') as conn:
                if ip_val:
                    cur = await conn.execute('SELECT COUNT(DISTINCT token) FROM fingerprints WHERE ip = ? AND token != ?', (ip_val, token))
                    r = await cur.fetchone()
                    same_ip_count = int(r[0]) if r and r[0] else 0
                if fp_val:
                    cur = await conn.execute('SELECT COUNT(DISTINCT token) FROM fingerprints WHERE fp = ? AND token != ?', (fp_val, token))
                    r = await cur.fetchone()
                    same_fp_count = int(r[0]) if r and r[0] else 0
                # previous bans heuristic: count actions where action contains 'ban'
                if ip_val or fp_val:
                    # crude previous ban search in actions.reason (demo-level)
                    cur = await conn.execute("SELECT COUNT(*) FROM actions WHERE action = 'ban' AND (reason LIKE ? OR reason LIKE ?)", (f'%{ip_val}%', f'%{fp_val}%'))
                    r = await cur.fetchone()
                    previous_bans = int(r[0]) if r and r[0] else 0

        db_stats = {'same_ip_count': same_ip_count, 'same_fp_count': same_fp_count, 'previously_banned_count': previous_bans}

        # known dna profiles
        known_profiles = await db.fetch_all_dna_profiles()

        # ip_info: try to take from fp_rows first (stored ip_info), otherwise basic empty
        ip_info = {}
        if fp_rows and fp_rows[0].get('ip_info'):
            ip_info = fp_rows[0].get('ip_info') or {}
        else:
            ip_info = {'is_datacenter': False, 'is_vpn': False, 'is_tor': False, 'proxy_score': 0, 'asn': None}

        honeypot_triggered = any(r.get('honeypot') for r in fp_rows)

        # find member
        guild = bot.get_guild(GUILD_ID)
        if not guild:
            print("Guild not available on bot.")
            return
        member = guild.get_member(int(discord_id_str))
        account_age_days = 9999
        if member:
            account_age_days = max(0, (discord.utils.utcnow() - member.created_at).days)

        # compute risk via detection
        risk = detection.compute_risk(fp_rows, known_profiles, ip_info, honeypot_triggered, account_age_days, social_scores=None, db_stats=db_stats)
        score = int(risk.get('risk_score', 0))
        reasons = risk.get('reasons', [])

        # mark token used (prevent replay) BEFORE role ops
        await db.mark_token_used(token)

        # apply decisions
        vrole = guild.get_role(VERIFY_ROLE_ID)
        qrole = guild.get_role(QUARANTINE_ROLE_ID)

        if not member:
            await db.add_action(discord_id_str, 'verify_no_member', f"token={token};score={score}")
            await mod_log(f"Verification submitted for <@{discord_id_str}> but member not found in guild.")
            return

        if score >= QUARANTINE_THRESHOLD:
            # quarantine (timebomb)
            try:
                if qrole:
                    await member.add_roles(qrole, reason=f"Auto-quarantine score={score}")
                until_ts = int(time.time()) + QUARANTINE_HOURS * 3600
                await db.quarantine_member(str(member.id), until_ts)
                await db.add_action(str(member.id), 'quarantine_auto', f"score={score};reasons={reasons}")
                await mod_log(f"👮 {member.mention} automatically quarantined (score={score}). Reasons: {reasons}")
                # optionally auto-ban on extremely high score if enabled
                if AUTO_BAN and score >= 95:
                    try:
                        await member.ban(reason=f"Auto-ban (score {score})")
                        await db.add_action(str(member.id), 'ban', f"auto-ban score={score}")
                        await mod_log(f"🔨 {member.mention} auto-banned (score {score}).")
                    except Exception as e:
                        print("Auto-ban failed:", e)
            except Exception as e:
                print("Quarantine application failed:", e)
        else:
            # assign verified
            try:
                if vrole:
                    await member.add_roles(vrole, reason=f"Verified score={score}")
                await db.set_verification_status(token, 'verified')
                await db.add_action(str(member.id), 'verified', f"score={score};reasons={reasons}")
                await mod_log(f"✅ {member.mention} verified (score={score}).")
                # store dna profile if not exists
                exists = False
                for p in known_profiles:
                    if p.get('discord_id') == str(member.id):
                        exists = True
                        break
                if not exists and fp_rows and fp_rows[0].get('dna'):
                    typing_profile = fp_rows[0]['dna'].get('typing', [])
                    mouse_profile = fp_rows[0]['dna'].get('mouse', [])
                    await db.save_dna_profile(str(member.id), typing_profile, mouse_profile)
            except Exception as e:
                print("Verification role assignment failed:", e)
    except Exception as ex:
        print("process_verification_token exception:", ex)

# -----------------------
# Bot events and tasks
# -----------------------
@bot.event
async def on_ready():
    print("Bot connected:", bot.user)
    await db.init_db()
    surge_check.start()
    quarantine_check.start()
    # start internal webhook server
    asyncio.create_task(start_internal_server())

@tasks.loop(seconds=10)
async def surge_check():
    global surge_mode
    now = time.time()
    window = 30
    while recent_joins and recent_joins[0] < now - window:
        recent_joins.pop(0)
    if len(recent_joins) >= 3 and not surge_mode:
        surge_mode = True
        await mod_log('⚠️ Surge detected: multiple joins. Entering Surge Mode.')
    elif len(recent_joins) == 0 and surge_mode:
        surge_mode = False
        await mod_log('✅ Surge ended.')

@tasks.loop(seconds=60)
async def quarantine_check():
    rows = await db.get_quarantined()
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
                        await member.remove_roles(qrole, reason='Quarantine expired.')
                    except:
                        pass
            await db.add_action(discord_id, 'quarantine_expired', 'Auto-unquarantine after expiration.')

@bot.event
async def on_member_join(member: discord.Member):
    if member.guild.id != GUILD_ID:
        return
    recent_joins.append(time.time())
    token = secrets.token_urlsafe(18)
    await db.create_verification(token, str(member.id), expires_seconds=600)
    link = VERIFY_BASE.rstrip('/') + f"/start/{token}"
    ch = bot.get_channel(MOD_LOG_CHANNEL_ID)
    if ch:
        try:
            msg = await ch.send(f"{member.mention}, welcome — verify here: {link}")
            # delete after 60s for privacy (best-effort)
            try:
                await msg.delete(delay=60)
            except Exception:
                pass
        except Exception as e:
            print("Failed to post verification link:", e)
    else:
        print("mod-log channel not found.")

# -----------------------
# Admin/export commands
# -----------------------
@bot.command()
@commands.has_permissions(administrator=True)
async def export_verifications(ctx):
    """Fetch CSV from local web admin endpoint and DM to caller (admin only)."""
    admin_secret = ADMIN_SECRET
    export_url = VERIFY_BASE.rstrip('/') + '/admin/export'
    params = {'secret': admin_secret}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(export_url, params=params, timeout=20) as resp:
                if resp.status != 200:
                    return await ctx.send("Failed to fetch export (status %s)." % resp.status)
                text = await resp.text()
        # send as file
        with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.csv') as tf:
            tf.write(text)
            tf.flush()
            await ctx.author.send(file=discord.File(tf.name, filename='verifications.csv'))
        await ctx.send("CSV exported and sent to your DMs.")
    except Exception as e:
        await ctx.send(f"Export failed: {e}")

# keep scan & verifynow helpers (previously present)
@bot.command()
@commands.has_permissions(manage_guild=True)
async def verifynow(ctx, member: discord.Member):
    token = secrets.token_urlsafe(18)
    await db.create_verification(token, str(member.id), expires_seconds=600)
    link = VERIFY_BASE.rstrip('/') + f"/start/{token}"
    await mod_log(f"{member.mention}, please verify here: {link}")
    await ctx.send("Verification link posted to mod-log channel.")

@bot.command()
@commands.has_permissions(manage_guild=True)
async def scan(ctx, member: discord.Member):
    async with aiosqlite.connect('aegisx_s.db') as conn:
        cur = await conn.execute(
            'SELECT v.discord_id, f.fp, f.ip, f.asn, f.ua, f.honeypot '
            'FROM verifications v LEFT JOIN fingerprints f ON v.token=f.token '
            'WHERE v.discord_id = ? ORDER BY f.created_at DESC LIMIT 1',
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

# -----------------------
# Run
# -----------------------
bot.run(TOKEN)
