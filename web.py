# web.py
"""
AegisX-S verification web server (Double-Counter style).
Saves fingerprint + dna -> notifies bot internal endpoint via HMAC-signed POST.

Env vars required:
- VERIFY_SECRET (same as bot)
- VERIFY_BASE (public URL used for links, set on Render)
Optional:
- IPQS_KEY (ipqualityscore API key)
- IPINFO_TOKEN (ipinfo.io token)
- BOT_INTERNAL_VERIFY (defaults to http://127.0.0.1:5001/verify)
- ADMIN_SECRET (for /admin/export)
- RATE_WINDOW_SECONDS, RATE_LIMIT_PER_WINDOW
"""
import aiosqlite
from flask import Flask, request, render_template, jsonify
import asyncio, os, json, time, hmac, hashlib
import aiohttp
from db import init_db, save_fingerprint, get_verification
from collections import deque, defaultdict

app = Flask(__name__)
asyncio.get_event_loop().run_until_complete(init_db())

# config
BOT_INTERNAL_VERIFY = os.getenv('BOT_INTERNAL_VERIFY', 'http://127.0.0.1:5001/verify')
VERIFY_SECRET = os.getenv('VERIFY_SECRET', 'please_set_verify_secret')
ADMIN_SECRET = os.getenv('ADMIN_SECRET', 'please_set_admin_secret')
IPQS_KEY = os.getenv('IPQS_KEY')     # optional
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')  # optional

RATE_WINDOW = int(os.getenv('RATE_WINDOW_SECONDS', '10'))
RATE_LIMIT = int(os.getenv('RATE_LIMIT_PER_WINDOW', '3'))

_ip_store = defaultdict(lambda: deque(maxlen=200))

# helper: IP intelligence using IPQS (recommended) else IPINFO fallback
import aiohttp
DATACENTER_KEYWORDS = ['aws', 'amazon', 'google', 'gcp', 'ovh', 'digitalocean', 'linode', 'hetzner', 'microsoft', 'azure']

async def lookup_ip_info(ip):
    res = {'is_datacenter': False, 'is_vpn': False, 'is_tor': False, 'proxy_score': 0, 'asn': None}
    try:
        if IPQS_KEY:
            url = f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=6) as r:
                    if r.status == 200:
                        j = await r.json()
                        res['is_vpn'] = bool(j.get('vpn') or j.get('proxy'))
                        res['is_tor'] = bool(j.get('tor'))
                        res['proxy_score'] = int(j.get('proxy_score') or 0)
                        res['asn'] = (j.get('asn') or j.get('organization') or None)
                        if j.get('hosting') or j.get('hosting_provider') or j.get('organization'):
                            low = str(j.get('organization') or '').lower()
                            if any(k in low for k in DATACENTER_KEYWORDS) or j.get('hosting'):
                                res['is_datacenter'] = True
                        return res
        if IPINFO_TOKEN:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=4) as r:
                    if r.status == 200:
                        j = await r.json()
                        org = j.get('org') or ''
                        res['asn'] = org
                        low = org.lower()
                        if any(k in low for k in DATACENTER_KEYWORDS):
                            res['is_datacenter'] = True
                        return res
    except Exception as e:
        print("lookup_ip_info error:", e)
    return res

# validate token (exists, not used, not expired)
async def check_token_valid(token):
    v = await get_verification(token)
    if not v:
        return False, 'token not found'
    _, discord_id, _, status, used, created_at, expires_at = v
    ts = int(time.time())
    if used:
        return False, 'token already used'
    if expires_at and ts > expires_at:
        return False, 'token expired'
    return True, ''

@app.route('/start/<token>')
def start(token):
    valid, reason = asyncio.get_event_loop().run_until_complete(check_token_valid(token))
    if not valid:
        return f"<h2>Invalid or expired verification link</h2><p>{reason}</p>", 400
    return render_template('verify.html', token=token)

@app.route('/submit', methods=['POST'])
def submit():
    data = request.json or {}
    token = data.get('token')
    if not token:
        return jsonify({'ok': False, 'error': 'no token provided'}), 400

    ip = request.headers.get('X-Real-IP') or request.remote_addr
    now = time.time()
    dq = _ip_store[ip]
    while dq and dq[0] < now - RATE_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT:
        return jsonify({'ok': False, 'error': 'rate limit exceeded'}), 429
    dq.append(now)

    valid, reason = asyncio.get_event_loop().run_until_complete(check_token_valid(token))
    if not valid:
        return jsonify({'ok': False, 'error': reason}), 400

    fp = data.get('fp', '')
    dna = data.get('dna', {})
    honeypot = bool(data.get('honeypot', False))
    ua = request.headers.get('User-Agent')

    # enrich ip info (async call)
    ip_info = asyncio.get_event_loop().run_until_complete(lookup_ip_info(ip))

    # payload: embed fp + dna + ip_info for bot processing
    payload_fp = json.dumps({'fp': fp, 'dna': dna, 'ip_info': ip_info})
    asyncio.get_event_loop().run_until_complete(save_fingerprint(token, payload_fp, ip, ip_info.get('asn'), ua, int(honeypot)))

    # sign token with HMAC and POST to bot
    sig = hmac.new(VERIFY_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()

    async def notify_bot():
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.post(BOT_INTERNAL_VERIFY, json={'token': token}, headers={'X-Signature': sig}, timeout=6) as resp:
                    txt = await resp.text()
                    print("Bot notify response:", resp.status, txt)
        except Exception as e:
            print("notify_bot exception:", e)

    asyncio.get_event_loop().create_task(notify_bot())

    return jsonify({'ok': True, 'status': 'submitted'}), 200

# Admin CSV export endpoint
import csv
from io import StringIO
@app.route('/admin/export', methods=['GET'])
def admin_export():
    secret = request.args.get('secret') or request.headers.get('X-Admin-Secret')
    if not secret or secret != ADMIN_SECRET:
        return 'Forbidden', 403

    async def fetch_all():
        import aiosqlite
        out = []
        async with aiosqlite.connect('aegisx_s.db') as conn:
            cur = await conn.execute('SELECT v.discord_id, v.token, v.status, v.used, v.created_at, v.expires_at, f.ip, f.asn, f.ua, f.honeypot FROM verifications v LEFT JOIN fingerprints f ON v.token=f.token ORDER BY v.created_at DESC')
            rows = await cur.fetchall()
            return rows
    rows = asyncio.get_event_loop().run_until_complete(fetch_all())
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['discord_id','token','status','used','created_at','expires_at','ip','asn','ua','honeypot'])
    for r in rows:
        cw.writerow(list(r))
    res = si.getvalue()
    return app.response_class(res, mimetype='text/csv', headers={'Content-Disposition':'attachment; filename=verifications.csv'})

@app.route('/status/<token>')
def status(token):
    """
    Return JSON about the verification token:
      { ok: True, discord_id, status, used, action, reason, quarantine_until }
    status is typically: 'pending', 'verified', or the DB status value.
    """
    async def _fetch():
        # use existing get_verification() from db.py
        v = await get_verification(token)
        if not v:
            return None
        # v: (id, discord_id, token, status, used, created_at, expires_at)
        _, discord_id, _, status_val, used, created_at, expires_at = v
        # latest action for that discord_id (if any)
        async with aiosqlite.connect('aegisx_s.db') as conn:
            cur = await conn.execute(
                'SELECT action, reason, created_at FROM actions WHERE discord_id = ? ORDER BY created_at DESC LIMIT 1',
                (str(discord_id),)
            )
            act = await cur.fetchone()
            cur2 = await conn.execute(
                'SELECT until_ts FROM quarantined WHERE discord_id = ? ORDER BY created_at DESC LIMIT 1',
                (str(discord_id),)
            )
            qrow = await cur2.fetchone()
        return {
            'discord_id': str(discord_id),
            'status': status_val or 'pending',
            'used': bool(used),
            'action': act[0] if act else None,
            'reason': act[1] if act and act[1] else None,
            'quarantine_until': int(qrow[0]) if qrow and qrow[0] else None
        }

    res = asyncio.get_event_loop().run_until_complete(_fetch())
    if not res:
        return jsonify({'ok': False, 'error': 'token not found'}), 404
    return jsonify({'ok': True, **res})


@app.route('/')
def index():
    return 'AegisX-S verification server (DoubleCounter-style demo).'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
