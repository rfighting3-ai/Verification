# web.py
"""
AegisX-S Verification Web Server
DoubleCounter-style clone: saves fingerprints, posts to bot with HMAC.
"""

import asyncio, os, time, json, hmac, hashlib, csv
from io import StringIO
from collections import defaultdict, deque
import aiohttp, aiosqlite
from flask import Flask, request, render_template, jsonify

from db import init_db, save_fingerprint, get_verification

app = Flask(__name__)
asyncio.get_event_loop().run_until_complete(init_db())

# ----------------------
# Config
# ----------------------
BOT_INTERNAL_VERIFY = os.getenv("BOT_INTERNAL_VERIFY", "http://127.0.0.1:5001/verify")
VERIFY_SECRET = os.getenv("VERIFY_SECRET", "please_set_verify_secret")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "please_set_admin_secret")

RATE_WINDOW = int(os.getenv("RATE_WINDOW_SECONDS", "10"))
RATE_LIMIT = int(os.getenv("RATE_LIMIT_PER_WINDOW", "3"))
_ip_store = defaultdict(lambda: deque(maxlen=200))

# ----------------------
# IP Intelligence (demo-level)
# ----------------------
DATACENTER_KEYWORDS = ["aws", "amazon", "google", "gcp", "ovh", "digitalocean", "linode", "hetzner", "azure", "microsoft"]

async def lookup_ip_info(ip: str):
    # simple heuristics only
    return {
        "is_datacenter": any(k in ip.lower() for k in DATACENTER_KEYWORDS),
        "is_vpn": False,
        "is_tor": False,
        "proxy_score": 0,
        "asn": "AS-LOCAL"
    }

# ----------------------
# Token validation
# ----------------------
async def check_token_valid(token):
    v = await get_verification(token)
    if not v:
        return False, "token not found"
    _, discord_id, _, status, used, created_at, expires_at = v
    now = int(time.time())
    if used:
        return False, "token already used"
    if expires_at and now > expires_at:
        return False, "token expired"
    return True, ""

# ----------------------
# Routes
# ----------------------
@app.route("/start/<token>")
def start(token):
    valid, reason = asyncio.get_event_loop().run_until_complete(check_token_valid(token))
    if not valid:
        return f"<h2>Invalid or expired verification link</h2><p>{reason}</p>", 400
    return render_template("verify.html", token=token)

@app.route("/submit", methods=["POST"])
def submit():
    data = request.json or {}
    token = data.get("token")
    if not token:
        return jsonify({"ok": False, "error": "no token"}), 400

    ip = request.headers.get("X-Real-IP") or request.remote_addr
    now = time.time()
    dq = _ip_store[ip]
    while dq and dq[0] < now - RATE_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT:
        return jsonify({"ok": False, "error": "rate limit exceeded"}), 429
    dq.append(now)

    valid, reason = asyncio.get_event_loop().run_until_complete(check_token_valid(token))
    if not valid:
        return jsonify({"ok": False, "error": reason}), 400

    ua = request.headers.get("User-Agent")
    fp = data.get("fp", "")
    dna = data.get("dna", {})
    honeypot = bool(data.get("honeypot", False))

    ip_info = asyncio.get_event_loop().run_until_complete(lookup_ip_info(ip))
    payload_fp = json.dumps({"fp": fp, "dna": dna, "ip_info": ip_info})

    asyncio.get_event_loop().run_until_complete(
        save_fingerprint(token, payload_fp, ip, ip_info.get("asn"), ua, int(honeypot))
    )

    sig = hmac.new(VERIFY_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()

    async def notify_bot():
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post(BOT_INTERNAL_VERIFY,
                                  json={"token": token},
                                  headers={"X-Signature": sig},
                                  timeout=6) as r:
                    print("Bot notify:", r.status, await r.text())
        except Exception as e:
            print("notify_bot failed:", e)

    asyncio.get_event_loop().create_task(notify_bot())
    return jsonify({"ok": True, "status": "submitted"}), 200

@app.route("/status/<token>")
def status(token):
    async def fetch():
        v = await get_verification(token)
        if not v:
            return None
        _, discord_id, _, status_val, used, created_at, expires_at = v
        return {
            "discord_id": str(discord_id),
            "status": status_val or "pending",
            "used": bool(used)
        }
    res = asyncio.get_event_loop().run_until_complete(fetch())
    if not res:
        return jsonify({"ok": False, "error": "token not found"}), 404
    return jsonify({"ok": True, **res})

@app.route("/admin/export")
def admin_export():
    secret = request.args.get("secret") or request.headers.get("X-Admin-Secret")
    if secret != ADMIN_SECRET:
        return "Forbidden", 403

    async def fetch_all():
        async with aiosqlite.connect("aegisx_s.db") as conn:
            cur = await conn.execute("SELECT discord_id, token, status, used, created_at, expires_at FROM verifications ORDER BY created_at DESC")
            return await cur.fetchall()
    rows = asyncio.get_event_loop().run_until_complete(fetch_all())
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["discord_id", "token", "status", "used", "created_at", "expires_at"])
    for r in rows:
        cw.writerow(list(r))
    return app.response_class(si.getvalue(), mimetype="text/csv")

@app.route("/")
def index():
    return "AegisX-S Verification server running."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
