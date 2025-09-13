# db.py
"""
Async SQLite helper for AegisX-S.

Provides:
- init_db()
- create_verification(token, discord_id, expires_seconds=600)
- get_verification(token)
- mark_token_used(token)
- set_verification_status(token, status)
- save_fingerprint(token, fp, ip, asn, ua, honeypot)
- fetch_fingerprints_by_token(token)
- save_dna_profile(discord_id, typing_profile, mouse_profile)
- fetch_all_dna_profiles()
- add_action(discord_id, action, reason)
- quarantine_member(discord_id, until_ts)
- get_quarantined()
"""

import aiosqlite
import time
import json
from pathlib import Path
from typing import Optional, List, Dict, Tuple

DB_PATH = Path("aegisx_s.db")

async def init_db(schema_path: str = "schema.sql"):
    """
    Initialize the SQLite DB using schema.sql. Safe to call multiple times.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        # Read schema file and execute
        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                sql = f.read()
            await db.executescript(sql)
            await db.commit()
        except FileNotFoundError:
            # If no schema file is present, assume DB is already created. Raise for visibility.
            raise

# -----------------------
# Verification lifecycle
# -----------------------
async def create_verification(token: str, discord_id: str, expires_seconds: int = 600):
    """
    Create a new verification row for a discord_id with a token.
    expires_seconds: lifespan of token in seconds (default 10 minutes).
    """
    ts = int(time.time())
    expires = ts + int(expires_seconds) if expires_seconds else None
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO verifications (discord_id, token, status, used, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (discord_id, token, "pending", 0, ts, expires)
        )
        await db.commit()

async def get_verification(token: str) -> Optional[Tuple]:
    """
    Return a single verification row for token:
      (id, discord_id, token, status, used, created_at, expires_at)
    Returns None if not found.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id, discord_id, token, status, used, created_at, expires_at FROM verifications WHERE token = ?",
            (token,)
        )
        r = await cur.fetchone()
        return r

async def mark_token_used(token: str):
    """
    Mark token as used and set verified_at timestamp.
    """
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE verifications SET used = 1, verified_at = ? WHERE token = ?",
            (ts, token)
        )
        await db.commit()

async def set_verification_status(token: str, status: str):
    """
    Update the status field (e.g., 'verified', 'quarantined', 'failed') and set verified_at.
    """
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE verifications SET status = ?, verified_at = ? WHERE token = ?",
            (status, ts, token)
        )
        await db.commit()

# -----------------------
# Fingerprints & DNA
# -----------------------
async def save_fingerprint(token: str, fp: str, ip: str, asn: Optional[str], ua: Optional[str], honeypot: int = 0):
    """
    Save a fingerprint row. 'fp' is typically a JSON string containing device/fp data.
    honeypot: 0 or 1
    """
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO fingerprints (token, fp, ip, asn, ua, honeypot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (token, fp, ip or "", asn or "", ua or "", int(bool(honeypot)), ts)
        )
        await db.commit()

async def fetch_fingerprints_by_token(token: str) -> List[Tuple]:
    """
    Return fingerprint rows for a given token, ordered newest-first.
    Each row is: (id, token, fp, ip, asn, ua, honeypot, created_at)
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id, token, fp, ip, asn, ua, honeypot, created_at FROM fingerprints WHERE token = ? ORDER BY created_at DESC",
            (token,)
        )
        rows = await cur.fetchall()
        return rows

# -----------------------
# DNA profiles (typing/mouse)
# -----------------------
async def save_dna_profile(discord_id: str, typing_profile, mouse_profile):
    """
    Stores DNA profiles (JSON serialised). typing_profile and mouse_profile should be JSON-serializable.
    """
    ts = int(time.time())
    typing_json = json.dumps(typing_profile)
    mouse_json = json.dumps(mouse_profile)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO dna_profiles (discord_id, typing_profile, mouse_profile, created_at) VALUES (?, ?, ?, ?)",
            (discord_id, typing_json, mouse_json, ts)
        )
        await db.commit()

async def fetch_all_dna_profiles() -> List[Dict]:
    """
    Return a list of DNA profile dicts: {'discord_id': str, 'typing': [...], 'mouse': [...]}
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT discord_id, typing_profile, mouse_profile FROM dna_profiles")
        rows = await cur.fetchall()
        out = []
        for r in rows:
            discord_id = r[0]
            try:
                typing = json.loads(r[1]) if r[1] else []
            except Exception:
                typing = []
            try:
                mouse = json.loads(r[2]) if r[2] else []
            except Exception:
                mouse = []
            out.append({'discord_id': discord_id, 'typing': typing, 'mouse': mouse})
        return out

# -----------------------
# Actions & quarantine
# -----------------------
async def add_action(discord_id: str, action: str, reason: str):
    """
    Log an action (verify/quarantine/ban/etc.) for auditing.
    """
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO actions (discord_id, action, reason, created_at) VALUES (?, ?, ?, ?)",
            (discord_id, action, reason or '', ts)
        )
        await db.commit()

async def quarantine_member(discord_id: str, until_ts: int):
    """
    Insert a quarantine row (time-bomb).
    """
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO quarantined (discord_id, until_ts, created_at) VALUES (?, ?, ?)",
            (discord_id, int(until_ts), ts)
        )
        await db.commit()

async def get_quarantined() -> List[Tuple]:
    """
    Return list of (discord_id, until_ts) for quarantined entries.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT discord_id, until_ts FROM quarantined")
        rows = await cur.fetchall()
        return rows

# -----------------------
# Convenience / maintenance helpers (optional)
# -----------------------
async def fetch_latest_action_for(discord_id: str) -> Optional[Tuple]:
    """
    Returns the latest (action, reason, created_at) for a discord_id, or None.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT action, reason, created_at FROM actions WHERE discord_id = ? ORDER BY created_at DESC LIMIT 1",
            (discord_id,)
        )
        r = await cur.fetchone()
        return r

# EOF
