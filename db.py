# db.py
import aiosqlite
import time
import json
from pathlib import Path

DB_PATH = Path('aegisx_s.db')

async def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        sql = open('schema.sql', 'r', encoding='utf-8').read()
        await db.executescript(sql)
        await db.commit()

async def create_verification(token: str, discord_id: str):
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            'INSERT INTO verifications (discord_id, token, status, created_at) VALUES (?, ?, ?, ?)',
            (discord_id, token, 'pending', ts)
        )
        await db.commit()

async def set_verification_status(token: str, status: str):
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            'UPDATE verifications SET status = ?, verified_at = ? WHERE token = ?',
            (status, ts, token)
        )
        await db.commit()

async def save_fingerprint(token: str, fp: str, ip: str, asn: str, ua: str, honeypot: int):
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            'INSERT INTO fingerprints (token, fp, ip, asn, ua, honeypot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (token, fp, ip, asn or '', ua or '', int(bool(honeypot)), ts)
        )
        await db.commit()

async def fetch_fingerprints_by_fp(fp: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute('SELECT * FROM fingerprints WHERE fp = ? ORDER BY created_at DESC', (fp,))
        rows = await cur.fetchall()
        return rows

async def save_dna_profile(discord_id: str, typing_profile, mouse_profile):
    ts = int(time.time())
    typing_json = json.dumps(typing_profile)
    mouse_json = json.dumps(mouse_profile)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            'INSERT INTO dna_profiles (discord_id, typing_profile, mouse_profile, created_at) VALUES (?, ?, ?, ?)',
            (discord_id, typing_json, mouse_json, ts)
        )
        await db.commit()

async def fetch_all_dna_profiles():
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute('SELECT discord_id, typing_profile, mouse_profile FROM dna_profiles')
        rows = await cur.fetchall()
        parsed = []
        for r in rows:
            parsed.append({
                'discord_id': r[0],
                'typing': json.loads(r[1]),
                'mouse': json.loads(r[2])
            })
        return parsed

async def add_action(discord_id: str, action: str, reason: str):
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            'INSERT INTO actions (discord_id, action, reason, created_at) VALUES (?, ?, ?, ?)',
            (discord_id, action, reason, ts)
        )
        await db.commit()

async def quarantine_member(discord_id: str, until_ts: int):
    ts = int(time.time())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            'INSERT INTO quarantined (discord_id, until_ts, created_at) VALUES (?, ?, ?)',
            (discord_id, until_ts, ts)
        )
        await db.commit()

async def get_quarantined():
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute('SELECT discord_id, until_ts FROM quarantined')
        return await cur.fetchall()
