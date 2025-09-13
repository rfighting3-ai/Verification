PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS verifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discord_id TEXT,
  token TEXT UNIQUE,
  status TEXT,
  created_at INTEGER,
  verified_at INTEGER
);

CREATE TABLE IF NOT EXISTS fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT,
  fp TEXT,
  ip TEXT,
  asn TEXT,
  ua TEXT,
  honeypot INTEGER DEFAULT 0,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS dna_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discord_id TEXT,
  typing_profile BLOB,
  mouse_profile BLOB,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discord_id TEXT,
  action TEXT,
  reason TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS honeypots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  element_id TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS quarantined (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discord_id TEXT,
  until_ts INTEGER,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS social_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  discord_id TEXT,
  other_discord_id TEXT,
  weight INTEGER DEFAULT 1,
  created_at INTEGER
);
