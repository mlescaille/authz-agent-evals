import os
import sqlite3
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def database_path():
    return os.environ.get("APP_DATABASE", os.path.join(os.getcwd(), "app.db"))


def connect(path):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    recovery_email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    merged_into_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    serial TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    owner_account_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_bindings (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    bound_at TEXT NOT NULL,
    released_at TEXT
);

CREATE TABLE IF NOT EXISTS device_shares (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS readings (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    author_account_id INTEGER NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_notes (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL,
    author_account_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL,
    origin_account_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS account_links (
    id INTEGER PRIMARY KEY,
    grantor_account_id INTEGER NOT NULL,
    grantee_account_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS merge_requests (
    id INTEGER PRIMARY KEY,
    survivor_account_id INTEGER NOT NULL,
    source_account_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def init_db(conn):
    conn.executescript(SCHEMA)
    conn.commit()
