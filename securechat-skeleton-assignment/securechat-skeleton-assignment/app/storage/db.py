# app/storage/db.py  (PostgreSQL backend)
import os, hmac
from hashlib import sha256
import psycopg2
from psycopg2 import Binary
from dotenv import load_dotenv

load_dotenv()  # loads .env from repo root

def _conn():
    return _pg_conn()

def _pg_conn():
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD") or os.getenv("DB_PASS", ""),
        dbname=os.getenv("DB_NAME", "securechat"),
    )
    conn.autocommit = True
    return conn

def ensure_schema():
    with _conn() as c, c.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
          email TEXT NOT NULL,
          username TEXT PRIMARY KEY,
          salt BYTEA NOT NULL,
          pwd_hash CHAR(64) NOT NULL
        );
        """)
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email_idx ON users(email);")

def create_user(email: str, username: str, pwd_plain: str) -> bool:
    ensure_schema()
    salt = os.urandom(16)
    h = sha256(salt + pwd_plain.encode()).hexdigest()
    with _conn() as c, c.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s", (username, email))
        if cur.fetchone():
            return False
        cur.execute(
            "INSERT INTO users(email,username,salt,pwd_hash) VALUES(%s,%s,%s,%s)",
            (email, username, Binary(salt), h),
        )
    return True

def auth_user(email: str, pwd_plain: str) -> str | None:
    ensure_schema()
    with _conn() as c, c.cursor() as cur:
        cur.execute("SELECT username, salt, pwd_hash FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        if not row:
            return None
        username, salt, pwd_hash = row
        # psycopg2 returns BYTEA as memoryview; normalize to bytes
        if isinstance(salt, memoryview):
            salt = bytes(salt)
        calc = sha256(salt + pwd_plain.encode()).hexdigest()
        return username if hmac.compare_digest(calc, pwd_hash) else None
