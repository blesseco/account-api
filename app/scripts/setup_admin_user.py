#!/usr/bin/env python3
# one-time helper to create/update an admin user
import os, time, asyncio, aiosqlite
from passlib.hash import bcrypt

DB = os.environ.get("DB_PATH", "/opt/account-api/db/accounts.sqlite")
EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
PASSWORD = os.environ.get("ADMIN_PASSWORD", "Strong!Passw0rd")

async def go():
    conn = await aiosqlite.connect(DB, isolation_level=None)
    try:
        await conn.execute("""CREATE TABLE IF NOT EXISTS admin_users(
            email TEXT PRIMARY KEY,
            pass_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );""")
        ph = bcrypt.hash(PASSWORD)
        await conn.execute("INSERT OR REPLACE INTO admin_users(email,pass_hash,created_at) VALUES (?,?,?)",
                           (EMAIL, ph, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())))
        print("admin user upserted:", EMAIL)
    finally:
        await conn.close()

asyncio.run(go())
