# Accounts Admin Pack (minimal)

This pack adds **email/password admin login** (no personal API key stored) and a **fixed admin.html**.

## Files
- `server/main.py` — patched FastAPI app (adds `/v1/admin/login`, accepts admin token).
- `admin/admin.html` — minimal dashboard wired to correct endpoints.
- `scripts/deploy.sh` — upload & restart helper.
- `scripts/setup_admin_user.py` — one-time admin creator.

## Quick deploy
```bash
cd account-admin-pack/scripts
export VPS=root@YOUR_VPS_IP
./deploy.sh
```

## Create admin user
```bash
ssh $VPS "python3 - <<'PY'
import os, time, asyncio, aiosqlite
from passlib.hash import bcrypt
DB='/opt/account-api/db/accounts.sqlite'
EMAIL='admin@yourmail.com'
PASS='Strong!Passw0rd'
async def go():
    conn = await aiosqlite.connect(DB, isolation_level=None)
    try:
        await conn.execute(\"\"\"CREATE TABLE IF NOT EXISTS admin_users(
            email TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );\"\"\" )
        ph = bcrypt.hash(PASS)
        await conn.execute('INSERT OR REPLACE INTO admin_users(email,pass_hash,created_at) VALUES (?,?,?)',
                           (EMAIL, ph, time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())))
        print('admin user upserted:', EMAIL)
    finally:
        await conn.close()
asyncio.run(go())
PY"
```

## Login
Open `https://YOUR_DOMAIN/admin` → **Login** → email/password → admin token stored as `X-API-Key`.  
All admin endpoints continue to work with this token.
