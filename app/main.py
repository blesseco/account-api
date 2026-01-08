# -*- coding: utf-8 -*-
# Clean, single-version Account API
# FastAPI + aiosqlite + passlib

import os
import json
from typing import Optional, List

import aiosqlite
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from starlette.requests import Request as StarletteRequest
from datetime import datetime

from passlib.hash import bcrypt
import secrets

# NEW: lightweight signer for admin login tokens
import hmac, hashlib, base64, time

def _rand_secret(length: int = 44) -> str:
    # ~43-44 chars urlsafe
    return secrets.token_urlsafe(32)[:length]

# --- plain-secret helper (ADD THIS) ---
async def _set_secret_plain(conn, key_id: str, secret: str):
    await conn.execute(
        "UPDATE api_keys SET secret_plain=? WHERE key_id=?",
        (secret, key_id),
    )
# --- /plain-secret helper ---

# --- optional encryption for reveal-without-rotate ---
FERNET_AVAILABLE = False
try:
    from cryptography.fernet import Fernet, InvalidToken  # pip install cryptography
    FERNET_AVAILABLE = True
except Exception:
    pass

APP_TITLE = "Account API"
DB_PATH = os.environ.get("DB_PATH", "/opt/account-api/db/accounts.sqlite")
ADMIN_KEYS_ENV = [k.strip() for k in os.environ.get("ADMIN_KEYS", "admin").split(",") if k.strip()]
ADMIN_LOGIN_SECRET = os.environ.get("ADMIN_LOGIN_SECRET", "change_me_please")

app = FastAPI(title=APP_TITLE)

# ---------------------------
# Global JSON error wrapper (so 500 is always JSON, jq won't explode)
# ---------------------------
@app.exception_handler(Exception)
async def on_any_error(request: StarletteRequest, exc: Exception):
    return JSONResponse(status_code=500, content={"ok": False, "error": "internal_error"})

# ---------------------------
# Utilities
# ---------------------------

@asynccontextmanager
async def _db():
    # NOTE: isolation_level=None => AUTOCOMMIT ON
    conn = await aiosqlite.connect(DB_PATH, isolation_level=None)
    try:
        conn.row_factory = aiosqlite.Row
        try:
            await conn.execute("PRAGMA foreign_keys = ON;")
        except Exception:
            pass
        # ensure admin table
        await _ensure_tables(conn)
        yield conn
    finally:
        await conn.close()



async def _cleanup_stale_used(conn):
    await conn.execute("""
        UPDATE accounts
        SET status='wasted',
            used_outcome='wasted'
        WHERE status='used'
          AND used_outcome IS NULL
          AND used_at <= datetime('now','-10 minutes')
    """)


async def _rate_check_fetch(conn, consumer, amount: int = 1):
    key_id = consumer["key_id"]

    rpm_limit = consumer.get("rpm_limit") or 0
    daily_cap = consumer.get("daily_cap") or 0

    # RPM check (last 1 minute)
    if rpm_limit > 0:
        cur = await conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE event = 'fetch_ok'
              AND key_id = ?
              AND ts >= datetime('now','-1 minute')
            """,
            (key_id,),
        )
        rpm_used = (await cur.fetchone())[0]

        if rpm_used + amount > rpm_limit:
            raise HTTPException(
                status_code=429,
                detail=f"rpm_limit_reached ({rpm_used}/{rpm_limit})",
            )

    # Daily cap check
    if daily_cap > 0:
        cur = await conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE event = 'fetch_ok'
              AND key_id = ?
              AND date(ts) = date('now')
            """,
            (key_id,),
        )
        today_used = (await cur.fetchone())[0]

        if today_used + amount > daily_cap:
            raise HTTPException(
                status_code=429,
                detail=f"daily_limit_reached ({today_used}/{daily_cap})",
            )

async def _allowed_owners(conn, consumer_key_id: str):
    """
    Returns ordered list of owner_key_ids this consumer can fetch from.
    Rule:
      - Self owner ALWAYS allowed
      - Other owners only if grant enabled
      - Self comes first (priority)
    """

    owners = []

    # 1️⃣ Self always allowed
    owners.append(consumer_key_id)

    # 2️⃣ Enabled grants (other owners)
    cur = await conn.execute(
        """
        SELECT owner_key_id
        FROM key_grants
        WHERE consumer_key_id = ?
          AND enabled = 1
          AND owner_key_id != ?
        """,
        (consumer_key_id, consumer_key_id),
    )

    rows = await cur.fetchall()
    for r in rows:
        owners.append(r["owner_key_id"])

    # remove duplicates just in case
    return list(dict.fromkeys(owners))

def now_ts() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# NEW: ensure admin_users table (no destructive change)
async def _ensure_tables(conn):
    await conn.execute("""
    CREATE TABLE IF NOT EXISTS admin_users(
        email TEXT PRIMARY KEY,
        pass_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

def _get_fernet():
    """
    Returns Fernet instance if SECRET_MASTER_KEY is configured & cryptography installed; else None.
    """
    if not FERNET_AVAILABLE:
        return None
    key = os.environ.get("SECRET_MASTER_KEY", "").strip()
    if not key:
        return None
    try:
        return Fernet(key.encode() if not key.startswith("gAAAA") else key)
    except Exception:
        return None

def _enc_secret(plain: str) -> Optional[str]:
    f = _get_fernet()
    if not f:
        return None
    try:
        token = f.encrypt(plain.encode("utf-8"))
        return token.decode("utf-8")
    except Exception:
        return None

def _dec_secret(token: str) -> Optional[str]:
    f = _get_fernet()
    if not f:
        return None
    try:
        return f.decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return None

# ===== BEGIN PATCH: admin login token helpers =====
def _sign(msg: str) -> str:
    sig = hmac.new(ADMIN_LOGIN_SECRET.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")

def mint_admin_token(email: str, ttl_seconds: int = 86400) -> str:
    exp = int(time.time()) + ttl_seconds
    payload = f"{email}.{exp}"
    return f"adminlogin.{payload}.{_sign(payload)}"

def verify_admin_token(token: str) -> Optional[str]:
    if not token or not token.startswith("adminlogin."):
        return None

    try:
        body = token[len("adminlogin."):]
        payload, sig = body.rsplit(".", 1)
        email, exp = payload.rsplit(".", 1)
    except Exception:
        return None

    if _sign(payload) != sig:
        return None

    if int(exp) < int(time.time()):
        return None

    return email

# ===== END PATCH =====

# ===== BEGIN PATCH: key verification =====
async def verify_key(conn: aiosqlite.Connection, x_api_key: str) -> dict:
    """
    Parse 'key.secret', row load (incl. secret_plain), verify (plain first, else bcrypt),
    check active. Return row as dict for downstream use.
    """
    if not x_api_key or "." not in x_api_key:
        raise HTTPException(status_code=401, detail="bad_key")

    kid, secret = x_api_key.split(".", 1)

    cur = await conn.execute(
        """
        SELECT
            key_id, label, key_hash, secret_plain, active,
            can_upload, can_consume, rpm_limit, daily_cap, created_at
        FROM api_keys
        WHERE key_id=?
        """,
        (kid,),
    )
    row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="bad_key")

    # Plain-first verification (falls back to bcrypt if plain is empty)
    sp = (row["secret_plain"] or "").strip()
    kh = (row["key_hash"] or "") if row["key_hash"] else ""

    if sp:
        ok = (secret == sp)
    elif kh:
        try:
            ok = bcrypt.verify(secret, kh)
        except Exception:
            ok = False
    else:
        ok = False

    if not ok:
        raise HTTPException(status_code=401, detail="bad_secret")

    if not row["active"]:
        raise HTTPException(status_code=403, detail="key_inactive")

    return {
        "key_id": row["key_id"],
        "label": row["label"],
        "key_hash": row["key_hash"],
        "secret_plain": row["secret_plain"],
        "active": row["active"],
        "can_upload": row["can_upload"],
        "can_consume": row["can_consume"],
        "rpm_limit": row["rpm_limit"],
        "daily_cap": row["daily_cap"],
        "created_at": row["created_at"],
    }
# ===== END PATCH =====

# ===== BEGIN PATCH: admin guard =====
async def _require_admin(conn: aiosqlite.Connection, x_api_key: str) -> dict:
    # accept admin login token
    who = verify_admin_token(x_api_key or "")
    if who:
        return {"key_id": f"admin:{who}", "label": "admin", "active": 1,
                "can_upload": 1, "can_consume": 1, "rpm_limit": 0, "daily_cap": 0,
                "created_at": now_ts()}
    # else accept env-listed admin keys
    me = await verify_key(conn, x_api_key)
    if me["key_id"] not in ADMIN_KEYS_ENV:
        raise HTTPException(status_code=403, detail="bad_admin_key")
    return me
# ===== END PATCH =====

async def _log_event(
    conn,
    actor_key_id: str,
    event: str,
    meta: dict,
    account_id: int | None = None,
    ip: str | None = None,
    ua: str | None = None,
):
    await conn.execute(
        """
        INSERT INTO events (ts, event, key_id, account_id, ip, ua, meta_json)
        VALUES (?,?,?,?,?,?,?)
        """,
        (
            now_ts(),
            event,
            actor_key_id,
            account_id,
            ip,
            ua,
            json.dumps(meta, ensure_ascii=False),
        ),
    )

# ---------------------------
# Health + Admin UI
# ---------------------------

@app.get("/healthz", response_class=JSONResponse)
async def healthz():
    return {"ok": True}

@app.get("/admin", response_class=HTMLResponse)
async def admin_ui():
    # Always serve file; hard no-cache
    path = "/opt/account-api/app/admin.html"
    headers = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
    if not os.path.exists(path):
        return HTMLResponse("<h1>Admin UI missing</h1>", status_code=404, headers=headers)
    return FileResponse(path, media_type="text/html; charset=utf-8", headers=headers)

# ---------------------------
# Admin login (email+password -> admin token)
# ---------------------------
@app.post("/v1/admin/login", response_class=JSONResponse)
async def v1_admin_login(request: Request):
    data = await request.json()
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "")
    if not email or not password:
        raise HTTPException(400, "need_email_password")
    async with _db() as conn:
        cur = await conn.execute("SELECT pass_hash FROM admin_users WHERE email=?", (email,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(401, "no_such_admin")
        if not bcrypt.verify(password, row["pass_hash"]):
            raise HTTPException(401, "bad_password")
    return {"ok": True, "admin_token": mint_admin_token(email)}

# ---------------------------
# Keys: me
# ---------------------------

@app.get("/v1/keys/me", response_class=JSONResponse)
async def v1_keys_me(X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        me = await verify_key(conn, X_API_KEY)
        return {
            "key_id": me["key_id"],
            "label": me["label"],
            "active": me["active"],
            "can_upload": me["can_upload"],
            "can_consume": me["can_consume"],
            "rpm_limit": me["rpm_limit"],
            "daily_cap": me["daily_cap"],
            "usage": {"rpm_current": 0, "today_fetches": 0},
        }

# ---------------------------
# Admin: Keys
# ---------------------------

@app.get("/v1/admin/list_keys", response_class=JSONResponse)
async def admin_list_keys(X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        _ = await _require_admin(conn, X_API_KEY)
        cur = await conn.execute("""
            SELECT key_id,label,active,can_upload,can_consume,daily_cap,rpm_limit,created_at
            FROM api_keys ORDER BY created_at ASC
        """)
        rows = [dict(r) for r in await cur.fetchall()]
        return {"keys": rows}

@app.post("/v1/admin/create_key")
async def v1_admin_create_key(request: Request, x_api_key: str = Header(...)):
    data = await request.json()
    key_id = (data.get("key_id") or "").strip()
    label = (data.get("label") or "").strip()
    if not key_id:
        raise HTTPException(status_code=400, detail="key_id_required")

    import secrets
    async with _db() as conn:
        # ✅ admin check yahin karo (conn + x_api_key)
        await _require_admin(conn, x_api_key)

        # exists?
        cur = await conn.execute(
            "SELECT secret_plain FROM api_keys WHERE key_id=?", (key_id,)
        )
        row = await cur.fetchone()

        if row:
            existing_secret = (row["secret_plain"] or "").strip()
            if existing_secret:
                return {"ok": True, "key_id": key_id, "api_key": f"{key_id}.{existing_secret}"}
            # empty tha → generate + update
            secret = secrets.token_urlsafe(32)
            api_key = f"{key_id}.{secret}"
            key_hash = bcrypt.hash(api_key)
            await conn.execute(
                "UPDATE api_keys SET key_hash=?, label=COALESCE(NULLIF(?,''),label), secret_plain=? WHERE key_id=?",
                (key_hash, label, secret, key_id),
            )
            return {"ok": True, "key_id": key_id, "api_key": api_key}

        # naya row
        secret = secrets.token_urlsafe(32)
        api_key = f"{key_id}.{secret}"
        key_hash = bcrypt.hash(api_key)
        await conn.execute(
            """
            INSERT INTO api_keys
              (key_id, key_hash, label, can_upload, can_consume, active, daily_cap, rpm_limit, secret_plain)
            VALUES
              (?, ?, ?, 1, 1, 1, 5000, 60, ?)
            """,
            (key_id, key_hash, label, secret),
        )
        return {"ok": True, "key_id": key_id, "api_key": api_key}
@app.post("/v1/admin/update_key", response_class=JSONResponse)
async def admin_update_key(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        admin = await _require_admin(conn, X_API_KEY)
        k = payload.get("key_id")
        if not k:
            raise HTTPException(400, "missing_key_id")

        fields = []
        params = []
        for name in ["label", "active", "can_upload", "can_consume", "rpm_limit", "daily_cap"]:
            if name in payload:
                val = payload[name]
                if name in ("active", "can_upload", "can_consume") and isinstance(val, (bool, int)):
                    val = int(val)
                fields.append(f"{name}=?")
                params.append(val)
        if not fields:
            return {"ok": True, "updated": 0}

        params.append(k)
        sql = f"UPDATE api_keys SET {', '.join(fields)} WHERE key_id=?"
        await conn.execute(sql, tuple(params))
        await _log_event(conn, admin["key_id"], "update_key", {"key_id": k, "fields": fields})
        return {"ok": True}

@app.post("/v1/admin/regen_secret")
async def v1_admin_regen_secret(
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    data = await request.json()
    key_id = (data.get("key_id") or "").strip()
    if not key_id:
        raise HTTPException(status_code=400, detail="missing_key_id")

    import secrets
    # generate new secret and full api_key
    secret = secrets.token_urlsafe(32).replace("-", "").replace("_", "")
    api_key = f"{key_id}.{secret}"
    key_hash = bcrypt.hash(api_key)

    async with _db() as conn:
        # IMPORTANT: pass conn into _require_admin
        admin = await _require_admin(conn, x_api_key)

        cur = await conn.execute(
            "UPDATE api_keys SET key_hash=?, secret_plain=? WHERE key_id=?",
            (key_hash, secret, key_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="unknown_key")

        await _log_event(conn, admin["key_id"], "regen_secret", {"key_id": key_id})

    return {"ok": True, "api_key": api_key}

@app.post("/v1/admin/delete_key", response_class=JSONResponse)
async def admin_delete_key(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        admin = await _require_admin(conn, X_API_KEY)
        k = payload.get("key_id")
        if not k:
            raise HTTPException(400, "missing_key_id")
        await conn.execute("DELETE FROM key_grants WHERE consumer_key_id=? OR owner_key_id=?", (k, k))
        await conn.execute("DELETE FROM api_keys WHERE key_id=?", (k,))
        await _log_event(conn, admin["key_id"], "delete_key", {"key_id": k})
        return {"ok": True, "deleted_key_id": k}

@app.post("/v1/admin/show_secret", response_class=JSONResponse)
async def admin_show_secret(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        # only admins
        await _require_admin(conn, X_API_KEY)

        k = payload.get("key_id")
        if not k:
            raise HTTPException(status_code=400, detail="missing_key_id")

        cur = await conn.execute(
            "SELECT secret_plain, secret_enc FROM api_keys WHERE key_id=?",
            (k,),
        )
        row = await cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="unknown_key")

        # 1) prefer plain text
        if row["secret_plain"]:
            secret = row["secret_plain"]
        else:
            # 2) optional fallback: try decrypt old encrypted value
            secret = None
            enc = row["secret_enc"]
            if enc:
                try:
                    f = _get_fernet()
                    if f:
                        secret = f.decrypt(enc.encode()).decode()
                        # backfill plain for next time
                        await conn.execute(
                            "UPDATE api_keys SET secret_plain=? WHERE key_id=?",
                            (secret, k),
                        )
                except Exception:
                    pass

            if not secret:
                raise HTTPException(status_code=400, detail="no_secret_stored")

        return {"ok": True, "key_id": k, "secret": secret, "api_key": f"{k}.{secret}"}

@app.get("/v1/admin/list_grants", response_class=JSONResponse)
async def admin_list_grants(X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        _ = await _require_admin(conn, X_API_KEY)
        cur = await conn.execute("""
            SELECT consumer_key_id, owner_key_id, enabled, created_at
            FROM key_grants ORDER BY created_at ASC
        """)
        rows = [dict(r) for r in await cur.fetchall()]
        return {"grants": rows}

@app.post("/v1/admin/grant", response_class=JSONResponse)
async def admin_grant(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        admin = await _require_admin(conn, X_API_KEY)
        consumer = payload.get("consumer_key_id")
        owner = payload.get("owner_key_id")
        enabled = int(payload.get("enabled", 1))
        if not consumer or not owner or consumer == owner:
            raise HTTPException(400, "bad_grant")
        await conn.execute("""
            INSERT INTO key_grants(consumer_key_id, owner_key_id, enabled, created_at)
            VALUES (?,?,?,?)
            ON CONFLICT(consumer_key_id, owner_key_id) DO UPDATE SET enabled=excluded.enabled
        """, (consumer, owner, enabled, now_ts()))
        await _log_event(conn, admin["key_id"], "grant", {"consumer": consumer, "owner": owner, "enabled": enabled})
        return {"ok": True}

@app.post("/v1/admin/revoke", response_class=JSONResponse)
async def admin_revoke(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with _db() as conn:
        admin = await _require_admin(conn, X_API_KEY)
        consumer = payload.get("consumer_key_id")
        owner = payload.get("owner_key_id")
        if not consumer or not owner:
            raise HTTPException(400, "bad_revoke")
        await conn.execute("DELETE FROM key_grants WHERE consumer_key_id=? AND owner_key_id=?", (consumer, owner))
        await _log_event(conn, admin["key_id"], "revoke", {"consumer": consumer, "owner": owner})
        return {"ok": True}

# ---------------------------
# Upload
# ---------------------------

# ---------------------------
# Upload
# ---------------------------

@app.post("/v1/upload", response_class=JSONResponse)
async def v1_upload(
    request: Request,
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    """
    Body: text/plain
    Format per line:
      email|password|recovery_token|cookie|owner_key_id

    owner_key_id optional -> defaults to current key_id
    """

    text = (await request.body()).decode("utf-8", errors="ignore")

    async with _db() as conn:
        me = await verify_key(conn, X_API_KEY)
        if not me["can_upload"]:
            raise HTTPException(status_code=403, detail="upload_not_allowed")

        inserted = 0
        dup = 0

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split("|")
            if len(parts) < 2:
                continue

            # normalize email + extract domain
            e = parts[0].strip().lower()
            if "@" not in e:
                continue
            domain = e.split("@", 1)[1]

            p = parts[1].strip() if len(parts) > 1 else ""
            rt = parts[2].strip() if len(parts) > 2 else ""
            cid = parts[3].strip() if len(parts) > 3 else ""
            owner = (
                parts[4].strip()
                if len(parts) > 4 and parts[4].strip()
                else me["key_id"]
            )

            # duplicate check (same email + same owner)
            cur = await conn.execute(
                "SELECT id FROM accounts WHERE e=? AND owner=?",
                (e, owner),
            )
            if await cur.fetchone():
                dup += 1
                continue

            await conn.execute(
                """
                INSERT INTO accounts (
                    e, p, rt, cid, owner, domain,
                    status, used_by, used_outcome,
                    created_at, used_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?,
                    'unused', NULL, NULL,
                    ?, NULL
                )
                """,
                (e, p, rt, cid, owner, domain, now_ts()),
            )

            inserted += 1

        await _log_event(
            conn,
            me["key_id"],
            "upload",
            {"inserted": inserted, "dup": dup},
        )

        return {
            "ok": True,
            "inserted": inserted,
            "duplicate": dup,
        }

# ---------------------------
# Fetch (GET batched) + Mark
# ---------------------------

@app.get("/v1/fetch", response_class=JSONResponse)
async def v1_fetch(
    quantity: int = Query(1, ge=1, le=100),
    domain: str = Query("all"),
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    domain = (domain or "all").lower()
    if domain not in {"hotmail.com", "outlook.com", "all"}:
        raise HTTPException(status_code=400, detail="invalid_domain")

    async with _db() as conn:
        await _cleanup_stale_used(conn)
        # 1️⃣ Key validation
        consumer = await verify_key(conn, X_API_KEY)
        if not consumer["can_consume"]:
            raise HTTPException(status_code=403, detail="consume_not_allowed")

        key_id = consumer["key_id"]

        # 2️⃣ Resolve allowed owners (SELF FIRST)
        owners = [key_id]

        cur = await conn.execute(
            """
            SELECT owner_key_id
            FROM key_grants
            WHERE consumer_key_id = ?
              AND enabled = 1
              AND owner_key_id != ?
            """,
            (key_id, key_id),
        )
        owners.extend([r[0] for r in await cur.fetchall()])

        # safety: remove duplicates, keep order
        owners = list(dict.fromkeys(owners))

        # 3️⃣ Select unused accounts (self first)
        placeholders = ",".join("?" * len(owners))
        sql = f"""
            SELECT id, e, p, rt, cid, owner
            FROM accounts
            WHERE status = 'unused'
              AND owner IN ({placeholders})
        """
        params = list(owners)

        if domain != "all":
            sql += " AND LOWER(e) LIKE ?"
            params.append(f"%@{domain}")

        sql += """
            ORDER BY
              CASE WHEN owner = ? THEN 0 ELSE 1 END,
              created_at ASC
            LIMIT ?
        """
        params.extend([key_id, quantity])

        cur = await conn.execute(sql, tuple(params))
        rows = [dict(r) for r in await cur.fetchall()]

        if not rows:
            return {
                "ok": True,
                "count": 0,
                "data": [],
                "out_of_stock": True,
                "reason": "no_matching_accounts",
                "domain": domain,
            }

        # 4️⃣ LIMIT CHECK (after stock confirmed)
        await _rate_check_fetch(conn, consumer, amount=len(rows))

        # 5️⃣ Mark accounts as used
        ids = [r["id"] for r in rows]
        id_place = ",".join("?" * len(ids))
        await conn.execute(
            f"""
            UPDATE accounts
            SET status='used',
                used_by=?,
                used_outcome=NULL,
                used_at=?
            WHERE id IN ({id_place})
            """,
            (key_id, now_ts(), *ids),
        )

        # 6️⃣ Log fetch event (ONLY fetch_ok)
        await _log_event(
            conn,
            key_id,
            "fetch_ok",
            {
                "count": len(rows),
                "domain": domain,
                "owners": list({r["owner"] for r in rows}),
            },
        )

        # 7️⃣ Clean response
        data = [
            {
                "id": r["id"],
                "e": r["e"],
                "p": r["p"],
                "rt": r["rt"],
                "cid": r["cid"],
                "owner": r["owner"],
            }
            for r in rows
        ]

        return {
            "ok": True,
            "count": len(data),
            "data": data,
            "out_of_stock": False,
            "domain": domain,
        }

@app.get("/v1/mark", response_class=JSONResponse)
async def v1_mark(
    status: str = Query(..., pattern="^(success|code_282|locked)$"),
    id: Optional[int] = Query(None),
    email: Optional[str] = Query(None),
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    async with _db() as conn:
        consumer = await verify_key(conn, X_API_KEY)

        used_outcome = "locked" if status == "locked" else ("reg_success" if status == "success" else "code_282")
        if not id and not email:
            raise HTTPException(400, "need_id_or_email")

        cur = await conn.execute("SELECT id, used_by FROM accounts WHERE " + ("id=?" if id else "e=?"),
                                 ((id if id else email),))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "account_not_found")

        if row["used_by"] and row["used_by"] != consumer["key_id"] and consumer["key_id"] not in ADMIN_KEYS_ENV:
            raise HTTPException(403, "not_your_claim")

        if used_outcome == "locked":
            await conn.execute("UPDATE accounts SET status='locked', used_outcome='locked' WHERE id=?", (row["id"],))
        else:
            await conn.execute(
                "UPDATE accounts SET status='used', used_outcome=?, used_at=COALESCE(used_at, ?) WHERE id=?",
                (used_outcome, now_ts(), row["id"])
            )

        await _log_event(conn, consumer["key_id"], "mark", {"id": row["id"], "status": used_outcome})
        return {"ok": True, "id": row["id"], "status": used_outcome}

# ---------------------------
# Admin: release pending
# ---------------------------

@app.post("/v1/admin/release_pending_older_than", response_class=JSONResponse)
async def v1_release_pending(
    minutes: int = Query(10, ge=1, le=1440),
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    async with _db() as conn:
        admin = await _require_admin(conn, X_API_KEY)
        cur = await conn.execute("""
            SELECT id FROM accounts
            WHERE status='used' AND used_outcome IS NULL AND used_at IS NOT NULL
                  AND (strftime('%s','now') - strftime('%s', used_at)) >= ?
        """, (minutes * 60,))
        ids = [r["id"] for r in await cur.fetchall()]
        released = 0
        if ids:
            id_place = ",".join("?" * len(ids))
            await conn.execute(
                f"UPDATE accounts SET status='unused', used_by=NULL, used_outcome=NULL, used_at=NULL WHERE id IN ({id_place})",
                (*ids,)
            )
            released = len(ids)
        await _log_event(conn, admin["key_id"], "release_pending", {"minutes": minutes, "released": released})
        return {"ok": True, "released": released}

# ---------------------------
# Stats + Owner summary
# ---------------------------

@app.get("/v1/stats", response_class=JSONResponse)
async def v1_stats(
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    owner_keys: Optional[str] = Query(None),
    consumer_keys: Optional[str] = Query(None),
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    async with _db() as conn:
        await _require_admin(conn, X_API_KEY)

        owners = [o.strip() for o in owner_keys.split(",")] if owner_keys else None
        consumers = [c.strip() for c in consumer_keys.split(",")] if consumer_keys else None

        # -----------------------
        # DATE-BASED FILTER (analytics only)
        # -----------------------
        where = []
        params: list = []

        if owners:
            where.append(f"owner IN ({','.join('?' * len(owners))})")
            params.extend(owners)

        if date_from:
            where.append("created_at >= ?")
            params.append(date_from)

        if date_to:
            where.append("created_at <= ?")
            params.append(date_to + " 23:59:59")

        where_clause = f"WHERE {' AND '.join(where)}" if where else ""

        # -----------------------
        # TOTALS (date based, EXCEPT unused)
        # -----------------------
        cur = await conn.execute(f"""
            SELECT
              COUNT(*) as uploaded,
              SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used_total,
              SUM(CASE WHEN status='locked' THEN 1 ELSE 0 END) as locked,
              SUM(CASE WHEN used_outcome='reg_success' THEN 1 ELSE 0 END) as reg_success,
              SUM(CASE WHEN used_outcome='code_282' THEN 1 ELSE 0 END) as code_282,
              SUM(CASE WHEN status='used' AND used_outcome IS NULL THEN 1 ELSE 0 END) as used_pending
            FROM accounts
            {where_clause}
        """, params)
        totals = dict(await cur.fetchone())

        # -----------------------
        # UNUSED (LIVE STOCK, NO DATE FILTER)
        # -----------------------
        cur = await conn.execute("""
            SELECT COUNT(*) as unused
            FROM accounts
            WHERE status='unused'
        """)
        totals["unused"] = (await cur.fetchone())["unused"]

        # -----------------------
        # PER OWNER (date based)
        # -----------------------
        cur = await conn.execute(f"""
            SELECT owner as owner_key_id,
              COUNT(*) as uploaded,
              SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used_total,
              SUM(CASE WHEN status='locked' THEN 1 ELSE 0 END) as locked,
              SUM(CASE WHEN used_outcome='reg_success' THEN 1 ELSE 0 END) as reg_success,
              SUM(CASE WHEN used_outcome='code_282' THEN 1 ELSE 0 END) as code_282,
              SUM(CASE WHEN status='used' AND used_outcome IS NULL THEN 1 ELSE 0 END) as used_pending
            FROM accounts
            {where_clause}
            GROUP BY owner
            ORDER BY owner
        """, params)
        per_owner = [dict(r) for r in await cur.fetchall()]

        # per-owner UNUSED (live)
        cur = await conn.execute("""
            SELECT owner, COUNT(*) as unused
            FROM accounts
            WHERE status='unused'
            GROUP BY owner
        """)
        unused_map = {r["owner"]: r["unused"] for r in await cur.fetchall()}

        for o in per_owner:
            o["unused"] = unused_map.get(o["owner_key_id"], 0)

        # -----------------------
        # PER CONSUMER
        # -----------------------
        where_c = []
        params_c = []

        if consumers:
            where_c.append(f"used_by IN ({','.join('?' * len(consumers))})")
            params_c.extend(consumers)

        if owners:
            where_c.append(f"owner IN ({','.join('?' * len(owners))})")
            params_c.extend(owners)

        where_c_clause = f"WHERE {' AND '.join(where_c)}" if where_c else ""

        cur = await conn.execute(f"""
            SELECT used_by as consumer, COUNT(*) as used_total
            FROM accounts
            {where_c_clause}
            GROUP BY used_by
            HAVING used_by IS NOT NULL
            ORDER BY used_total DESC
        """, params_c)
        per_consumer = [dict(r) for r in await cur.fetchall()]

        return {
            "range": {"from": date_from, "to": date_to},
            "filter": {"owners": owners, "consumer_keys": consumers},
            "totals": totals,
            "per_owner": per_owner,
            "per_consumer": per_consumer,
        }


@app.get("/v1/owner_summary", response_class=JSONResponse)
async def v1_owner_summary(
    date_from: str = Query(...),
    date_to: Optional[str] = Query(None),
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    async with _db() as conn:
        _ = await _require_admin(conn, X_API_KEY)

        # apply date filter here too
        params: List[object] = []
        date_filter = []
        if date_from:
            date_filter.append("created_at >= ?")
            params.append(date_from)
        if date_to:
            date_filter.append("created_at <= ?")
            params.append(date_to + " 23:59:59")
        where_clause = ("WHERE " + " AND ".join(date_filter)) if date_filter else ""

        cur = await conn.execute(f"""
            SELECT owner as owner_key, COUNT(*) as uploaded,
                   SUM(CASE WHEN status='unused' THEN 1 ELSE 0 END) as unused,
                   SUM(CASE WHEN status='used' THEN 1 ELSE 0 END) as used_total,
                   SUM(CASE WHEN status='locked' THEN 1 ELSE 0 END) as locked,
                   SUM(CASE WHEN used_outcome='reg_success' THEN 1 ELSE 0 END) as reg_success,
                   SUM(CASE WHEN used_outcome='code_282' THEN 1 ELSE 0 END) as code_282
            FROM accounts
            {where_clause}
            GROUP BY owner
            ORDER BY owner
        """, tuple(params))
        owners_rows = [dict(r) for r in await cur.fetchall()]
        for o in owners_rows:
            remaining_after_unlock = (o["unused"] or 0) + (o["locked"] or 0)
            o["owner"] = o.pop("owner_key")
            o["remaining_after_unlock"] = remaining_after_unlock
            o["used_breakup"] = {
                "reg_success": o["reg_success"] or 0,
                "code_282": o["code_282"] or 0,
                "other": (o["used_total"] or 0) - ((o["reg_success"] or 0) + (o["code_282"] or 0)),
            }

        cur = await conn.execute(f"""
            SELECT used_by as consumer, owner, COUNT(*) as cnt
            FROM accounts
            {where_clause if where_clause else ""}
            GROUP BY used_by, owner
            HAVING used_by IS NOT NULL
        """, tuple(params))
        by = {}
        for r in await cur.fetchall():
            consumer = r["consumer"]
            owner = r["owner"]
            cnt = r["cnt"]
            if consumer not in by:
                by[consumer] = {"consumer": consumer, "used_total": 0, "by_owner": {}}
            by[consumer]["used_total"] += cnt
            by[consumer]["by_owner"][owner] = cnt

        consumers_rows = list(by.values())
        return {
            "range": {"from": date_from, "to": date_to},
            "owners": owners_rows,
            "consumers": consumers_rows,
        }
