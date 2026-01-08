from fastapi import FastAPI, Header, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, FileResponse
import os, json, time, asyncio, random, string
import aiosqlite
from passlib.hash import bcrypt
from typing import Set, Dict, Any, List, Optional, Tuple
from datetime import datetime

app = FastAPI()

DB_PATH = os.getenv("DB_PATH", "/opt/account-api/db/accounts.sqlite")
ADMIN_KEYS = {k.strip() for k in os.getenv("ADMIN_KEYS", "").split(",") if k.strip()}
TTL_SECS = int(os.getenv("TTL_SECS", "600"))  # auto-release TTL

# ---------- helpers ----------

def db_ctx():
    return aiosqlite.connect(DB_PATH)

def parse_api_key(raw: str):
    if not raw or "." not in raw:
        raise HTTPException(401, "bad_api_key_format")
    kid, secret = raw.split(".", 1)
    if not kid or not secret:
        raise HTTPException(401, "bad_api_key_format")
    return kid, secret

async def verify_key(conn, raw_key: str, *, must_upload=False, must_consume=False):
    kid, secret = parse_api_key(raw_key)
    row = await (await conn.execute(
        "SELECT * FROM api_keys WHERE key_id=? AND active=1", (kid,)
    )).fetchone()
    if not row:
        raise HTTPException(401, "key_not_found_or_inactive")
    if not bcrypt.verify(secret, row["key_hash"]):
        raise HTTPException(401, "bad_secret")
    if must_upload and not row["can_upload"]:
        raise HTTPException(403, "no_upload_perm")
    if must_consume and not row["can_consume"]:
        raise HTTPException(403, "no_consume_perm")
    return dict(row)

async def allowed_owner_keys(conn, consumer_kid: str) -> Set[str]:
    owners = {consumer_kid}
    async with conn.execute(
        "SELECT owner_key_id FROM key_grants WHERE consumer_key_id=? AND enabled=1",
        (consumer_kid,)
    ) as cur:
        async for r in cur:
            owners.add(r["owner_key_id"])
    return owners

async def log_ev(conn, event: str, key_id: str, account_id: Optional[int], request, meta: dict | None = None):
    ip = getattr(getattr(request, "client", None), "host", None)
    ua = request.headers.get("user-agent") if hasattr(request, "headers") else None
    await conn.execute(
        "INSERT INTO events(event,key_id,account_id,ip,ua,meta_json) VALUES(?,?,?,?,?,?)",
        (event, key_id, account_id, ip, ua, json.dumps(meta or {}))
    )

async def rate_check_fetch(conn, key_row: dict):
    kid = key_row["key_id"]
    rpm = key_row.get("rpm_limit", 60)
    cap = key_row.get("daily_cap", 5000)
    # last 60s successful fetches
    rpm_used = (await (await conn.execute(
        "SELECT COUNT(*) FROM events WHERE key_id=? AND event='fetch_ok' AND ts >= datetime('now','-60 seconds')",
        (kid,)
    )).fetchone())[0]
    if rpm_used >= rpm:
        raise HTTPException(429, "rpm_limit")
    # daily cap (UTC day)
    day_used = (await (await conn.execute(
        "SELECT COUNT(*) FROM events WHERE key_id=? AND event='fetch_ok' AND date(ts)=date('now')",
        (kid,)
    )).fetchone())[0]
    if day_used >= cap:
        raise HTTPException(429, "daily_cap")

def _iso(d: str):
    try:
        return datetime.strptime(d, "%Y-%m-%d").strftime("%Y-%m-%d")
    except:
        raise HTTPException(400, "bad_date_format_use_YYYY-MM-DD")

def _gen_secret(n: int = 40) -> str:
    import string as _s, random as _r
    return "".join(_r.choices(_s.ascii_letters + _s.digits, k=n))

async def _require_admin(conn, X_API_KEY: str) -> str:
    akid, asec = parse_api_key(X_API_KEY)
    row = await (await conn.execute(
        "SELECT key_hash FROM api_keys WHERE key_id=? AND active=1", (akid,)
    )).fetchone()
    if not row or not bcrypt.verify(asec, row["key_hash"]):
        raise HTTPException(401, "bad_admin_key")
    if akid not in ADMIN_KEYS:
        raise HTTPException(403, "admin_only")
    return akid

# ---------- health ----------

@app.get("/healthz")
async def health():
    return {"ok": True}

# ---------- upload ----------

@app.post("/v1/upload")
async def upload_accounts(request: Request, X_API_KEY: str = Header(..., alias="X-API-Key")):
    body = await request.json()
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row

        key = await verify_key(conn, X_API_KEY, must_upload=True)
        owner = key["key_id"]

        items = body if isinstance(body, list) else [body]
        inserted = 0
        dup = 0
        for it in items:
            e = it.get("e") or it.get("email")
            p = it.get("p") or it.get("password")
            rt = it.get("rt") or it.get("refresh_token")
            cid = it.get("cid") or it.get("client_id")
            meta = it.get("meta") or {}
            if not (e and p and rt and cid):
                continue
            try:
                await conn.execute(
                    """INSERT INTO accounts
                       (email,password,refresh_token,client_id,status,used_outcome,created_at,owner_key_id,meta_json)
                       VALUES (?,?,?,?, 'unused', NULL, CURRENT_TIMESTAMP, ?, ?)""",
                    (e, p, rt, cid, owner, json.dumps(meta))
                )
                inserted += 1
            except aiosqlite.IntegrityError:
                dup += 1

        await conn.commit()
        return {"ins": inserted, "dup": dup}

# ---------- fetch (atomic claim) ----------

@app.post("/v1/fetch")
async def fetch_one(
    request: Request,
    X_API_KEY: str = Header(..., alias="X-API-Key"),
    owner_keys: Optional[str] = Query(None),
    wait: int = Query(0, ge=0, le=30)
):
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row

        key = await verify_key(conn, X_API_KEY, must_consume=True)
        consumer_kid = key["key_id"]

        await rate_check_fetch(conn, key)

        allowed = await allowed_owner_keys(conn, consumer_kid)
        if owner_keys:
            asked = {s.strip() for s in owner_keys.split(",") if s.strip()}
            allowed = allowed.intersection(asked)
            if not allowed:
                raise HTTPException(403, "no_acl_for_requested_owner_keys")

        placeholders = ",".join(["?"] * len(allowed))
        allowed_tuple = tuple(sorted(allowed))

        async def try_claim():
            sql = f"""
                WITH pick AS (
                    SELECT id FROM accounts
                    WHERE status='unused' AND owner_key_id IN ({placeholders})
                    ORDER BY created_at
                    LIMIT 1
                )
                UPDATE accounts
                SET status='used', used_by_key=?, used_at=CURRENT_TIMESTAMP
                WHERE id IN (SELECT id FROM pick)
                RETURNING id,email,password,refresh_token,client_id
            """
            async with conn.execute(sql, (*allowed_tuple, consumer_kid)) as cur:
                row = await cur.fetchone()
                if row:
                    await conn.commit()
                    return dict(row)
                return None

        got = await try_claim()
        if got:
            await log_ev(conn, "fetch_ok", consumer_kid, got["id"], request)
            await conn.commit()
            return {"id": got["id"], "e": got["email"], "p": got["password"], "rt": got["refresh_token"], "cid": got["client_id"]}

        if wait > 0:
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                await asyncio.sleep(0.5)
                got = await try_claim()
                if got:
                    await log_ev(conn, "fetch_ok", consumer_kid, got["id"], request)
                    await conn.commit()
                    return {"id": got["id"], "e": got["email"], "p": got["password"], "rt": got["refresh_token"], "cid": got["client_id"]}

        raise HTTPException(404, "no_unused_available")

# ---------- post-fetch state updates ----------

async def _must_same_key(conn, caller_kid: str, account_id: int):
    row = await (await conn.execute(
        "SELECT id,status,used_by_key FROM accounts WHERE id=?", (account_id,)
    )).fetchone()
    if not row:
        raise HTTPException(404, "account_not_found")
    if row["status"] != "used":
        raise HTTPException(409, "illegal_state_transition")
    if row["used_by_key"] != caller_kid:
        raise HTTPException(403, "wrong_key_for_account")
    return dict(row)

@app.post("/v1/mark_used_reg_success")
async def mark_used_reg_success(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    acc_id = payload.get("id")
    if not acc_id:
        raise HTTPException(400, "id_required")
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row
        key = await verify_key(conn, X_API_KEY, must_consume=True)
        await _must_same_key(conn, key["key_id"], acc_id)
        await conn.execute("UPDATE accounts SET used_outcome='reg_success' WHERE id=?", (acc_id,))
        await conn.commit()
        return {"ok": True}

@app.post("/v1/mark_used_282")
async def mark_used_282(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    acc_id = payload.get("id")
    if not acc_id:
        raise HTTPException(400, "id_required")
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row
        key = await verify_key(conn, X_API_KEY, must_consume=True)
        await _must_same_key(conn, key["key_id"], acc_id)
        await conn.execute("UPDATE accounts SET used_outcome='code_282' WHERE id=?", (acc_id,))
        await conn.commit()
        return {"ok": True}

@app.post("/v1/mark_locked")
async def mark_locked(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    acc_id = payload.get("id")
    if not acc_id:
        raise HTTPException(400, "id_required")
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row
        key = await verify_key(conn, X_API_KEY, must_consume=True)
        await _must_same_key(conn, key["key_id"], acc_id)
        await conn.execute("UPDATE accounts SET status='locked', locked_at=CURRENT_TIMESTAMP, used_outcome=NULL WHERE id=?", (acc_id,))
        await conn.commit()
        return {"ok": True}

# ---------- stats ----------

@app.get("/v1/stats")
async def stats(
    X_API_KEY: str = Header(..., alias="X-API-Key"),
    date_from: str | None = None,
    date_to: str | None = None,
    owner_keys: str | None = None,       # comma sep
    consumer_keys: str | None = None     # comma sep
):
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row

        viewer_row = await verify_key(conn, X_API_KEY, must_consume=True)
        viewer = viewer_row["key_id"]

        # allowed owners for viewer
        allowed = await allowed_owner_keys(conn, viewer)
        if viewer in ADMIN_KEYS:
            rows = await (await conn.execute("SELECT DISTINCT owner_key_id FROM accounts")).fetchall()
            allowed = {r[0] for r in rows} if rows else set()
            allowed.add(viewer)

        # parse filters
        where = []
        params: list = []

        if date_from:
            where.append("date(created_at) >= ?")
            params.append(_iso(date_from))
        if date_to:
            where.append("date(created_at) <= ?")
            params.append(_iso(date_to))

        # owner filter (intersection with ACL)
        if owner_keys:
            asked = {s.strip() for s in owner_keys.split(",") if s.strip()}
            owners = sorted(asked.intersection(allowed))
        else:
            owners = sorted(allowed)
        if not owners:
            raise HTTPException(403, "no_acl_for_requested_owner_keys")
        where.append(f"owner_key_id IN ({','.join(['?']*len(owners))})")
        params.extend(owners)

        # consumer filter
        if consumer_keys:
            cset = [s.strip() for s in consumer_keys.split(",") if s.strip()]
            where.append(f"used_by_key IN ({','.join(['?']*len(cset))})")
            params.extend(cset)

        _where = ("WHERE " + " AND ".join(where)) if where else ""

        async def one(sql, p=params):
            row = await (await conn.execute(sql, p)).fetchone()
            return row[0] if row and row[0] is not None else 0

        uploaded = await one(f"SELECT COUNT(*) FROM accounts {_where}")
        unused   = await one(f"SELECT COUNT(*) FROM accounts {_where} AND status='unused'")
        locked   = await one(f"SELECT COUNT(*) FROM accounts {_where} AND status='locked'")
        used_all = await one(f"SELECT COUNT(*) FROM accounts {_where} AND status IN ('used','locked')")
        reg_ok   = await one(f"SELECT COUNT(*) FROM accounts {_where} AND status='used' AND used_outcome='reg_success'")
        c282     = await one(f"SELECT COUNT(*) FROM accounts {_where} AND status='used' AND used_outcome='code_282'")
        used_pending = await one(f"SELECT COUNT(*) FROM accounts {_where} AND status='used' AND used_outcome IS NULL")

        # per-owner breakdown
        owners_sql = f"""
          SELECT owner_key_id,
                 COUNT(*) as uploaded,
                 SUM(status='unused') as unused,
                 SUM(status IN ('used','locked')) as used_total,
                 SUM(status='locked') as locked,
                 SUM(status='used' AND used_outcome='reg_success') as reg_success,
                 SUM(status='used' AND used_outcome='code_282') as code_282,
                 SUM(status='used' AND used_outcome IS NULL) as used_pending
          FROM accounts {_where}
          GROUP BY owner_key_id
          ORDER BY owner_key_id
        """
        per_owner = []
        async with conn.execute(owners_sql, params) as cur:
            async for r in cur:
                per_owner.append(dict(r))

        # per-consumer breakdown (only used/locked)
        consumers_sql = f"""
          SELECT COALESCE(used_by_key,'') as used_by_key,
                 COUNT(*) as total
          FROM accounts {_where} AND status IN ('used','locked')
          GROUP BY used_by_key
          ORDER BY used_by_key
        """
        per_consumer = []
        async with conn.execute(consumers_sql, params) as cur:
            async for r in cur:
                per_consumer.append(dict(r))

        return {
            "range": {"from": date_from, "to": date_to},
            "filter": {"owners": owners, "consumer_keys": consumer_keys},
            "totals": {
                "uploaded": uploaded,
                "unused": unused,
                "used_total": used_all,
                "locked": locked,
                "reg_success": reg_ok,
                "code_282": c282,
                "used_pending": used_pending
            },
            "per_owner": per_owner,
            "per_consumer": per_consumer
        }

# ---------- TTL reaper ----------

async def _reaper_once():
    cutoff = f"-{TTL_SECS} seconds"
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        await conn.execute("""
            UPDATE accounts
            SET status='unused', used_by_key=NULL, used_at=NULL
            WHERE status='used'
              AND used_outcome IS NULL
              AND used_at < datetime('now', ?)
        """, (cutoff,))
        await conn.commit()

async def _reaper_loop():
    while True:
        try:
            await _reaper_once()
        except Exception:
            pass
        await asyncio.sleep(30)

@app.on_event("startup")
async def _start_reaper():
    asyncio.create_task(_reaper_loop())

# ---------- key info ----------

@app.get("/v1/keys/me")
async def key_me(X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row
        kid, secret = parse_api_key(X_API_KEY)
        row = await (await conn.execute(
            "SELECT * FROM api_keys WHERE key_id=? AND active=1", (kid,)
        )).fetchone()
        if not row or not bcrypt.verify(secret, row["key_hash"]):
            raise HTTPException(401, "bad_key")
        d = dict(row)
        rpm_used = (await (await conn.execute(
            "SELECT COUNT(*) FROM events WHERE key_id=? AND event='fetch_ok' AND ts>=datetime('now','-60 seconds')", (kid,)
        )).fetchone())[0]
        day_used = (await (await conn.execute(
            "SELECT COUNT(*) FROM events WHERE key_id=? AND event='fetch_ok' AND date(ts)=date('now')", (kid,)
        )).fetchone())[0]
        return {
            "key_id": kid,
            "label": d.get("label"),
            "active": d.get("active"),
            "can_upload": d.get("can_upload"),
            "can_consume": d.get("can_consume"),
            "rpm_limit": d.get("rpm_limit"),
            "daily_cap": d.get("daily_cap"),
            "usage": {"rpm_current": rpm_used, "today_fetches": day_used}
        }

# ---------- admin API ----------

@app.post("/v1/admin/update_key")
async def admin_update_key(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        kid = payload.get("key_id")
        if not kid:
            raise HTTPException(400, "key_id_required")
        fields, args = [], []
        for col in ("active","can_upload","can_consume","daily_cap","rpm_limit","label"):
            if col in payload:
                fields.append(f"{col}=?")
                args.append(payload[col])
        if not fields:
            return {"ok": True, "note": "no_changes"}
        args.append(kid)
        await conn.execute(f"UPDATE api_keys SET {', '.join(fields)} WHERE key_id=?", tuple(args))
        await conn.commit()
        return {"ok": True}

@app.post("/v1/admin/create_key")
async def admin_create_key(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        kid = payload.get("key_id")
        if not kid:
            raise HTTPException(400, "key_id_required")
        label = payload.get("label") or kid
        secret = _gen_secret()
        khash = bcrypt.hash(secret)
        await conn.execute("""
            INSERT INTO api_keys(key_id,key_hash,label,can_upload,can_consume,active,daily_cap,rpm_limit)
            VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(key_id) DO UPDATE SET
              key_hash=excluded.key_hash,label=excluded.label,can_upload=excluded.can_upload,
              can_consume=excluded.can_consume,active=excluded.active,
              daily_cap=excluded.daily_cap,rpm_limit=excluded.rpm_limit
        """, (kid, khash, label,
              int(payload.get("can_upload",1)),
              int(payload.get("can_consume",1)),
              int(payload.get("active",1)),
              int(payload.get("daily_cap",5000)),
              int(payload.get("rpm_limit",60))))
        await conn.commit()
        return {"ok": True, "api_key": f"{kid}.{secret}"}

@app.post("/v1/admin/regen_secret")
async def admin_regen_secret(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        kid = payload.get("key_id")
        if not kid:
            raise HTTPException(400, "key_id_required")
        secret = _gen_secret()
        khash = bcrypt.hash(secret)
        await conn.execute("UPDATE api_keys SET key_hash=? WHERE key_id=?", (khash, kid))
        await conn.commit()
        return {"ok": True, "api_key": f"{kid}.{secret}"}

@app.get("/v1/admin/list_keys")
async def admin_list_keys(X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        out = []
        async with conn.execute("SELECT key_id,label,active,can_upload,can_consume,daily_cap,rpm_limit,created_at FROM api_keys ORDER BY key_id") as cur:
            async for r in cur:
                out.append(dict(r))
        return {"keys": out}

@app.get("/v1/admin/list_grants")
async def admin_list_grants(X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        out = []
        async with conn.execute(
            "SELECT consumer_key_id, owner_key_id, enabled, created_at FROM key_grants ORDER BY consumer_key_id, owner_key_id"
        ) as cur:
            async for r in cur:
                out.append(dict(r))
        return {"grants": out}

@app.post("/v1/admin/grant")
async def admin_grant(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        c = payload.get("consumer_key_id"); o = payload.get("owner_key_id"); en = int(payload.get("enabled",1))
        if not (c and o): raise HTTPException(400, "consumer_key_id_and_owner_key_id_required")
        await conn.execute(
            "INSERT OR REPLACE INTO key_grants(consumer_key_id,owner_key_id,enabled,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)",
            (c,o,en)
        )
        await conn.commit()
        return {"ok": True}

@app.post("/v1/admin/revoke")
async def admin_revoke(payload: dict, X_API_KEY: str = Header(..., alias="X-API-Key")):
    async with db_ctx() as conn:
        conn.row_factory = aiosqlite.Row
        await _require_admin(conn, X_API_KEY)
        c = payload.get("consumer_key_id"); o = payload.get("owner_key_id")
        if not (c and o): raise HTTPException(400, "consumer_key_id_and_owner_key_id_required")
        await conn.execute("UPDATE key_grants SET enabled=0 WHERE consumer_key_id=? AND owner_key_id=?", (c,o))
        await conn.commit()
        return {"ok": True}

# ---------- UI routes ----------

# user dashboard disabled
@app.get("/user")
async def user_ui_disabled():
    raise HTTPException(404, "user_ui_disabled")

# admin UI with hard no-cache
@app.get("/admin")
async def admin_ui_latest():
    path = "/opt/account-api/app/admin.html"
    headers = {"Cache-Control":"no-store, no-cache, must-revalidate, max-age=0"}
    return FileResponse(path, media_type="text/html; charset=utf-8", headers=headers)


# ----------------------------
# Admin: enable/disable/delete
# ----------------------------
from pydantic import BaseModel
from fastapi import Header

class _KeyIdReq(BaseModel):
    key_id: str

def _is_admin_kid(kid: str) -> bool:  # small helper (fallback if not present above)
    try:
        admins = os.getenv("ADMIN_KEYS", "admin").split(",")
        admins = [a.strip() for a in admins if a.strip()]
        return kid in admins
    except Exception:
        return False

@app.post("/v1/admin/enable_key")
async def admin_enable_key(req: _KeyIdReq, x_api_key: str = Header(..., alias="X-API-Key")):
    # auth: header admin key
    admin_kid, _ = parse_api_key(x_api_key)
    if not _is_admin_kid(admin_kid):
        raise HTTPException(403, "bad_admin_key")

    k = (req.key_id or "").strip()
    if not k:
        raise HTTPException(400, "key_id_required")

    async with db_ctx() as conn:
        await conn.execute("UPDATE api_keys SET active=1 WHERE key_id=?", (k,))
        await conn.commit()
    return {"ok": True}

@app.post("/v1/admin/disable_key")
async def admin_disable_key(req: _KeyIdReq, x_api_key: str = Header(..., alias="X-API-Key")):
    admin_kid, _ = parse_api_key(x_api_key)
    if not _is_admin_kid(admin_kid):
        raise HTTPException(403, "bad_admin_key")

    k = (req.key_id or "").strip()
    if not k:
        raise HTTPException(400, "key_id_required")

    async with db_ctx() as conn:
        await conn.execute("UPDATE api_keys SET active=0 WHERE key_id=?", (k,))
        await conn.commit()
    return {"ok": True}

@app.post("/v1/admin/delete_key")
async def admin_delete_key(req: _KeyIdReq, x_api_key: str = Header(..., alias="X-API-Key")):
    """
    Hard delete a key + clean dependent grants.
    NOTE: Admin keys (listed in ADMIN_KEYS) cannot be deleted.
    """
    admin_kid, _ = parse_api_key(x_api_key)
    if not _is_admin_kid(admin_kid):
        raise HTTPException(403, "bad_admin_key")

    k = (req.key_id or "").strip()
    if not k:
        raise HTTPException(400, "key_id_required")

    # never allow deleting admin keys themselves
    admins = [a.strip() for a in os.getenv("ADMIN_KEYS", "admin").split(",") if a.strip()]
    if k in admins:
        raise HTTPException(400, "cannot_delete_admin_key")

    async with db_ctx() as conn:
        # check existence
        cur = await conn.execute("SELECT 1 FROM api_keys WHERE key_id=?", (k,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "key_not_found")

        # clean dependent grants (both sides)
        await conn.execute("DELETE FROM key_grants WHERE consumer_key_id=? OR owner_key_id=?", (k, k))
        # delete the key
        await conn.execute("DELETE FROM api_keys WHERE key_id=?", (k,))
        await conn.commit()

    return {"ok": True}

# ---------- safer delete key (user) ----------
from pydantic import BaseModel

class _KeyIdReq(BaseModel):
    key_id: str

def _is_admin_kid(kid: str) -> bool:
    admins = os.getenv("ADMIN_KEYS", "admin")
    allowed = [a.strip() for a in admins.split(",") if a.strip()]
    return kid in allowed

@app.post("/v1/admin/delete_key")
async def admin_delete_key(req: _KeyIdReq, x_api_key: str = Header(..., alias="X-API-Key")):
    # only admins can delete
    admin_kid, _ = parse_api_key(x_api_key)
    if not _is_admin_kid(admin_kid):
        raise HTTPException(403, "bad_admin_key")

    kid = (req.key_id or "").strip()
    if not kid:
        raise HTTPException(400, "key_id_required")
    if _is_admin_kid(kid):
        raise HTTPException(400, "cannot_delete_admin_key")

    async with db_ctx() as conn:
        # key exists?
        cur = await conn.execute("SELECT 1 FROM api_keys WHERE key_id=?", (kid,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "key_not_found")

        # do everything in a transaction
        await conn.execute("BEGIN")
        try:
            # remove grants where this key is consumer or owner
            await conn.execute("DELETE FROM key_grants WHERE consumer_key_id=? OR owner_key_id=?", (kid, kid))
            # remove the api key
            await conn.execute("DELETE FROM api_keys WHERE key_id=?", (kid,))
            await conn.commit()
        except Exception as e:
            await conn.rollback()
            import sys, traceback
            print(f"[delete_key_error] key_id={kid}: {e}", file=sys.stderr)
            traceback.print_exc()
            raise HTTPException(500, "delete_failed")

    return {"ok": True, "deleted_key_id": kid}

# =========================
# === GET endpoints (v1) ==
# =========================

from fastapi import Query

async def _get_allowed_owners_v1(conn, consumer_kid: str, owners_csv: Optional[str]) -> List[str]:
    """ACL: self + enabled grants unless owners= filter is provided."""
    allowed = {consumer_kid}
    async with conn.execute(
        "SELECT owner_key_id FROM key_grants WHERE consumer_key_id=? AND enabled=1",
        (consumer_kid,)
    ) as cur:
        async for r in cur:
            allowed.add(r[0])

    if owners_csv:
        asked = {s.strip() for s in owners_csv.split(",") if s.strip()}
        allowed = allowed.intersection(asked)

    # keep only active upload-capable owners
    if not allowed:
        return []
    q = ",".join(["?"] * len(allowed))
    cur = await conn.execute(
        f"SELECT key_id FROM api_keys WHERE key_id IN ({q}) AND active=1 AND can_upload=1",
        tuple(sorted(allowed)),
    )
    rows = await cur.fetchall()
    return [r[0] for r in rows]

@app.get("/v1/fetch")
async def v1_fetch_get(
    quantity: int = Query(1, ge=1, le=100),
    owners: Optional[str] = Query(None, description="comma separated owner_key_ids"),
    wait: int = Query(0, ge=0, le=30),
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    """
    Atomically claim up to ?quantity unused accounts from allowed owners.
    Returns 409 with {"detail":"out_of_stock","owners":[...]} if none available.
    """
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row

        me = await verify_key(conn, X_API_KEY, must_consume=True)
        consumer = me["key_id"]

        await rate_check_fetch(conn, me)
        allowed = await _get_allowed_owners_v1(conn, consumer, owners)
        if not allowed:
            raise HTTPException(403, "no_acl_for_requested_owner_keys")

        placeholders = ",".join(["?"] * len(allowed))
        allowed_tuple = tuple(sorted(allowed))

        async def try_claim(n: int):
            sql = f"""
            WITH pick AS (
              SELECT id FROM accounts
              WHERE status='unused' AND owner_key_id IN ({placeholders})
              ORDER BY created_at
              LIMIT ?
            )
            UPDATE accounts
              SET status='used', used_by_key=?, used_at=CURRENT_TIMESTAMP
            WHERE id IN (SELECT id FROM pick)
            RETURNING id,email,password,refresh_token,client_id,owner_key_id
            """
            params = (*allowed_tuple, n, consumer)
            async with conn.execute(sql, params) as cur:
                rows = await cur.fetchall()
            if rows:
                await conn.commit()
                for r in rows:
                    await log_ev(conn, "fetch_ok", consumer, r["id"], request=None, meta={"owner": r["owner_key_id"]})
                await conn.commit()
                return [
                  {"id":r["id"], "e":r["email"], "p":r["password"],
                   "rt":r["refresh_token"], "cid":r["client_id"], "owner":r["owner_key_id"]}
                  for r in rows
                ]
            return None

        got = await try_claim(quantity)
        if got:
            return {"ok": True, "count": len(got), "data": got}

        if wait > 0:
            deadline = time.monotonic() + wait
            while time.monotonic() < deadline:
                await asyncio.sleep(0.5)
                got = await try_claim(quantity)
                if got:
                    return {"ok": True, "count": len(got), "data": got}

        raise HTTPException(409, {"detail": "out_of_stock", "owners": list(allowed)})

@app.get("/v1/mark")
async def v1_mark_get(
    status: str = Query(..., description="'reg_success' | 'code_282' | 'locked' | alias: 'success'"),
    id: Optional[int] = None,
    email: Optional[str] = None,
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    """
    Mark by id or email.
    - Non-admin callers must be the consumer who fetched the account.
    - Admin keys can override.
    """
    if not id and not email:
        raise HTTPException(422, "id_or_email_required")

    st = status.strip().lower()
    if st == "success":
        st = "reg_success"
    if st not in ("reg_success", "code_282", "locked"):
        raise HTTPException(422, "bad_status")

    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row

        caller = await verify_key(conn, X_API_KEY)
        caller_id = caller["key_id"]
        is_admin = caller_id in ADMIN_KEYS

        # find target
        if id:
            row = await (await conn.execute(
                "SELECT id,status,used_by_key FROM accounts WHERE id=?", (id,)
            )).fetchone()
        else:
            row = await (await conn.execute(
                "SELECT id,status,used_by_key FROM accounts WHERE email=?", (email,)
            )).fetchone()

        if not row:
            raise HTTPException(404, "account_not_found")

        acc_id, acc_status, acc_used_by = row["id"], row["status"], row["used_by_key"]

        if not is_admin:
            # only the consumer who fetched it may mark
            if st in ("reg_success", "code_282"):
                if acc_status != "used" or acc_used_by != caller_id:
                    raise HTTPException(403, "wrong_key_for_account")
            if st == "locked":
                # allow locking if you fetched it; otherwise forbid
                if acc_used_by != caller_id:
                    raise HTTPException(403, "wrong_key_for_account")

        if st == "locked":
            await conn.execute(
                "UPDATE accounts SET status='locked', locked_at=CURRENT_TIMESTAMP, used_outcome=NULL WHERE id=?",
                (acc_id,)
            )
        else:
            await conn.execute(
                "UPDATE accounts SET status='used', used_outcome=?, used_at=COALESCE(used_at,CURRENT_TIMESTAMP) WHERE id=?",
                (st, acc_id,)
            )

        await conn.execute(
            "INSERT INTO events(event,key_id,account_id,ip,ua,meta_json) VALUES(?,?,?,?,?,?)",
            (f"mark_{st}", caller_id, acc_id, None, None, json.dumps({}))
        )
        await conn.commit()
        return {"ok": True, "id": acc_id, "status": st}

@app.get("/v1/owner_summary")
async def v1_owner_summary(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    owners: Optional[str] = None,
    X_API_KEY: str = Header(..., alias="X-API-Key"),
):
    """
    Rollup: per owner (uploaded/unused/used/locked/breakup) + per-consumer usage by owner
    """
    async with db_ctx() as conn:
        await conn.execute("PRAGMA journal_mode=WAL;")
        await conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = aiosqlite.Row

        viewer = await verify_key(conn, X_API_KEY)
        viewer_id = viewer["key_id"]
        allowed = await _get_allowed_owners_v1(conn, viewer_id, owners)
        # Admin can see all
        if viewer_id in ADMIN_KEYS and not owners:
            cur = await conn.execute("SELECT DISTINCT owner_key_id FROM accounts")
            allowed = [r[0] for r in await cur.fetchall()]

        if not allowed:
            return {"range":{"from":date_from,"to":date_to},"owners":[], "consumers":[]}

        where = ["owner_key_id IN (" + ",".join(["?"]*len(allowed)) + ")"]
        args: List[Any] = list(allowed)
        if date_from:
            where.append("date(created_at) >= date(?)")
            args.append(_iso(date_from))
        if date_to:
            where.append("date(created_at) <= date(?)")
            args.append(_iso(date_to))
        ws = " AND ".join(where)

        cur = await conn.execute(
            f"""
            SELECT owner_key_id,
                   COUNT(*) AS uploaded,
                   SUM(status='unused') AS unused,
                   SUM(status IN ('used','locked')) AS used_total,
                   SUM(status='locked') AS locked,
                   SUM(CASE WHEN status='used' AND used_outcome='reg_success' THEN 1 ELSE 0 END) AS reg_success,
                   SUM(CASE WHEN status='used' AND used_outcome='code_282' THEN 1 ELSE 0 END) AS code_282
            FROM accounts
            WHERE {ws}
            GROUP BY owner_key_id
            ORDER BY owner_key_id
            """,
            args
        )
        owners_out = []
        async for r in cur:
            uploaded = r["uploaded"]
            reg_ok = r["reg_success"] or 0
            c282   = r["code_282"] or 0
            owners_out.append({
              "owner": r["owner_key_id"],
              "uploaded": uploaded,
              "unused": r["unused"] or 0,
              "used_total": r["used_total"] or 0,
              "locked": r["locked"] or 0,
              "reg_success": reg_ok,
              "code_282": c282,
              "remaining_after_unlock": uploaded - (reg_ok + c282),
              "used_breakup": {
                "reg_success": reg_ok,
                "code_282": c282,
                "other": max(0, (r["used_total"] or 0) - (reg_ok + c282)),
              },
            })

        # per-consumer usage by owner (from events 'fetch_ok')
        ev_where = ["e.event='fetch_ok'"]
        ev_args: List[Any] = []
        if date_from:
            ev_where.append("date(e.ts) >= date(?)")
            ev_args.append(_iso(date_from))
        if date_to:
            ev_where.append("date(e.ts) <= date(?)")
            ev_args.append(_iso(date_to))
        ev_where.append("a.owner_key_id IN (" + ",".join(["?"]*len(allowed)) + ")")
        ev_args += allowed
        ev_sql = " AND ".join(ev_where)

        cur = await conn.execute(
            f"""
            SELECT e.key_id AS consumer_key_id, a.owner_key_id, COUNT(*) AS cnt
            FROM events e
            JOIN accounts a ON a.id = e.account_id
            WHERE {ev_sql}
            GROUP BY e.key_id, a.owner_key_id
            ORDER BY e.key_id, a.owner_key_id
            """,
            ev_args
        )
        consumers = {}
        async for consumer_k, owner_k, cnt in cur:
            row = consumers.setdefault(consumer_k or "-", {"consumer": consumer_k or "-", "used_total": 0, "by_owner": {}})
            row["by_owner"][owner_k] = cnt
            row["used_total"] += cnt

        return {"range":{"from":date_from,"to":date_to}, "owners": owners_out, "consumers": list(consumers.values())}

@app.post("/v1/admin/release_pending_older_than")
async def v1_release_pending(minutes: int = 10, X_API_KEY: str = Header(..., alias="X-API-Key")):
    """
    Manual TTL: set back to UNUSED any 'used' rows with no used_outcome older than X minutes.
    """
    async with db_ctx() as conn:
        me = await verify_key(conn, X_API_KEY)
        if me["key_id"] not in ADMIN_KEYS:
            raise HTTPException(403, "admin_only")
        cur = await conn.execute(
            """
            UPDATE accounts
              SET status='unused', used_by_key=NULL, used_at=NULL
            WHERE status='used' AND used_outcome IS NULL
              AND used_at < datetime('now', ?)
            """,
            (f"-{int(minutes)} minutes",)
        )
        await conn.commit()
        return {"ok": True, "released": cur.rowcount if hasattr(cur, "rowcount") else None, "older_than_min": minutes}

# --- robust release_pending_older_than (overrides any earlier definition) ---
from fastapi import Query, Header, HTTPException
from typing import Optional

def _is_admin_key(key: str) -> bool:
    # Uses your existing ENV ADMIN_KEYS check if present;
    # fallback: treat any key_id in ADMIN_KEYS as admin.
    import os
    admins = set((os.getenv("ADMIN_KEYS","") or "").split(",")) - {""}
    try:
        key_id = key.split(".", 1)[0]
    except Exception:
        return False
    return key_id in admins

@app.post("/v1/admin/release_pending_older_than")
async def admin_release_pending_older_than(
    minutes: int = Query(..., ge=1, le=10080),
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    if not _is_admin_key(x_api_key):
        raise HTTPException(status_code=403, detail="forbidden")

    cutoff = f"-{minutes} minutes"
    released = 0
    async with db_ctx() as conn:
        # Try path A: accounts.updated_at exists
        try:
            # probe column
            await conn.execute("SELECT updated_at FROM accounts LIMIT 1")
            cur = await conn.execute("""
                UPDATE accounts
                   SET status='unused',
                       claimed_by=NULL
                 WHERE status='used_pending'
                   AND updated_at <= datetime('now', ?)
            """, (cutoff,))
            released = cur.rowcount or 0
            await conn.commit()
            return {"ok": True, "released": released}
        except Exception:
            pass

        # Path B: fall back to events’ last timestamp
        # (works if events has: account_id, created_at)
        cur = await conn.execute("""
            UPDATE accounts
               SET status='unused',
                   claimed_by=NULL
             WHERE status='used_pending'
               AND COALESCE((
                     SELECT MAX(created_at)
                       FROM events e
                      WHERE e.account_id = accounts.id
                   ), '1970-01-01 00:00:00')
                   <= datetime('now', ?)
        """, (cutoff,))
        released = cur.rowcount or 0
        await conn.commit()
        return {"ok": True, "released": released}

# --- robust release_pending_older_than (overrides any earlier definition) ---
from fastapi import Query, Header, HTTPException
from typing import Optional

def _is_admin_key(key: str) -> bool:
    # Uses your existing ENV ADMIN_KEYS check if present;
    # fallback: treat any key_id in ADMIN_KEYS as admin.
    import os
    admins = set((os.getenv("ADMIN_KEYS","") or "").split(",")) - {""}
    try:
        key_id = key.split(".", 1)[0]
    except Exception:
        return False
    return key_id in admins

@app.post("/v1/admin/release_pending_older_than")
async def admin_release_pending_older_than(
    minutes: int = Query(..., ge=1, le=10080),
    x_api_key: str = Header(..., alias="X-API-Key"),
):
    if not _is_admin_key(x_api_key):
        raise HTTPException(status_code=403, detail="forbidden")

    cutoff = f"-{minutes} minutes"
    released = 0
    async with db_ctx() as conn:
        # Try path A: accounts.updated_at exists
        try:
            # probe column
            await conn.execute("SELECT updated_at FROM accounts LIMIT 1")
            cur = await conn.execute("""
                UPDATE accounts
                   SET status='unused',
                       claimed_by=NULL
                 WHERE status='used_pending'
                   AND updated_at <= datetime('now', ?)
            """, (cutoff,))
            released = cur.rowcount or 0
            await conn.commit()
            return {"ok": True, "released": released}
        except Exception:
            pass

        # Path B: fall back to events’ last timestamp
        # (works if events has: account_id, created_at)
        cur = await conn.execute("""
            UPDATE accounts
               SET status='unused',
                   claimed_by=NULL
             WHERE status='used_pending'
               AND COALESCE((
                     SELECT MAX(created_at)
                       FROM events e
                      WHERE e.account_id = accounts.id
                   ), '1970-01-01 00:00:00')
                   <= datetime('now', ?)
        """, (cutoff,))
        released = cur.rowcount or 0
        await conn.commit()
        return {"ok": True, "released": released}
