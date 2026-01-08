import os, sys, sqlite3, secrets, string, datetime
from passlib.hash import bcrypt

DB=os.environ.get("DB_PATH","/opt/account-api/db/accounts.sqlite")
kid = sys.argv[1] if len(sys.argv)>1 else None
if not kid: 
    print("usage: make_key.py <key_id>"); exit(1)

secret = ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(40))
hashv = bcrypt.hash(secret)

con = sqlite3.connect(DB)
con.execute("""INSERT OR REPLACE INTO api_keys
(key_id,key_hash,label,can_upload,can_consume,active,daily_cap,rpm_limit,created_at)
VALUES(?,?,?,?,?,?,?, ?, datetime('now'))""",
            (kid, hashv, kid, 1,1,1, 5000,60))
con.commit(); con.close()

print(f"KEY_ID={kid}\nSECRET={secret}\nX-API-Key => {kid}.{secret}")
