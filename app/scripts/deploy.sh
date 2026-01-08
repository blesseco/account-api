#!/usr/bin/env bash
set -euo pipefail

# === CONFIG ===
VPS="${VPS:-root@your.vps.ip}"
APP_DIR="/opt/account-api"
APP_DB_DIR="$APP_DIR/db"
APP_HTML_DIR="$APP_DIR/app"

echo "[1/5] Create dirs on VPS"
ssh "$VPS" "sudo mkdir -p $APP_DB_DIR $APP_HTML_DIR && sudo chown -R \$USER:\$USER $APP_DIR"

echo "[2/5] Upload server + admin UI"
scp -r server/main.py "$VPS:$APP_DIR/main.py"
scp -r admin/admin.html "$VPS:$APP_HTML_DIR/admin.html"

echo "[3/5] Ensure env (ADMIN_LOGIN_SECRET)"
ssh "$VPS" 'sudo bash -lc "mkdir -p /etc/systemd/system/account-api.service.d; cat >/etc/systemd/system/account-api.service.d/env.conf <<EOF
[Service]
Environment=ADMIN_LOGIN_SECRET=change_this_to_a_long_random_value
EOF
systemctl daemon-reload || true"'

echo "[4/5] Restart service"
ssh "$VPS" "sudo systemctl restart account-api && sleep 1 && sudo systemctl status --no-pager account-api | sed -n '1,12p'"

echo "[5/5] Hit healthz"
ssh "$VPS" "curl -s http://127.0.0.1:8000/healthz && echo"
echo "Done ✅"
