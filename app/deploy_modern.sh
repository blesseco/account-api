#!/usr/bin/env bash
set -euo pipefail
# usage: VPS=root@IP ./deploy_modern.sh
VPS="${VPS:-root@your.vps.ip}"
APP_DIR="/opt/account-api/app"
echo "[1/2] Upload new admin UI"
scp admin_pro.html "$VPS:$APP_DIR/admin.html"
echo "[2/2] Done. Open https://YOUR_DOMAIN/admin?v=$(date +%s) and hard refresh."
