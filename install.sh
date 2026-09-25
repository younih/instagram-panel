#!/usr/bin/env bash
#
# نصب آسان پنل مدیریت اینستاگرام (نسخه ۲: فرانت + بک‌اند) روی VPS اوبونتو
# اجرا:  sudo ./install.sh panel.example.com
#
# این اسکریپت موارد زیر را انجام می‌دهد:
#   ۱. نصب nginx، پایتون، certbot و فایروال
#   ۲. انتشار فایل‌های فرانت (ورود/ثبت‌نام، پنل کاربری، پنل ادمین) در /var/www/instagram-panel
#   ۳. راه‌اندازی بک‌اند Flask + SQLite در /opt/panel (سرویس دائمی systemd + gunicorn)
#   ۴. ساخت حساب ادمین اولیه (فقط در نصب اول)
#   ۵. تنظیم nginx: سرو فایل‌های استاتیک + پروکسی /api به بک‌اند
#   ۶. دریافت گواهی رایگان HTTPS از Let's Encrypt
#
# به‌روزرسانی نسخه‌های قبلی: اسکریپت را دوباره اجرا کنید؛ دیتابیس و حساب‌ها حفظ می‌شوند.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "خطا: لطفاً با sudo اجرا کنید:"
  echo "  sudo ./install.sh panel.example.com"
  exit 1
fi

DOMAIN="${1:?خطا: نام ساب‌دامنه را وارد کنید. مثال: sudo ./install.sh panel.example.com}"

for f in index.html app.html admin.html; do
  if [[ ! -f ./$f ]]; then
    echo "خطا: فایل $f در پوشه جاری پیدا نشد. ابتدا ریپو را clone/pull کنید و داخل آن اجرا کنید."
    exit 1
  fi
done
if [[ ! -f ./api/app.py ]]; then
  echo "خطا: پوشه api/ در پوشه جاری پیدا نشد."
  exit 1
fi

WEBROOT="/var/www/instagram-panel"
APPDIR="/opt/panel/api"
DATADIR="/opt/panel/data"
VENV="/opt/panel/venv"
SERVICE="panel-api"

echo "==> [1/7] به‌روزرسانی سیستم و نصب پیش‌نیازها ..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx certbot python3-certbot-nginx \
  python3 python3-venv ufw

echo "==> [2/7] انتشار فایل‌های فرانت در $WEBROOT ..."
mkdir -p "$WEBROOT"
cp ./index.html ./app.html ./admin.html "$WEBROOT/"
chown -R www-data:www-data "$WEBROOT"
chmod -R 755 "$WEBROOT"

echo "==> [3/7] راه‌اندازی بک‌اند در /opt/panel ..."
mkdir -p "$APPDIR" "$DATADIR"
cp ./api/app.py ./api/seed_admin.py ./api/requirements.txt "$APPDIR/"
if [[ ! -d "$VENV" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$APPDIR/requirements.txt"
chown -R www-data:www-data "$DATADIR"
chmod 700 "$DATADIR"

echo "==> [4/7] ساخت دیتابیس ..."
PANEL_DATA_DIR="$DATADIR" "$VENV/bin/python" -c "import sys; sys.path.insert(0, '$APPDIR'); from app import init_db; init_db()"
chown -R www-data:www-data "$DATADIR"

echo "==> [5/7] حساب ادمین ..."
ADMIN_EXISTS=$(PANEL_DATA_DIR="$DATADIR" "$VENV/bin/python" -c "
import sqlite3; db=sqlite3.connect('$DATADIR/panel.db')
print(db.execute(\"SELECT COUNT(*) FROM users WHERE role='admin'\").fetchone()[0])")
if [[ "$ADMIN_EXISTS" == "0" ]]; then
  echo "   هیچ ادمینی وجود ندارد؛ حساب ادمین اولیه را بسازید:"
  read -rp "   نام نمایشی [مدیر سایت]: " ADMIN_NAME
  ADMIN_NAME="${ADMIN_NAME:-مدیر سایت}"
  read -rp "   ایمیل ادمین: " ADMIN_EMAIL
  while [[ -z "$ADMIN_EMAIL" ]]; do read -rp "   ایمیل ادمین (الزامی): " ADMIN_EMAIL; done
  read -rsp "   گذرواژه ادمین (حداقل ۸ کاراکتر): " ADMIN_PASS; echo
  while [[ ${#ADMIN_PASS} -lt 8 ]]; do read -rsp "   گذرواژه کوتاه است؛ دوباره: " ADMIN_PASS; echo; done
  PANEL_DATA_DIR="$DATADIR" \
  PANEL_ADMIN_NAME="$ADMIN_NAME" PANEL_ADMIN_EMAIL="$ADMIN_EMAIL" PANEL_ADMIN_PASSWORD="$ADMIN_PASS" \
    "$VENV/bin/python" "$APPDIR/seed_admin.py"
  chown -R www-data:www-data "$DATADIR"
else
  echo "   ادمین از قبل وجود دارد؛ بدون تغییر."
fi

echo "==> نصب سرویس دائمی بک‌اند ($SERVICE) ..."
# انتخاب پورت آزاد برای بک‌اند (8000 ممکن است توسط پروژه دیگری اشغال باشد)
PANEL_PORT=8000
while ss -tln 2>/dev/null | grep -q ":${PANEL_PORT} "; do
  PANEL_PORT=$((PANEL_PORT+1))
done
echo "   پورت بک‌اند: $PANEL_PORT"
cat > /etc/systemd/system/${SERVICE}.service <<EOF
[Unit]
Description=Instagram Panel API (Flask + gunicorn)
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${APPDIR}
Environment=PANEL_DATA_DIR=${DATADIR}
ExecStart=${VENV}/bin/gunicorn app:app --bind 127.0.0.1:${PANEL_PORT} --workers 2 --timeout 120
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE"
systemctl restart "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" || { echo "خطا: سرویس بک‌اند بالا نیامد:"; journalctl -u "$SERVICE" -n 20 --no-pager; exit 1; }
echo "   سرویس بک‌اند فعال است."

echo "==> [6/7] تنظیم nginx برای $DOMAIN ..."

# بلوک مشترک هر دو server (پورت 80 و 443)
nginx_inner() {
cat <<EOF
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # بک‌اند
    location /api/ {
        proxy_pass http://127.0.0.1:$PANEL_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 120s;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
EOF
}

# نوشتن کانفیگ nginx؛ اگر گواهی هست بلاک 443 هم با همان گواهی نوشته می‌شود.
# (بلاک 443 قدیمیِ ساخته‌ی certbot حذف می‌شود چون location /api/ را ندارد و تداخل می‌کند.)
write_nginx_config() {
rm -f /etc/nginx/sites-enabled/instagram-panel-le-ssl.conf \
      /etc/nginx/sites-available/instagram-panel-le-ssl.conf
{
echo "server {"
echo "    listen 80;"
echo "    server_name ${DOMAIN};"
echo "    root ${WEBROOT};"
echo "    index index.html;"
echo ""
if [[ -d /etc/letsencrypt/live/$DOMAIN ]]; then
echo "    # گواهی از قبل وجود دارد: همه‌چیز به HTTPS هدایت می‌شود"
echo "    if (\$host = ${DOMAIN}) { return 301 https://\$host\$request_uri; }"
echo ""
fi
nginx_inner
echo "}"
if [[ -d /etc/letsencrypt/live/$DOMAIN ]]; then
echo ""
echo "server {"
echo "    listen 443 ssl;"
echo "    server_name ${DOMAIN};"
echo "    root ${WEBROOT};"
echo "    index index.html;"
echo "    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;"
echo "    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;"
echo "    include /etc/letsencrypt/options-ssl-nginx.conf;"
echo "    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;"
echo ""
nginx_inner
echo "}"
fi
} > /etc/nginx/sites-available/instagram-panel
ln -sf /etc/nginx/sites-available/instagram-panel /etc/nginx/sites-enabled/instagram-panel
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
}

write_nginx_config
systemctl enable --now nginx

echo "==> فعال‌سازی فایروال ..."
ufw --force enable >/dev/null 2>&1 || true
ufw allow 22/tcp comment 'SSH' >/dev/null
ufw allow 80/tcp comment 'HTTP' >/dev/null
ufw allow 443/tcp comment 'HTTPS' >/dev/null

echo "==> [7/8] گواهی HTTPS ..."
# مرحله ۶ بلاک 443 را خودش می‌نویسد؛ certbot فقط در نصب اول (نبود گواهی) لازم است،
# و بعدش کانفیگ دوباره نوشته می‌شود تا بلاک 443 با گواهی تازه همراه شود.
if [[ ! -d /etc/letsencrypt/live/$DOMAIN ]]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos \
    --register-unsafely-without-email --redirect \
    --deploy-hook "systemctl reload nginx"
  write_nginx_config
else
  echo "   گواهی $DOMAIN از قبل وجود دارد؛ از همان استفاده شد."
fi

echo ""
echo "✅ تمام شد!"
echo "   ورود:            https://${DOMAIN}/"
echo "   پنل کاربری:      https://${DOMAIN}/app.html"
echo "   پنل ادمین:       https://${DOMAIN}/admin.html"
echo "   وضعیت بک‌اند:    systemctl status ${SERVICE}"
echo ""
echo "   فلو کار: کاربر ثبت‌نام می‌کند ← در «درخواست‌های تأیید» پنل ادمین تأیید می‌کنید ← وارد پنل کاربری می‌شود."
echo ""
echo "==> [8/8] کرون‌جاب‌های داخلی اینستاگرام (اسنپ‌شات رشد + انتشار زمان‌بندی‌شده) ..."
TOKEN_FILE="${DATADIR}/.internal_token"
if [[ ! -f "$TOKEN_FILE" ]]; then
  openssl rand -hex 32 > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
fi
ITOKEN=$(cat "$TOKEN_FILE")
CRON_SNAP="*/30 * * * * curl -s -m 50 -X POST http://127.0.0.1:${PANEL_PORT}/api/internal/ig/snapshot-all -H \"X-Internal-Token: ${ITOKEN}\" >/dev/null 2>&1"
CRON_RUN="*/15 * * * * curl -s -m 100 -X POST http://127.0.0.1:${PANEL_PORT}/api/internal/ig/run-scheduled -H \"X-Internal-Token: ${ITOKEN}\" >/dev/null 2>&1"
CRON_REPLY="*/15 * * * * curl -s -m 100 -X POST http://127.0.0.1:${PANEL_PORT}/api/internal/ig/autoreply -H \"X-Internal-Token: ${ITOKEN}\" >/dev/null 2>&1"
( crontab -l 2>/dev/null | grep -v "/api/internal/ig/" ; echo "$CRON_SNAP" ; echo "$CRON_RUN" ; echo "$CRON_REPLY" ) | crontab -
echo "   کرون‌ها نصب شدند: اسنپ‌شات هر ۳۰ دقیقه، اجرای زمان‌بندی و پاسخ خودکار هر ۱۵ دقیقه."
