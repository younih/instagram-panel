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
ExecStart=${VENV}/bin/gunicorn app:app --bind 127.0.0.1:8000 --workers 2 --timeout 60
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" || { echo "خطا: سرویس بک‌اند بالا نیامد:"; journalctl -u "$SERVICE" -n 20 --no-pager; exit 1; }
echo "   سرویس بک‌اند فعال است."

echo "==> [6/7] تنظیم nginx برای $DOMAIN ..."
cat > /etc/nginx/sites-available/instagram-panel <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    root ${WEBROOT};
    index index.html;

    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # بک‌اند
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 30s;
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
ln -sf /etc/nginx/sites-available/instagram-panel /etc/nginx/sites-enabled/instagram-panel
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo "==> فعال‌سازی فایروال ..."
ufw --force enable >/dev/null 2>&1 || true
ufw allow 22/tcp comment 'SSH' >/dev/null
ufw allow 80/tcp comment 'HTTP' >/dev/null
ufw allow 443/tcp comment 'HTTPS' >/dev/null

echo "==> [7/7] گواهی HTTPS ..."
# نکته مهم: اسکریپت در مرحله ۶ فایل کانفیگ nginx را از نو می‌نویسد (فقط پورت ۸۰)،
# پس certbot باید همیشه اجرا شود تا بلاک ۴۴۳/HTTPS را دوباره اضافه کند؛
# اگر گواهی موجود باشد certbot فقط نصب را ترمیم می‌کند و گواهی تازه صادر نمی‌کند.
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos \
  --register-unsafely-without-email --redirect
systemctl reload nginx

echo ""
echo "✅ تمام شد!"
echo "   ورود:            https://${DOMAIN}/"
echo "   پنل کاربری:      https://${DOMAIN}/app.html"
echo "   پنل ادمین:       https://${DOMAIN}/admin.html"
echo "   وضعیت بک‌اند:    systemctl status ${SERVICE}"
echo ""
echo "   فلو کار: کاربر ثبت‌نام می‌کند ← در «درخواست‌های تأیید» پنل ادمین تأیید می‌کنید ← وارد پنل کاربری می‌شود."
