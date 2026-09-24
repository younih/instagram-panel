#!/usr/bin/env bash
#
# نصب آسان پنل مدیریت اینستاگرام روی VPS اوبونتو
# اجرا:  sudo ./install.sh panel.example.com
#
# این اسکریپت موارد زیر را انجام می‌دهد:
#   ۱. نصب nginx و certbot
#   ۲. انتشار فایل‌های سایت در /var/www/instagram-panel
#   ۳. ساخت کانفیگ nginx برای ساب‌دامنه
#   ۴. فعال‌سازی فایروال (فقط پورت‌های ۲۲، ۸۰ و ۴۴۳)
#   ۵. دریافت گواهی رایگان HTTPS از Let's Encrypt
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "خطا: لطفاً با sudo اجرا کنید:"
  echo "  sudo ./install.sh panel.example.com"
  exit 1
fi

DOMAIN="${1:?خطا: نام ساب‌دامنه را وارد کنید. مثال: sudo ./install.sh panel.example.com}"

if [[ ! -f ./index.html ]]; then
  echo "خطا: فایل index.html در پوشه جاری پیدا نشد. ابتدا ریپو را clone کنید و داخل آن اجرا کنید."
  exit 1
fi

echo "==> [1/5] به‌روزرسانی سیستم و نصب nginx و certbot ..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx certbot python3-certbot-nginx ufw

echo "==> [2/5] انتشار فایل‌های سایت ..."
WEBROOT="/var/www/instagram-panel"
mkdir -p "$WEBROOT"
cp ./index.html "$WEBROOT/index.html"
chown -R www-data:www-data "$WEBROOT"
chmod -R 755 "$WEBROOT"

echo "==> [3/5] تنظیم nginx برای $DOMAIN ..."
cat > /etc/nginx/sites-available/instagram-panel <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    root ${WEBROOT};
    index index.html;

    # امنیت پایه
    server_tokens off;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

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

echo "==> [4/5] فعال‌سازی فایروال ..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

echo "==> [5/5] دریافت گواهی HTTPS ..."
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos \
  --register-unsafely-without-email --redirect

echo ""
echo "✅ تمام شد! پنل روی https://${DOMAIN} بالا آمد."
