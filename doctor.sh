#!/usr/bin/env bash
#
# دکتر پنل: عیب‌یابی بک‌اند + تلاش تعمیر خودکار
# اجرا:  cd instagram-panel && git pull && sudo bash doctor.sh
# خروجی کامل را برای پشتیبانی بفرستید.
#
if [[ $EUID -ne 0 ]]; then
  echo "خطا: با sudo اجرا کنید:  sudo bash doctor.sh"
  exit 1
fi

# پورت بک‌اند را از فایل سرویس می‌خوانیم (پیش‌فرض 8000)
PANEL_PORT=$(grep -oP '127\.0\.0\.1:\K[0-9]+' /etc/systemd/system/panel-api.service 2>/dev/null | head -1)
PANEL_PORT=${PANEL_PORT:-8000}
echo "(پورت بک‌اند طبق سرویس: $PANEL_PORT)"

echo "========== ۱) وضعیت سرویس‌ها =========="
if systemctl is-active panel-api --quiet; then echo "panel-api: active ✅"; else echo "panel-api: $(systemctl is-active panel-api) ❌"; fi
if systemctl is-active nginx --quiet; then echo "nginx: active ✅"; else echo "nginx: $(systemctl is-active nginx) ❌"; fi

echo ""
echo "========== ۲) چه چیزی روی پورت ${PANEL_PORT} است؟ =========="
ss -tlnp | grep ":${PANEL_PORT}" || echo "(هیچ‌چیز روی این پورت گوش نمی‌دهد)"

echo ""
echo "========== ۳) سلامت مستقیم بک‌اند =========="
CODE=$(curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:${PANEL_PORT}/api/health 2>/dev/null || echo "000")
echo "http://127.0.0.1:${PANEL_PORT}/api/health -> $CODE  (سالم یعنی 200)"

echo ""
echo "========== ۴) لاگ panel-api (۲۵ خط آخر) =========="
journalctl -u panel-api -n 25 --no-pager --no-hostname 2>/dev/null | tail -25

echo ""
echo "========== ۵) تلاش تعمیر خودکار بک‌اند =========="
if systemctl is-active panel-api --quiet && [[ "$CODE" == "200" ]]; then
  echo "بک‌اند سالم است؛ نیازی به تعمیر نبود. ✅"
else
  LINE=$(ss -tlnp | grep ":${PANEL_PORT}" | head -1)
  if [[ -n "$LINE" ]]; then
    PID=$(echo "$LINE" | grep -oP 'pid=\K[0-9]+' | head -1)
    PROC=$(echo "$LINE" | grep -oP 'users:\(\("\K[^"]+' | head -1)
    echo "پورت ${PANEL_PORT} توسط «${PROC:-نامشخص}» (PID: ${PID:-نامشخص}) اشغال شده و مانع بالا آمدن بک‌اند است."
    read -rp "این پروسه کشته شود؟ [y/N] " ANS
    if [[ "$ANS" =~ ^[yY]$ ]] && [[ -n "$PID" ]]; then
      kill "$PID" && echo "پروسه $PID کشته شد." || echo "کشتن پروسه ناموفق بود."
      sleep 1
    else
      echo "رد شد؛ بدون خالی شدن پورت، بک‌اند روی همین پورت بالا نمی‌آید."
    fi
  fi
  echo "ری‌استارت panel-api ..."
  systemctl restart panel-api
  sleep 6
  if systemctl is-active panel-api --quiet; then echo "panel-api: active ✅"; else echo "panel-api: $(systemctl is-active panel-api) ❌"; fi
  CODE2=$(curl -s -m 5 -o /dev/null -w "%{http_code}" http://127.0.0.1:${PANEL_PORT}/api/health 2>/dev/null || echo "000")
  echo "http://127.0.0.1:${PANEL_PORT}/api/health -> $CODE2"
  if [[ "$CODE2" == "200" ]]; then
    echo "✅ بک‌اند تعمیر شد! حالا لاگین را امتحان کنید."
  else
    echo "❌ بک‌اند هنوز جواب نمی‌دهد؛ خروجی کامل این اسکریپت را بفرستید."
  fi
fi

echo ""
echo "========== ۶) وضعیت nginx برای مسیر /api/ =========="
COUNT=$(nginx -T 2>/dev/null | grep -c "location /api/")
echo "تعداد location /api/ در کانفیگ: $COUNT"
if [[ "$COUNT" -ge 2 ]]; then
  echo "مسیر /api/ هم برای HTTP و هم HTTPS تنظیم است. ✅"
else
  echo "⚠️ مسیر /api/ برای HTTPS تنظیم نیست؛ بعد از سالم شدن بک‌اند، این را اجرا کنید:"
  echo "   cd instagram-panel && git pull && sudo bash install.sh <subdomain>"
fi
echo ""
echo "پایان."
