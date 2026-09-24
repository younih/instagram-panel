#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ساخت ادمین اولیه — فقط اگر هیچ ادمینی وجود نداشته باشد.
مقادیر از متغیرهای محیطی خوانده می‌شود:
  PANEL_ADMIN_NAME / PANEL_ADMIN_EMAIL / PANEL_ADMIN_PASSWORD
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import init_db, now_iso, get_db, DATA_DIR  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

init_db()

name = os.environ.get("PANEL_ADMIN_NAME", "مدیر سایت")
email = (os.environ.get("PANEL_ADMIN_EMAIL") or "").strip().lower()
password = os.environ.get("PANEL_ADMIN_PASSWORD") or ""

if not email or not password:
    print("خطا: PANEL_ADMIN_EMAIL و PANEL_ADMIN_PASSWORD باید تنظیم شوند.")
    sys.exit(1)

import sqlite3

db = sqlite3.connect(os.path.join(DATA_DIR, "panel.db"))
exists = db.execute(
    "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
).fetchone()
if exists:
    print("ادمین از قبل وجود دارد؛ چیزی ساخته نشد.")
else:
    db.execute(
        "INSERT INTO users(name, email, password_hash, role, status, created_at)"
        " VALUES (?, ?, ?, 'admin', 'active', ?)",
        (name, email, generate_password_hash(password), now_iso()),
    )
    db.commit()
    print(f"ادمین ساخته شد: {email}")
db.close()
