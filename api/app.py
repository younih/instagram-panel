#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
پنل مدیریت اینستاگرام — بک‌اند
Flask + SQLite — احراز هویت، نقش‌ها (ادمین/کاربر)، تأیید ثبت‌نام توسط ادمین.

اجرا (توسعه):  PANEL_DATA_DIR=./data python3 app.py
اجرا (سرور):   gunicorn app:app --bind 127.0.0.1:8000   (با PANEL_DATA_DIR=/opt/panel/data)
"""

import os
import re
import sqlite3
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve_data_dir():
    env = os.environ.get("PANEL_DATA_DIR")
    if env:
        return env
    if os.path.isdir("/opt/panel/data"):
        return "/opt/panel/data"
    return os.path.join(BASE_DIR, "data")


DATA_DIR = resolve_data_dir()
DB_PATH = os.path.join(DATA_DIR, "panel.db")
SECRET_PATH = os.path.join(DATA_DIR, "secret.key")

app = Flask(__name__)


def load_secret():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(SECRET_PATH):
        with open(SECRET_PATH, "w") as f:
            f.write(secrets.token_hex(32))
        os.chmod(SECRET_PATH, 0o600)
    with open(SECRET_PATH, "r") as f:
        return f.read().strip()


app.secret_key = load_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)
# پشت nginx هستیم؛ طرح/هاست واقعی را از هدرهای X-Forwarded بخوان
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

STATUS_LABELS = {
    "pending": "در انتظار تأیید",
    "active": "فعال",
    "rejected": "رد شده",
    "disabled": "غیرفعال",
}


# ---------------------------------------------------------------- دیتابیس
def get_db():
    if "db" not in g:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g.db = db
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """ساخت جداول (idempotent) + تنظیمات پیش‌فرض."""
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT NOT NULL,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            status        TEXT NOT NULL DEFAULT 'pending',
            created_at    TEXT NOT NULL,
            last_login    TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_users_email  ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ig_accounts (
            user_id      INTEGER PRIMARY KEY,
            username     TEXT NOT NULL,
            enc_secret   TEXT NOT NULL,
            connected_at TEXT NOT NULL,
            updated_at   TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    # مهاجرت از نسخه قدیمی (ستون enc_password) — فقط اگر وجود داشت
    cols = {r[1] for r in db.execute("PRAGMA table_info(ig_accounts)")}
    if "enc_password" in cols and "enc_secret" not in cols:
        db.execute("ALTER TABLE ig_accounts RENAME COLUMN enc_password TO enc_secret")
        db.commit()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS ig_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            followers   INTEGER NOT NULL DEFAULT 0,
            following   INTEGER NOT NULL DEFAULT 0,
            media_count INTEGER NOT NULL DEFAULT 0,
            taken_at    TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ig_snapshots_user ON ig_snapshots(user_id, taken_at);

        CREATE TABLE IF NOT EXISTS ig_scheduled (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            photo_path   TEXT NOT NULL,
            caption      TEXT NOT NULL DEFAULT '',
            publish_at   TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            attempts     INTEGER NOT NULL DEFAULT 0,
            error        TEXT,
            media_id     TEXT,
            created_at   TEXT NOT NULL,
            published_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_ig_scheduled_due ON ig_scheduled(status, publish_at);

        CREATE TABLE IF NOT EXISTS yt_accounts (
            user_id       INTEGER PRIMARY KEY,
            channel_id    TEXT NOT NULL,
            channel_title TEXT NOT NULL DEFAULT '',
            thumb         TEXT NOT NULL DEFAULT '',
            enc_tokens    TEXT NOT NULL,
            connected_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )
    db.commit()
    defaults = {
        "site_name": "پنل مدیریت اینستاگرام",
        "announcement": "",
        "google_client_id": "",
        "google_client_secret": "",
        "public_base_url": "",
    }
    for k, v in defaults.items():
        db.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
    db.commit()
    db.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def user_to_dict(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "role": row["role"],
        "status": row["status"],
        "status_label": STATUS_LABELS.get(row["status"], row["status"]),
        "created_at": row["created_at"],
        "last_login": row["last_login"],
    }


def get_user_by_id(uid):
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return user_to_dict(row) if row else None


def get_user_by_email(email):
    row = (
        get_db()
        .execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
        .fetchone()
    )
    return row


# ---------------------------------------------------------------- کمک‌ها
def ok(**data):
    payload = {"ok": True}
    payload.update(data)
    return jsonify(payload)


def err(message, code="error", http=400):
    return jsonify({"ok": False, "error": code, "message": message}), http


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        uid = session.get("uid")
        if not uid:
            return err("وارد نشده‌اید. لطفاً ابتدا وارد شوید.", "unauthorized", 401)
        me = get_user_by_id(uid)
        if not me or me["status"] != "active":
            session.clear()
            return err("نشست شما معتبر نیست.", "unauthorized", 401)
        g.me = me
        return fn(*a, **kw)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        uid = session.get("uid")
        if not uid:
            return err("وارد نشده‌اید.", "unauthorized", 401)
        me = get_user_by_id(uid)
        if not me or me["status"] != "active" or me["role"] != "admin":
            return err("دسترسی مدیر لازم است.", "forbidden", 403)
        g.me = me
        return fn(*a, **kw)

    return wrapper


# ---------------------------------------------------------------- عمومی
@app.get("/api/public/site")
def public_site():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    return ok(site={r["key"]: r["value"] for r in rows})


# ---------------------------------------------------------------- احراز هویت
@app.post("/api/auth/signup")
def signup():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not name:
        return err("نام را وارد کنید.", "validation")
    if not EMAIL_RE.match(email):
        return err("نشانی ایمیل معتبر نیست.", "validation")
    if len(password) < 8:
        return err("گذرواژه باید حداقل ۸ کاراکتر باشد.", "validation")

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
        return err("این ایمیل قبلاً ثبت شده است؛ وارد شوید.", "duplicate", 409)

    db.execute(
        "INSERT INTO users(name, email, password_hash, role, status, created_at)"
        " VALUES (?, ?, ?, 'user', 'pending', ?)",
        (name, email, generate_password_hash(password), now_iso()),
    )
    db.commit()
    return ok(message="ثبت‌نام انجام شد؛ حساب شما پس از تأیید مدیر فعال می‌شود."), 201


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    row = get_user_by_email(email)
    if not row or not check_password_hash(row["password_hash"], password):
        return err("ایمیل یا گذرواژه اشتباه است.", "bad_credentials", 401)

    status = row["status"]
    if status == "pending":
        return err(
            "حساب شما در انتظار تأیید مدیر است؛ پس از تأیید می‌توانید وارد شوید.",
            "pending",
            403,
        )
    if status == "rejected":
        return err("درخواست عضویت شما رد شده است.", "rejected", 403)
    if status == "disabled":
        return err("حساب شما غیرفعال شده است؛ با مدیر در تماس باشید.", "disabled", 403)

    session.clear()
    session["uid"] = row["id"]
    session.permanent = True
    get_db().execute(
        "UPDATE users SET last_login = ? WHERE id = ?", (now_iso(), row["id"])
    )
    get_db().commit()
    return ok(user=user_to_dict(row))


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return ok(message="خارج شدید.")


@app.get("/api/auth/me")
def me():
    uid = session.get("uid")
    if not uid:
        return err("وارد نشده‌اید.", "unauthorized", 401)
    user = get_user_by_id(uid)
    if not user or user["status"] != "active":
        session.clear()
        return err("نشست معتبر نیست.", "unauthorized", 401)
    return ok(user=user)


# ---------------------------------------------------------------- پنل کاربری
@app.get("/api/user/profile")
@login_required
def user_profile():
    return ok(user=g.me)


@app.put("/api/user/profile")
@login_required
def user_profile_update():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""

    db = get_db()
    if name:
        db.execute("UPDATE users SET name = ? WHERE id = ?", (name, g.me["id"]))
    if new_password:
        row = db.execute(
            "SELECT password_hash FROM users WHERE id = ?", (g.me["id"],)
        ).fetchone()
        if not check_password_hash(row["password_hash"], current_password):
            return err("گذرواژه فعلی اشتباه است.", "bad_password", 403)
        if len(new_password) < 8:
            return err("گذرواژه جدید باید حداقل ۸ کاراکتر باشد.", "validation")
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), g.me["id"]),
        )
    db.commit()
    return ok(user=get_user_by_id(g.me["id"]), message="پروفایل به‌روزرسانی شد.")


# ---------------------------------------------------------------- پنل ادمین
@app.get("/api/admin/stats")
@admin_required
def admin_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    by_status = {
        r["status"]: r["c"]
        for r in db.execute(
            "SELECT status, COUNT(*) c FROM users GROUP BY status"
        ).fetchall()
    }
    admins = db.execute(
        "SELECT COUNT(*) c FROM users WHERE role='admin' AND status='active'"
    ).fetchone()["c"]
    recent = [
        user_to_dict(r)
        for r in db.execute(
            "SELECT * FROM users ORDER BY id DESC LIMIT 5"
        ).fetchall()
    ]
    return ok(
        stats={
            "total": total,
            "pending": by_status.get("pending", 0),
            "active": by_status.get("active", 0),
            "rejected": by_status.get("rejected", 0),
            "disabled": by_status.get("disabled", 0),
            "admins": admins,
        },
        recent=recent,
    )


@app.get("/api/admin/users")
@admin_required
def admin_users():
    status = request.args.get("status")
    db = get_db()
    if status in STATUS_LABELS:
        rows = db.execute(
            "SELECT * FROM users WHERE status = ? ORDER BY id DESC", (status,)
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return ok(users=[user_to_dict(r) for r in rows])


def _change_status(uid, new_status):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return err("کاربر پیدا نشد.", "not_found", 404)
    if row["id"] == g.me["id"]:
        return err("نمی‌توانید وضعیت حساب خودتان را تغییر دهید.", "self_action", 403)
    db.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, uid))
    db.commit()
    return ok(user=get_user_by_id(uid))


@app.post("/api/admin/users/<int:uid>/approve")
@admin_required
def admin_approve(uid):
    return _change_status(uid, "active")


@app.post("/api/admin/users/<int:uid>/reject")
@admin_required
def admin_reject(uid):
    return _change_status(uid, "rejected")


@app.post("/api/admin/users/<int:uid>/disable")
@admin_required
def admin_disable(uid):
    return _change_status(uid, "disabled")


@app.post("/api/admin/users/<int:uid>/enable")
@admin_required
def admin_enable(uid):
    return _change_status(uid, "active")


@app.put("/api/admin/users/<int:uid>")
@admin_required
def admin_update_user(uid):
    data = request.get_json(silent=True) or {}
    role = data.get("role")
    if role not in ("user", "admin"):
        return err("نقش معتبر نیست.", "validation")
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return err("کاربر پیدا نشد.", "not_found", 404)
    if row["id"] == g.me["id"] and role != "admin":
        return err("نمی‌توانید نقش ادمین خودتان را بردارید.", "self_action", 403)
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
    db.commit()
    return ok(user=get_user_by_id(uid))


@app.delete("/api/admin/users/<int:uid>")
@admin_required
def admin_delete_user(uid):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return err("کاربر پیدا نشد.", "not_found", 404)
    if row["id"] == g.me["id"]:
        return err("نمی‌توانید حساب خودتان را حذف کنید.", "self_action", 403)
    if row["role"] == "admin" and row["status"] == "active":
        remaining = db.execute(
            "SELECT COUNT(*) c FROM users WHERE role='admin' AND status='active' AND id != ?",
            (uid,),
        ).fetchone()["c"]
        if remaining == 0:
            return err("آخرین ادمین فعال را نمی‌توان حذف کرد.", "last_admin", 403)
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    return ok(message="کاربر حذف شد.")


@app.get("/api/admin/settings")
@admin_required
def admin_settings_get():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    return ok(settings={r["key"]: r["value"] for r in rows})


@app.put("/api/admin/settings")
@admin_required
def admin_settings_put():
    data = request.get_json(silent=True) or {}
    allowed = {"site_name", "announcement", "google_client_id", "google_client_secret", "public_base_url"}
    db = get_db()
    for k in allowed:
        if k in data:
            v = str(data[k] or "").strip()
            if k == "site_name" and not v:
                return err("نام سایت نمی‌تواند خالی باشد.", "validation")
            db.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, v),
            )
    db.commit()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    return ok(settings={r["key"]: r["value"] for r in rows}, message="تنظیمات ذخیره شد.")


# ---------------------------------------------------------------- اینستاگرام واقعی
# اتصال اکانت واقعی اینستاگرام با sessionid (کوکی نشست وب).
# چرا sessionid؟ لاگین یوزر/پسورد با کتابخانه‌ها روی بعضی IPها توسط اینستاگرام
# با خطای «نسخه اپ قدیمی است» بلاک می‌شود؛ ولی sessionid که کاربر از مرورگر
# خودش (بعد از لاگین عادی در instagram.com) کپی می‌کند، این محدودیت را ندارد.
# sessionid با Fernet روی همین سرور رمزنگاری و ذخیره می‌شود.
import threading
import time

_ig_lock = threading.RLock()
_ig_clients = {}  # uid -> {"cl": Client, "at": timestamp}
_IG_TTL = 20 * 60  # ۲۰ دقیقه استفاده مجدد از کلاینت


def _ig_fernet():
    from cryptography.fernet import Fernet

    kp = os.path.join(DATA_DIR, ".ig_key")
    if os.path.exists(kp):
        with open(kp, "rb") as f:
            key = f.read().strip()
    else:
        key = Fernet.generate_key()
        with open(kp, "wb") as f:
            f.write(key)
        os.chmod(kp, 0o600)
    return Fernet(key)


def _ig_creds(uid):
    row = (
        get_db()
        .execute(
            "SELECT username, enc_secret FROM ig_accounts WHERE user_id = ?", (uid,)
        )
        .fetchone()
    )
    if not row:
        return None, None
    try:
        secret = _ig_fernet().decrypt(row["enc_secret"].encode()).decode()
    except Exception:
        return row["username"], None
    return row["username"], secret


def _ig_client(uid):
    """کلاینت لاگین‌شده با sessionid؛ حداکثر ۲۰ دقیقه کش می‌شود."""
    from instagrapi import Client

    username, secret = _ig_creds(uid)
    if not username or not secret:
        return None
    now = time.time()
    with _ig_lock:
        cached = _ig_clients.get(uid)
        if cached and now - cached["at"] < _IG_TTL:
            return cached["cl"]
        cl = Client(request_timeout=15)
        cl.delay_range = [1, 3]
        try:
            cl.login_by_sessionid(secret)  # خودش با user_info اعتبارسنجی می‌کند
        except Exception:
            _ig_clients.pop(uid, None)
            raise
        _ig_clients[uid] = {"cl": cl, "at": now}
        return cl


def _ig_errmap(e):
    from instagrapi.exceptions import (
        ClientError,
        ClientLoginRequired,
        ClientRequestTimeout,
        LoginRequired,
        PleaseWaitFewMinutes,
    )

    if isinstance(e, AssertionError):
        return (
            "sessionid معتبر نیست؛ از مرورگر کپی‌اش کن (باید با عدد شروع شود و طولانی باشد).",
            "invalid_sessionid",
            401,
        )
    if isinstance(e, (LoginRequired, ClientLoginRequired)):
        return (
            "نشست اینستاگرام منقضی شده؛ دوباره وارد instagram.com شو و sessionid جدید بده.",
            "session_expired",
            401,
        )
    if isinstance(e, ClientRequestTimeout):
        return (
            "اینستاگرام به‌موقع جواب نداد؛ اتصال اینترنت سرور را بررسی کن و دوباره تلاش کن.",
            "ig_timeout",
            504,
        )
    if isinstance(e, PleaseWaitFewMinutes):
        return (
            "اینستاگرام موقتاً محدودت کرد؛ چند دقیقه دیگر تلاش کن.",
            "rate_limited",
            429,
        )
    if isinstance(e, ClientError):
        return (f"خطای اینستاگرام: {e}", "ig_error", 502)
    return (f"خطای غیرمنتظره: {e}", "ig_error", 502)


@app.post("/api/ig/connect")
@login_required
def ig_connect():
    from instagrapi import Client

    data = request.get_json(silent=True) or {}
    sessionid = (data.get("sessionid") or "").strip()
    if not sessionid:
        return err("sessionid را وارد کنید.", "validation")
    # اعتبارسنجی واقعی: تزریق کوکی و خواندن پروفایل
    cl = Client(request_timeout=15)
    cl.delay_range = [1, 3]
    try:
        with _ig_lock:
            cl.login_by_sessionid(sessionid)
            username = cl.username
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)

    enc = _ig_fernet().encrypt(sessionid.encode()).decode()
    uid = g.me["id"]
    db = get_db()
    db.execute(
        "INSERT INTO ig_accounts(user_id, username, enc_secret, connected_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT(user_id) DO UPDATE SET username=excluded.username,"
        " enc_secret=excluded.enc_secret, updated_at=excluded.updated_at",
        (uid, username, enc, now_iso(), now_iso()),
    )
    db.commit()
    with _ig_lock:
        _ig_clients[uid] = {"cl": cl, "at": time.time()}
    return ok(username=username, message="اکانت اینستاگرام متصل شد.")


@app.post("/api/ig/disconnect")
@login_required
def ig_disconnect():
    uid = g.me["id"]
    get_db().execute("DELETE FROM ig_accounts WHERE user_id = ?", (uid,))
    get_db().commit()
    with _ig_lock:
        _ig_clients.pop(uid, None)
    # پاک‌سازی نشست‌های قدیمی نسخه قبلی (اگر مانده باشند)
    sp = os.path.join(DATA_DIR, "ig_sessions", f"{uid}.json")
    if os.path.exists(sp):
        try:
            os.remove(sp)
        except OSError:
            pass
    return ok(message="اتصال اینستاگرام قطع شد.")


@app.get("/api/ig/status")
@login_required
def ig_status():
    username, _ = _ig_creds(g.me["id"])
    return ok(connected=bool(username), username=username)


@app.get("/api/ig/profile")
@login_required
def ig_profile():
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            u = cl.user_info(cl.user_id)
        return ok(
            profile={
                "username": u.username,
                "full_name": u.full_name or "",
                "biography": u.biography or "",
                "profile_pic_url": str(u.profile_pic_url or ""),
                "follower_count": u.follower_count or 0,
                "following_count": u.following_count or 0,
                "media_count": u.media_count or 0,
                "is_private": bool(u.is_private),
                "is_verified": bool(u.is_verified),
            }
        )
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.get("/api/ig/medias")
@login_required
def ig_medias():
    try:
        limit = int(request.args.get("limit", 12))
    except (TypeError, ValueError):
        limit = 12
    limit = min(max(limit, 1), 30)
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            medias = cl.user_medias(cl.user_id, limit)
        out = []
        for m in medias:
            out.append(
                {
                    "id": str(m.pk),
                    "code": m.code,
                    "media_type": m.media_type,  # 1=عکس 2=ویدیو 8=آلبوم
                    "thumbnail_url": str(m.thumbnail_url or ""),
                    "like_count": m.like_count or 0,
                    "comment_count": m.comment_count or 0,
                    "has_liked": bool(m.has_liked),
                    "caption": (m.caption_text or "")[:180],
                    "taken_at": m.taken_at.isoformat() if m.taken_at else None,
                }
            )
        return ok(medias=out)
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


def _ig_action(media_id, action):
    from instagrapi import Client  # noqa: F401 (ثبت وابستگی)
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    if not media_id:
        return err("شناسه پست مشخص نیست.", "validation")
    try:
        with _ig_lock:
            if action == "like":
                cl.media_like(media_id)
            else:
                cl.media_unlike(media_id)
        return ok(message="لایک شد." if action == "like" else "لایک برداشته شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.post("/api/ig/like")
@login_required
def ig_like():
    data = request.get_json(silent=True) or {}
    return _ig_action((data.get("media_id") or "").strip(), "like")


@app.post("/api/ig/unlike")
@login_required
def ig_unlike():
    data = request.get_json(silent=True) or {}
    return _ig_action((data.get("media_id") or "").strip(), "unlike")


# ---------------------------------------------------------------- آنالیز اینستاگرام
def _ig_record_snapshot(uid, followers, following, media_count):
    """ثبت اسنپ‌شات رشد؛ اگر کمتر از ۱۰ دقیقه از قبلی گذشته، رد می‌کند."""
    db = get_db()
    row = db.execute(
        "SELECT taken_at FROM ig_snapshots WHERE user_id = ? ORDER BY taken_at DESC LIMIT 1",
        (uid,),
    ).fetchone()
    if row:
        try:
            last = datetime.fromisoformat(row["taken_at"])
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - last < timedelta(minutes=10):
                return False
        except (ValueError, TypeError):
            pass
    db.execute(
        "INSERT INTO ig_snapshots(user_id, followers, following, media_count, taken_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (uid, followers, following, media_count, now_iso()),
    )
    db.commit()
    return True


def _ig_taken_iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _ig_media_sum(m):
    return {
        "id": str(m.pk),
        "code": m.code,
        "thumbnail_url": str(m.thumbnail_url or ""),
        "like_count": m.like_count or 0,
        "comment_count": m.comment_count or 0,
        "caption": (m.caption_text or "")[:140],
        "taken_at": _ig_taken_iso(m.taken_at),
    }


@app.get("/api/ig/stats")
@login_required
def ig_stats():
    uid = g.me["id"]
    cl = _ig_client(uid)
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            u = cl.user_info(cl.user_id)
            medias = cl.user_medias(cl.user_id, 30)
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)
    followers = u.follower_count or 0
    _ig_record_snapshot(uid, followers, u.following_count or 0, u.media_count or 0)
    recent = medias[:12]
    inter = sum((m.like_count or 0) + (m.comment_count or 0) for m in recent)
    eng = round(inter / len(recent) / followers * 100, 2) if recent and followers else 0
    best = sorted(medias, key=lambda m: (m.like_count or 0) + (m.comment_count or 0), reverse=True)[:6]
    snaps = get_db().execute(
        "SELECT taken_at, followers, following, media_count FROM ig_snapshots"
        " WHERE user_id = ? ORDER BY taken_at",
        (uid,),
    ).fetchall()
    return ok(
        stats={
            "followers": followers,
            "following": u.following_count or 0,
            "media_count": u.media_count or 0,
            "engagement_rate": eng,
            "snapshots": [dict(s) for s in snaps],
            "best_posts": [_ig_media_sum(m) for m in best],
            "recent": [
                {
                    "id": str(m.pk),
                    "taken_at": _ig_taken_iso(m.taken_at),
                    "like_count": m.like_count or 0,
                    "comment_count": m.comment_count or 0,
                }
                for m in medias
            ],
        }
    )


@app.post("/api/ig/snapshot")
@login_required
def ig_snapshot():
    uid = g.me["id"]
    cl = _ig_client(uid)
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            u = cl.user_info(cl.user_id)
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)
    saved = _ig_record_snapshot(uid, u.follower_count or 0, u.following_count or 0, u.media_count or 0)
    return ok(message="اسنپ‌شات ثبت شد." if saved else "اسنپ‌شات تازه‌ای ثبت شده بود.")


# ---------------------------------------------------------------- فالوور / فالووینگ
def _ig_user_short(u):
    return {
        "pk": str(u.pk),
        "username": u.username,
        "full_name": u.full_name or "",
        "profile_pic_url": str(u.profile_pic_url or ""),
        "is_private": bool(u.is_private),
        "is_verified": bool(u.is_verified),
    }


def _ig_social(kind):
    try:
        amount = min(max(int(request.args.get("amount", 100)), 1), 200)
    except (TypeError, ValueError):
        amount = 100
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            if kind == "followers":
                data = cl.user_followers(cl.user_id, amount=amount)
            else:
                data = cl.user_following(cl.user_id, amount=amount)
        return ok(users=[_ig_user_short(u) for u in data.values()], count=len(data))
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.get("/api/ig/followers")
@login_required
def ig_followers():
    return _ig_social("followers")


@app.get("/api/ig/following")
@login_required
def ig_following():
    return _ig_social("following")


def _ig_social_action(action):
    data = request.get_json(silent=True) or {}
    target = str(data.get("user_id") or "").strip()
    if not target.isdigit():
        return err("کاربر مشخص نیست.", "validation")
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            res = cl.user_follow(target) if action == "follow" else cl.user_unfollow(target)
        return ok(result=bool(res), message="انجام شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.post("/api/ig/follow")
@login_required
def ig_follow():
    return _ig_social_action("follow")


@app.post("/api/ig/unfollow")
@login_required
def ig_unfollow():
    return _ig_social_action("unfollow")


# ---------------------------------------------------------------- کامنت‌ها
@app.get("/api/ig/comments")
@login_required
def ig_comments():
    media_id = (request.args.get("media_id") or "").strip()
    if not media_id:
        return err("پست مشخص نیست.", "validation")
    try:
        amount = min(max(int(request.args.get("amount", 30)), 1), 100)
    except (TypeError, ValueError):
        amount = 30
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            comments = cl.media_comments(media_id, amount=amount)
        out = []
        for c in comments:
            usr = c.user
            out.append(
                {
                    "pk": str(c.pk),
                    "text": c.text or "",
                    "username": usr.username if usr else "",
                    "profile_pic_url": str(usr.profile_pic_url) if usr and usr.profile_pic_url else "",
                    "like_count": c.like_count or 0,
                    "has_liked": bool(c.has_liked),
                    "created_at": _ig_taken_iso(c.created_at_utc),
                }
            )
        return ok(comments=out, count=len(out))
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.post("/api/ig/comment")
@login_required
def ig_comment_add():
    data = request.get_json(silent=True) or {}
    media_id = (data.get("media_id") or "").strip()
    text = (data.get("text") or "").strip()
    if not media_id or not text:
        return err("متن کامنت و پست مشخص نیست.", "validation")
    if len(text) > 2200:
        return err("متن کامنت خیلی طولانی است.", "validation")
    replied_to = str(data.get("replied_to") or "").strip()
    replied_to_id = int(replied_to) if replied_to.isdigit() else None
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            c = cl.media_comment(media_id, text, replied_to_comment_id=replied_to_id)
        return ok(comment_id=str(c.pk), message="کامنت ثبت شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.post("/api/ig/comment/delete")
@login_required
def ig_comment_delete():
    data = request.get_json(silent=True) or {}
    media_id = (data.get("media_id") or "").strip()
    comment_id = str(data.get("comment_id") or "").strip()
    if not media_id or not comment_id.isdigit():
        return err("مشخصات کامنت ناقص است.", "validation")
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            cl.comment_bulk_delete(media_id, [int(comment_id)])
        return ok(message="کامنت حذف شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.post("/api/ig/comment/like")
@login_required
def ig_comment_like():
    data = request.get_json(silent=True) or {}
    comment_id = str(data.get("comment_id") or "").strip()
    like = bool(data.get("like", True))
    if not comment_id.isdigit():
        return err("کامنت مشخص نیست.", "validation")
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            if like:
                cl.comment_like(int(comment_id))
            else:
                cl.comment_unlike(int(comment_id))
        return ok(message="انجام شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


# ---------------------------------------------------------------- دایرکت
@app.get("/api/ig/threads")
@login_required
def ig_threads():
    try:
        amount = min(max(int(request.args.get("amount", 20)), 1), 50)
    except (TypeError, ValueError):
        amount = 20
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            threads = cl.direct_threads(amount=amount)
        out = []
        for t in threads:
            tid = t.id or t.pk
            users = [
                {
                    "pk": str(x.pk),
                    "username": x.username,
                    "profile_pic_url": str(x.profile_pic_url or ""),
                }
                for x in (t.users or [])
            ]
            title = t.thread_title or ", ".join(x["username"] for x in users[:3])
            out.append(
                {
                    "id": str(tid),
                    "title": title,
                    "users": users,
                    "is_group": bool(t.is_group),
                    "last_activity_at": _ig_taken_iso(t.last_activity_at),
                }
            )
        return ok(threads=out)
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.get("/api/ig/thread/messages")
@login_required
def ig_thread_messages():
    thread_id = (request.args.get("thread_id") or "").strip()
    if not thread_id.isdigit():
        return err("گفتگو مشخص نیست.", "validation")
    try:
        amount = min(max(int(request.args.get("amount", 30)), 1), 100)
    except (TypeError, ValueError):
        amount = 30
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            msgs = cl.direct_messages(int(thread_id), amount=amount)
        out = []
        for m in msgs:
            out.append(
                {
                    "id": str(m.id),
                    "text": m.text or "",
                    "user_id": str(m.user_id or ""),
                    "is_mine": bool(m.is_sent_by_viewer),
                    "item_type": m.item_type or "text",
                    "timestamp": _ig_taken_iso(m.timestamp),
                }
            )
        out.sort(key=lambda x: x["timestamp"] or "")
        return ok(messages=out)
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


@app.post("/api/ig/thread/send")
@login_required
def ig_thread_send():
    data = request.get_json(silent=True) or {}
    thread_id = str(data.get("thread_id") or "").strip()
    text = (data.get("text") or "").strip()
    if not thread_id.isdigit() or not text:
        return err("متن پیام و گفتگو مشخص نیست.", "validation")
    if len(text) > 1000:
        return err("متن پیام خیلی طولانی است.", "validation")
    cl = _ig_client(g.me["id"])
    if not cl:
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            m = cl.direct_send(text, thread_ids=[int(thread_id)])
        return ok(message_id=str(m.id), message="ارسال شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)


# ---------------------------------------------------------------- انتشار و زمان‌بندی
def _ig_save_upload(file_storage):
    if not file_storage or not file_storage.filename:
        raise ValueError("فایل عکس انتخاب نشده است.")
    ext = os.path.splitext(file_storage.filename.lower())[1]
    if ext not in (".jpg", ".jpeg", ".png", ".webp"):
        raise ValueError("فقط عکس (jpg/png/webp) قابل انتشار است.")
    data = file_storage.read()
    if len(data) > 10 * 1024 * 1024:
        raise ValueError("حجم عکس حداکثر ۱۰ مگابایت باشد.")
    if len(data) < 1024:
        raise ValueError("فایل معتبر نیست.")
    d = os.path.join(DATA_DIR, "ig_uploads")
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, f"{uuid.uuid4().hex}{ext}")
    with open(p, "wb") as f:
        f.write(data)
    return p


@app.post("/api/ig/publish")
@login_required
def ig_publish():
    from pathlib import Path

    caption = (request.form.get("caption") or "").strip()
    if len(caption) > 2200:
        return err("کپشن خیلی طولانی است.", "validation")
    try:
        path = _ig_save_upload(request.files.get("photo"))
    except ValueError as e:
        return err(str(e), "validation")
    cl = _ig_client(g.me["id"])
    if not cl:
        try:
            os.remove(path)
        except OSError:
            pass
        return err("اکانت اینستاگرام متصل نیست.", "not_connected", 404)
    try:
        with _ig_lock:
            media = cl.photo_upload(Path(path), caption)
        return ok(media_id=str(media.pk), code=media.code, message="پست منتشر شد.")
    except Exception as e:
        msg, code_name, http = _ig_errmap(e)
        return err(msg, code_name, http)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


@app.post("/api/ig/schedule")
@login_required
def ig_schedule():
    caption = (request.form.get("caption") or "").strip()
    publish_at = (request.form.get("publish_at") or "").strip()
    if len(caption) > 2200:
        return err("کپشن خیلی طولانی است.", "validation")
    try:
        dt = datetime.fromisoformat(publish_at.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return err("زمان انتشار معتبر نیست.", "validation")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if dt <= now:
        return err("زمان انتشار باید در آینده باشد.", "validation")
    if dt > now + timedelta(days=30):
        return err("زمان‌بندی حداکثر تا ۳۰ روز آینده.", "validation")
    try:
        path = _ig_save_upload(request.files.get("photo"))
    except ValueError as e:
        return err(str(e), "validation")
    db = get_db()
    cur = db.execute(
        "INSERT INTO ig_scheduled(user_id, photo_path, caption, publish_at, status, created_at)"
        " VALUES (?, ?, ?, ?, 'pending', ?)",
        (g.me["id"], path, caption, dt.astimezone(timezone.utc).isoformat(), now_iso()),
    )
    db.commit()
    return ok(id=cur.lastrowid, message="زمان‌بندی ثبت شد.")


@app.get("/api/ig/scheduled")
@login_required
def ig_scheduled_list():
    rows = get_db().execute(
        "SELECT id, caption, publish_at, status, error, attempts, created_at, published_at, media_id"
        " FROM ig_scheduled WHERE user_id = ? ORDER BY publish_at",
        (g.me["id"],),
    ).fetchall()
    items = []
    for r in rows:
        d = dict(r)
        d["caption"] = (d["caption"] or "")[:120]
        items.append(d)
    return ok(items=items)


@app.post("/api/ig/scheduled/delete")
@login_required
def ig_scheduled_delete():
    data = request.get_json(silent=True) or {}
    sid = data.get("id")
    if not isinstance(sid, int):
        return err("مورد مشخص نیست.", "validation")
    db = get_db()
    row = db.execute(
        "SELECT photo_path, status FROM ig_scheduled WHERE id = ? AND user_id = ?",
        (sid, g.me["id"]),
    ).fetchone()
    if not row:
        return err("یافت نشد.", "not_found", 404)
    if row["status"] != "pending":
        return err("فقط زمان‌بندیِ در انتظار حذف می‌شود.", "validation")
    db.execute("DELETE FROM ig_scheduled WHERE id = ?", (sid,))
    db.commit()
    try:
        os.remove(row["photo_path"])
    except OSError:
        pass
    return ok(message="حذف شد.")


# ---------------------------------------------------------------- اندپوینت‌های داخلی (کرون سرور)
def _ig_internal_token():
    p = os.path.join(DATA_DIR, ".internal_token")
    if os.path.exists(p):
        with open(p) as f:
            return f.read().strip()
    tok = secrets.token_hex(32)
    with open(p, "w") as f:
        f.write(tok)
    os.chmod(p, 0o600)
    return tok


def _internal_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if request.headers.get("X-Internal-Token") != _ig_internal_token():
            return err("forbidden", "forbidden", 403)
        return fn(*a, **kw)

    return wrapper


@app.post("/api/internal/ig/snapshot-all")
@_internal_required
def internal_snapshot_all():
    from instagrapi import Client

    rows = get_db().execute("SELECT user_id, enc_secret FROM ig_accounts").fetchall()
    done, failed = 0, 0
    for r in rows:
        try:
            secret = _ig_fernet().decrypt(r["enc_secret"].encode()).decode()
            cl = Client(request_timeout=15)
            cl.delay_range = [1, 3]
            cl.login_by_sessionid(secret)
            with _ig_lock:
                u = cl.user_info(cl.user_id)
            _ig_record_snapshot(
                r["user_id"], u.follower_count or 0, u.following_count or 0, u.media_count or 0
            )
            done += 1
        except Exception:
            failed += 1
    return ok(done=done, failed=failed)


@app.post("/api/internal/ig/run-scheduled")
@_internal_required
def internal_run_scheduled():
    from pathlib import Path

    now = now_iso()
    rows = get_db().execute(
        "SELECT id, user_id, photo_path, caption, attempts FROM ig_scheduled"
        " WHERE status = 'pending' AND publish_at <= ?",
        (now,),
    ).fetchall()
    results = []
    for r in rows:
        try:
            cl = _ig_client(r["user_id"])
            if not cl:
                raise RuntimeError("اکانت اینستاگرام متصل نیست")
            if not os.path.exists(r["photo_path"]):
                raise RuntimeError("فایل عکس پیدا نشد")
            with _ig_lock:
                media = cl.photo_upload(Path(r["photo_path"]), r["caption"] or "")
            get_db().execute(
                "UPDATE ig_scheduled SET status = 'sent', published_at = ?, media_id = ? WHERE id = ?",
                (now_iso(), str(media.pk), r["id"]),
            )
            try:
                os.remove(r["photo_path"])
            except OSError:
                pass
            results.append({"id": r["id"], "ok": True})
        except Exception as e:
            attempts = (r["attempts"] or 0) + 1
            status = "failed" if attempts >= 3 else "pending"
            get_db().execute(
                "UPDATE ig_scheduled SET attempts = ?, status = ?, error = ? WHERE id = ?",
                (attempts, status, str(e)[:300], r["id"]),
            )
            results.append({"id": r["id"], "ok": False})
    get_db().commit()
    return ok(results=results)


# ---------------------------------------------------------------- یوتیوب (OAuth گوگل)
# اتصال واقعی کانال یوتیوب با Google OAuth 2.0 — فقط خواندنی (آمار کانال و ویدیوها).
# پیش‌نیاز (یک‌بار توسط ادمین):
#   1) ساخت OAuth Client ID از نوع Web در Google Cloud + فعال‌سازی YouTube Data API v3
#   2) ثبت redirect URI دقیق: https://<subdomain>/api/yt/oauth/callback
#   3) وارد کردن Client ID/Secret در تنظیمات پنل ادمین (+ آدرس عمومی سایت)
# توکن‌ها با Fernet رمزنگاری و در yt_accounts ذخیره می‌شوند؛ access token
# به‌صورت خودکار با refresh token تمدید می‌شود.
import json as _json
import urllib.parse as _urlparse
import urllib.request as _urlreq

_YT_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_YT_TOKEN_URL = "https://oauth2.googleapis.com/token"
_YT_REVOKE_URL = "https://oauth2.googleapis.com/revoke"
_YT_API = "https://www.googleapis.com/youtube/v3"
_YT_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/youtube.readonly",
]

_yt_states = {}  # state -> {"uid": int, "at": float}
_yt_state_lock = threading.RLock()


def _yt_settings():
    rows = get_db().execute("SELECT key, value FROM settings").fetchall()
    s = {r["key"]: r["value"] for r in rows}
    return {
        "client_id": (s.get("google_client_id") or "").strip(),
        "client_secret": (s.get("google_client_secret") or "").strip(),
        "base_url": (s.get("public_base_url") or "").strip().rstrip("/"),
    }


def _yt_redirect_uri():
    base = _yt_settings()["base_url"]
    if base:
        return base + "/api/yt/oauth/callback"
    return request.url_root.rstrip("/") + "/api/yt/oauth/callback"


def _yt_configured():
    s = _yt_settings()
    return bool(s["client_id"] and s["client_secret"])


def _yt_tokens_row(uid):
    return get_db().execute("SELECT * FROM yt_accounts WHERE user_id = ?", (uid,)).fetchone()


def _yt_load_tokens(uid):
    row = _yt_tokens_row(uid)
    if not row:
        return None
    try:
        return _json.loads(_ig_fernet().decrypt(row["enc_tokens"].encode()).decode())
    except Exception:
        return None


def _yt_save(uid, tokens, channel):
    enc = _ig_fernet().encrypt(_json.dumps(tokens).encode()).decode()
    db = get_db()
    db.execute(
        "INSERT INTO yt_accounts(user_id, channel_id, channel_title, thumb, enc_tokens, connected_at)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(user_id) DO UPDATE SET channel_id=excluded.channel_id,"
        " channel_title=excluded.channel_title, thumb=excluded.thumb,"
        " enc_tokens=excluded.enc_tokens, connected_at=excluded.connected_at",
        (
            uid,
            channel.get("id", ""),
            channel.get("title", ""),
            channel.get("thumb", ""),
            enc,
            now_iso(),
        ),
    )
    db.commit()


def _yt_refresh(uid):
    toks = _yt_load_tokens(uid)
    if not toks or not toks.get("refresh_token"):
        return None
    s = _yt_settings()
    data = _urlparse.urlencode(
        {
            "client_id": s["client_id"],
            "client_secret": s["client_secret"],
            "refresh_token": toks["refresh_token"],
            "grant_type": "refresh_token",
        }
    ).encode()
    try:
        req = _urlreq.Request(
            _YT_TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with _urlreq.urlopen(req, timeout=20) as resp:
            j = _json.loads(resp.read().decode())
    except Exception:
        return None
    if "access_token" not in j:
        return None
    toks["access_token"] = j["access_token"]
    toks["expires_at"] = time.time() + int(j.get("expires_in", 3600)) - 60
    enc = _ig_fernet().encrypt(_json.dumps(toks).encode()).decode()
    db = get_db()
    db.execute("UPDATE yt_accounts SET enc_tokens = ? WHERE user_id = ?", (enc, uid))
    db.commit()
    return toks["access_token"]


def _yt_access(uid):
    toks = _yt_load_tokens(uid)
    if not toks:
        return None
    if toks.get("expires_at", 0) < time.time() + 30:
        return _yt_refresh(uid)
    return toks.get("access_token")


def _yt_get(uid, path, params):
    """فراخوانی YouTube Data API با تمدید خودکار توکن. برمی‌گرداند (data, error)."""
    token = _yt_access(uid)
    if not token:
        return None, "توکن یوتیوب نامعتبر است؛ دوباره وصل شو."

    def _call(tok):
        url = _YT_API + path + "?" + _urlparse.urlencode(params)
        req = _urlreq.Request(url, headers={"Authorization": "Bearer " + tok})
        with _urlreq.urlopen(req, timeout=25) as resp:
            return _json.loads(resp.read().decode())

    try:
        return _call(token), None
    except _urlreq.HTTPError as e:
        if e.code == 401:
            token = _yt_refresh(uid)
            if token:
                try:
                    return _call(token), None
                except Exception as e2:
                    return None, "خطای یوتیوب: " + str(e2)[:200]
        try:
            detail = e.read().decode()[:300]
        except Exception:
            detail = ""
        return None, "خطای YouTube API (کد %s). %s" % (e.code, detail)
    except Exception as e:
        return None, "خطا در تماس با یوتیوب: " + str(e)[:200]


def _yt_channel_by_token(access_token):
    try:
        q = _urlparse.urlencode({"part": "snippet,statistics", "mine": "true"})
        req = _urlreq.Request(
            _YT_API + "/channels?" + q, headers={"Authorization": "Bearer " + access_token}
        )
        with _urlreq.urlopen(req, timeout=25) as resp:
            j = _json.loads(resp.read().decode())
    except Exception as e:
        return None, "خطا در خواندن کانال: " + str(e)[:150]
    items = j.get("items") or []
    if not items:
        return None, "کانالی برای این حساب گوگل پیدا نشد."
    it = items[0]
    sn, st = it.get("snippet", {}), it.get("statistics", {})
    thumbs = sn.get("thumbnails", {}) or {}
    thumb = (thumbs.get("default") or {}).get("url", "")
    return (
        {
            "id": it.get("id", ""),
            "title": sn.get("title", ""),
            "thumb": thumb,
            "stats": st,
        },
        None,
    )


def _yt_popup(msg, ok_):
    flag = "yt-connected" if ok_ else "yt-failed"
    safe = msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    html = (
        "<!doctype html><html dir=rtl><head><meta charset=utf-8><title>یوتیوب</title></head>"
        "<body style='font-family:sans-serif;text-align:center;padding:60px 20px'>"
        "<p>" + safe + "</p><p>این پنجره بسته می‌شود…</p>"
        "<script>try{if(window.opener){window.opener.postMessage('" + flag + "','*')}}catch(e){}"
        "setTimeout(function(){window.close()},1500)</script>"
        "</body></html>"
    )
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/api/yt/config-hint")
@login_required
def yt_config_hint():
    return ok(configured=_yt_configured(), redirect_uri=_yt_redirect_uri())


@app.get("/api/yt/oauth/start")
@login_required
def yt_oauth_start():
    if not _yt_configured():
        return err("کلید گوگل در تنظیمات ادمین وارد نشده است.", "not_configured", 503)
    state = secrets.token_urlsafe(24)
    with _yt_state_lock:
        _yt_states[state] = {"uid": g.me["id"], "at": time.time()}
        for k in [k for k, v in _yt_states.items() if time.time() - v["at"] > 600]:
            _yt_states.pop(k, None)
    params = _urlparse.urlencode(
        {
            "client_id": _yt_settings()["client_id"],
            "redirect_uri": _yt_redirect_uri(),
            "response_type": "code",
            "scope": " ".join(_YT_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
    )
    from flask import redirect

    return redirect(_YT_AUTH_URL + "?" + params, code=302)


@app.get("/api/yt/oauth/callback")
@login_required
def yt_oauth_callback():
    if request.args.get("error"):
        return _yt_popup("اتصال توسط شما لغو شد.", False)
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    with _yt_state_lock:
        st = _yt_states.pop(state, None)
    if not st or st["uid"] != g.me["id"] or not code:
        return _yt_popup("نشست تأیید نامعتبر است؛ دوباره تلاش کن.", False)
    s = _yt_settings()
    data = _urlparse.urlencode(
        {
            "code": code,
            "client_id": s["client_id"],
            "client_secret": s["client_secret"],
            "redirect_uri": _yt_redirect_uri(),
            "grant_type": "authorization_code",
        }
    ).encode()
    try:
        req = _urlreq.Request(
            _YT_TOKEN_URL,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with _urlreq.urlopen(req, timeout=20) as resp:
            toks = _json.loads(resp.read().decode())
    except Exception as e:
        return _yt_popup("خطا در دریافت توکن: " + str(e)[:150], False)
    if "access_token" not in toks:
        return _yt_popup("گوگل توکن برنگرداند.", False)
    tokens = {
        "access_token": toks["access_token"],
        "refresh_token": toks.get("refresh_token", ""),
        "expires_at": time.time() + int(toks.get("expires_in", 3600)) - 60,
    }
    ch, cerr = _yt_channel_by_token(tokens["access_token"])
    if cerr:
        return _yt_popup(cerr, False)
    _yt_save(g.me["id"], tokens, ch)
    return _yt_popup("کانال «%s» وصل شد!" % ch.get("title", ""), True)


@app.get("/api/yt/status")
@login_required
def yt_status():
    row = _yt_tokens_row(g.me["id"])
    if not row:
        return ok(connected=False)
    return ok(
        connected=True,
        channel={
            "id": row["channel_id"],
            "title": row["channel_title"],
            "thumb": row["thumb"],
            "connected_at": row["connected_at"],
        },
    )


@app.post("/api/yt/disconnect")
@login_required
def yt_disconnect():
    toks = _yt_load_tokens(g.me["id"])
    if toks and toks.get("access_token"):
        try:  # revoke بهترین‌تلاش است؛ شکستش مهم نیست
            data = _urlparse.urlencode({"token": toks["access_token"]}).encode()
            _urlreq.urlopen(
                _urlreq.Request(_YT_REVOKE_URL, data=data), timeout=10
            ).read()
        except Exception:
            pass
    db = get_db()
    db.execute("DELETE FROM yt_accounts WHERE user_id = ?", (g.me["id"],))
    db.commit()
    return ok(message="اتصال یوتیوب قطع شد.")


@app.get("/api/yt/channel")
@login_required
def yt_channel():
    j, e = _yt_get(
        g.me["id"], "/channels", {"part": "snippet,statistics", "mine": "true"}
    )
    if e:
        return err(e, "yt_error", 502)
    items = j.get("items") or []
    if not items:
        return err("کانالی پیدا نشد.", "yt_error", 404)
    it = items[0]
    sn, st = it.get("snippet", {}), it.get("statistics", {})
    thumbs = sn.get("thumbnails", {}) or {}
    thumb = (thumbs.get("medium") or thumbs.get("default") or {}).get("url", "")
    return ok(
        channel={
            "id": it.get("id"),
            "title": sn.get("title"),
            "description": (sn.get("description") or "")[:300],
            "thumb": thumb,
            "published_at": sn.get("publishedAt"),
            "stats": st,
        }
    )


@app.get("/api/yt/videos")
@login_required
def yt_videos():
    j, e = _yt_get(g.me["id"], "/channels", {"part": "contentDetails", "mine": "true"})
    if e:
        return err(e, "yt_error", 502)
    items = j.get("items") or []
    pl = None
    if items:
        pl = ((items[0].get("contentDetails", {}) or {}).get("relatedPlaylists") or {}).get(
            "uploads"
        )
    if not pl:
        return err("پلی‌لیست ویدیوها پیدا نشد.", "yt_error", 404)
    pj, pe = _yt_get(
        g.me["id"],
        "/playlistItems",
        {"part": "contentDetails", "playlistId": pl, "maxResults": 12},
    )
    if pe:
        return err(pe, "yt_error", 502)
    vids = [
        it["contentDetails"]["videoId"]
        for it in pj.get("items", [])
        if (it.get("contentDetails") or {}).get("videoId")
    ]
    if not vids:
        return ok(videos=[])
    vj, ve = _yt_get(
        g.me["id"], "/videos", {"part": "snippet,statistics", "id": ",".join(vids)}
    )
    if ve:
        return err(ve, "yt_error", 502)
    out = []
    for it in vj.get("items", []):
        sn, st = it.get("snippet", {}), it.get("statistics", {})
        thumbs = sn.get("thumbnails", {}) or {}
        th = thumbs.get("medium") or thumbs.get("default") or {}
        out.append(
            {
                "id": it.get("id"),
                "title": sn.get("title"),
                "thumb": th.get("url"),
                "published_at": sn.get("publishedAt"),
                "views": st.get("viewCount", "0"),
                "likes": st.get("likeCount", "0"),
                "comments": st.get("commentCount", "0"),
            }
        )
    return ok(videos=out)


# ---------------------------------------------------------------- سلامت
@app.get("/api/health")
def health():
    return ok(status="up")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8000, debug=False)
