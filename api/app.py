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
    defaults = {
        "site_name": "پنل مدیریت اینستاگرام",
        "announcement": "",
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
    allowed = {"site_name", "announcement"}
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


# ---------------------------------------------------------------- سلامت
@app.get("/api/health")
def health():
    return ok(status="up")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=8000, debug=False)
