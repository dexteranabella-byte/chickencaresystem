# app.py - rewritten to fix DB connection/pooling issues and centralize DB access
import os
import logging
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg
from psycopg.rows import dict_row
import psycopg.errors as pg_errors

# optional pool (psycopg_pool.ConnectionPool signature doesn't accept row_factory)
try:
    from psycopg_pool import ConnectionPool
except Exception:
    ConnectionPool = None

# -------------------------
# App config
# -------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)
logger = app.logger

app.secret_key = os.environ.get("SECRET_KEY", "change_me_for_prod")
DB_URL_RAW = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/db")
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")

# Superadmin fallback (used only for auth if DB user not found)
SUPER_ADMIN_USER = os.environ.get("SUPER_ADMIN_USER", "admin")
SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL", "chickenmonitoringsystem@gmail.com")
SUPER_ADMIN_PASS = os.environ.get("SUPER_ADMIN_PASS", "chicken123")

# ensure psycopg-friendly URL prefix
DB_URL = DB_URL_RAW.replace("postgres://", "postgresql://", 1) if DB_URL_RAW.startswith("postgres://") else DB_URL_RAW

# Mail config (used for reset emails)
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=SMTP_PASSWORD
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# session cookie safety
app.config.update(
    SESSION_COOKIE_SECURE=not DEBUG,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------------------------
# Connection pool setup
# -------------------------
POOL_MAX = int(os.environ.get("DB_POOL_MAX", 6))
pool = None
if ConnectionPool is None:
    logger.warning("psycopg_pool not available; using direct connections.")
else:
    try:
        # DO NOT pass row_factory here (psycopg_pool doesn't expect it)
        pool = ConnectionPool(conninfo=DB_URL, max_size=POOL_MAX)
        logger.info("Connection pool created.")
    except Exception as e:
        logger.exception("Failed to create ConnectionPool, falling back to direct connections: %s", e)
        pool = None

# -------------------------
# DB helpers (centralized)
# -------------------------
def _get_conn_ctx():
    """
    Return a context manager that yields a psycopg connection.
    Use like:
        with _get_conn_ctx() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                ...
    """
    if pool:
        return pool.connection()  # this is already a context manager
    # direct connection context
    class _DirectCtx:
        def __enter__(self):
            self.conn = psycopg.connect(DB_URL)
            return self.conn
        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type:
                    self.conn.rollback()
                else:
                    self.conn.commit()
            finally:
                self.conn.close()
    return _DirectCtx()

def db_query(sql, params=None, one=False, many=False):
    """Run SELECT query and return rows (dict_row)."""
    params = params or ()
    try:
        with _get_conn_ctx() as conn:
            # ensure returned rows are dict-like
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(sql, params)
                if one:
                    return cur.fetchone()
                if many:
                    return cur.fetchmany(many)
                return cur.fetchall()
    except Exception:
        logger.exception("db_query failed")
        return None

def db_execute(sql, params=None):
    """Run INSERT/UPDATE/DELETE (returns True on success)."""
    params = params or ()
    try:
        with _get_conn_ctx() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
        return True
    except Exception:
        logger.exception("db_execute failed")
        return False

# -------------------------
# Initialize tables (safe)
# -------------------------
def init_tables():
    """Create minimal tables if missing (safe to run each start)."""
    try:
        with _get_conn_ctx() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(266) UNIQUE NOT NULL,
                        email VARCHAR(266) UNIQUE NOT NULL,
                        password VARCHAR(266) NOT NULL,
                        role TEXT DEFAULT 'user',
                        reset_token TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sensordata (
                        id SERIAL PRIMARY KEY,
                        datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                        humidity REAL,
                        temperature REAL,
                        ammonia REAL,
                        light1 VARCHAR(266),
                        light2 VARCHAR(266),
                        exhaustfan VARCHAR(266)
                    )
                """)
                # other tables (kept minimal; original schema can be run via your SQL file)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sensordata1 (
                        id SERIAL PRIMARY KEY,
                        datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                        food VARCHAR(266),
                        water VARCHAR(266)
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sensordata2 (
                        id SERIAL PRIMARY KEY,
                        datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                        conveyor VARCHAR(266),
                        sprinkle VARCHAR(266),
                        uvlight VARCHAR(266)
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sensordata3 (
                        id SERIAL PRIMARY KEY,
                        datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                        chicknumber VARCHAR(266),
                        weight REAL
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sensordata4 (
                        id SERIAL PRIMARY KEY,
                        water_level REAL,
                        food_level REAL,
                        datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS feeding_schedule (
                        id SERIAL PRIMARY KEY,
                        feed_time TIMESTAMP WITHOUT TIME ZONE,
                        feed_type VARCHAR(266),
                        amount FLOAT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS chickens (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(100),
                        age INTEGER,
                        weight FLOAT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS chickstatus (
                        id SERIAL PRIMARY KEY,
                        ChickNumber VARCHAR(266),
                        status VARCHAR(100),
                        DateTime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS notifications (
                        id SERIAL PRIMARY KEY,
                        message TEXT,
                        DateTime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
                    )
                """)
        logger.info("init_tables: ensured tables exist.")
    except Exception:
        logger.exception("init_tables: failed to ensure tables")

init_tables()

# -------------------------
# Utilities & user helpers
# -------------------------
def normalize_env_records(rows):
    out = []
    for r in rows or []:
        rec = dict(r) if not isinstance(r, dict) else r
        dt = rec.get("datetime")
        if isinstance(dt, datetime.datetime):
            rec["date"] = dt.strftime("%Y-%m-%d")
            rec["time"] = dt.strftime("%H:%M:%S")
        out.append(rec)
    return out

def get_user_by_email(email):
    return db_query("SELECT * FROM users WHERE email=%s", (email,), one=True)

def get_user_by_username(username):
    return db_query("SELECT * FROM users WHERE username=%s", (username,), one=True)

def get_user_by_id(uid):
    return db_query("SELECT * FROM users WHERE id=%s", (uid,), one=True)

def get_current_user():
    uid = session.get("user_id")
    if uid:
        return get_user_by_id(uid)
    if session.get("user_role") == "superadmin":
        return {"username": session.get("user_username"), "email": session.get("user_email"), "role": "superadmin"}
    return None

# -------------------------
# Auth decorators
# -------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session and session.get("user_role") not in ("admin","superadmin","user"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if session.get("user_role") not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# -------------------------
# Routes (kept compact but full behavior)
# -------------------------
@app.route("/")
def home():
    role = session.get("user_role")
    if role in ("admin","superadmin"):
        return redirect(url_for("admin_dashboard"))
    if role:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=("GET","POST"))
def login():
    if "user_id" in session or session.get("user_role") in ("admin","superadmin","user"):
        role = session.get("user_role")
        return redirect(url_for("admin_dashboard") if role in ("admin","superadmin") else url_for("dashboard"))

    if request.method == "POST":
        identifier = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        # try DB lookup
        user = None
        if "@" in identifier:
            user = get_user_by_email(identifier)
        else:
            user = get_user_by_username(identifier) or get_user_by_email(identifier)

        if user:
            stored = user.get("password") or ""
            # support hashed passwords and plaintext fallback
            try:
                if stored and (check_password_hash(stored, password) or stored == password):
                    session.update({
                        "user_id": user["id"],
                        "user_role": user.get("role","user"),
                        "user_username": user.get("username"),
                        "user_email": user.get("email")
                    })
                    flash(f"Welcome, {user.get('username','User')}!", "success")
                    return redirect(url_for("admin_dashboard") if user.get("role") in ("admin","superadmin") else url_for("dashboard"))
                else:
                    flash("Invalid email/username or password", "danger")
            except Exception:
                logger.exception("Password check failed")
                flash("Login failed. Try again.", "danger")
        else:
            # fallback to env superadmin if DB user not found
            matches = (identifier == SUPER_ADMIN_USER) or (identifier == SUPER_ADMIN_EMAIL)
            if matches and password == SUPER_ADMIN_PASS:
                session.update({
                    "user_id": None,
                    "user_role": "superadmin",
                    "user_username": SUPER_ADMIN_USER,
                    "user_email": SUPER_ADMIN_EMAIL
                })
                flash(f"Welcome, {SUPER_ADMIN_USER} (superadmin)!", "success")
                return redirect(url_for("admin_dashboard"))
            flash("Invalid email/username or password", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/register", methods=("GET","POST"))
def register():
    if "user_id" in session or session.get("user_role"):
        role = session.get("user_role")
        return redirect(url_for("admin_dashboard") if role in ("admin","superadmin") else url_for("dashboard"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        if not username or not email or not password:
            flash("All fields required.", "warning")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password)
        try:
            success = db_execute("INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,%s)",
                                 (username, email, hashed, "user"))
            if success:
                flash("Registered — please login.", "success")
                return redirect(url_for("login"))
            flash("Registration failed.", "danger")
        except pg_errors.UniqueViolation:
            flash("Email or username already registered.", "danger")
        except Exception:
            logger.exception("Registration failed")
            flash("Registration error.", "danger")
    return render_template("register.html")

@app.route("/dashboard")
@login_required
def dashboard():
    records = db_query("SELECT * FROM sensordata ORDER BY id DESC LIMIT 5") or []
    records = normalize_env_records(records)
    total_chickens = db_query("SELECT COUNT(*) AS total FROM chickens", (), one=True) or {"total": 0}
    total_chickens = int(total_chickens.get("total") or 0)
    temperature = records[0].get("temperature") if records else 0
    humidity = records[0].get("humidity") if records else 0
    upcoming_feeding = "N/A"
    nxt = db_query("SELECT feed_time FROM feeding_schedule WHERE feed_time > NOW() ORDER BY feed_time ASC LIMIT 1", (), one=True)
    if nxt and nxt.get("feed_time"):
        ft = nxt["feed_time"]
        upcoming_feeding = ft.strftime("%H:%M") if isinstance(ft, datetime.datetime) else str(ft)
    return render_template("dashboard.html", records=records, total_chickens=total_chickens,
                           temperature=temperature, humidity=humidity, upcoming_feeding=upcoming_feeding)

@app.route("/admin-dashboard")
@role_required("admin","superadmin")
def admin_dashboard():
    active_users = db_query("SELECT COUNT(*) AS c FROM users", (), one=True) or {"c": 0}
    active_users = int(active_users.get("c") or 0)
    recent_activities = []
    rows = db_query("SELECT id, datetime FROM sensordata ORDER BY id DESC LIMIT 5") or []
    for r in rows:
        rec = dict(r)
        recent_activities.append({"user": "system", "action":"sensordata inserted", "date": str(rec.get("datetime"))})
    return render_template("admin-dashboard.html", active_users=active_users, reports_count=0,
                           active_farms=0, alerts_count=0, recent_activities=recent_activities)

# Data API examples kept (use db_query)
@app.route('/data')
def data():
    res = db_query("SELECT datetime, humidity, temperature, ammonia, light1, light2, exhaustfan FROM sensordata ORDER BY datetime DESC LIMIT 10") or []
    # format datetimes
    for r in res:
        if r.get("datetime") and isinstance(r["datetime"], datetime.datetime):
            r["datetime"] = r["datetime"].strftime("%Y-%m-%d %I:%M:%S %p")
    return jsonify(res)

# add other endpoints from your original app as needed following same pattern...
# STOP endpoints (examples)
@app.route("/stop_water_relay", methods=("POST",))
@login_required
def stop_water_relay():
    db_execute("INSERT INTO sensordata1 (datetime, food, water) VALUES (%s,%s,%s)",
               (datetime.datetime.now(), "OFF", "OFF"))
    return jsonify({"success": True})

# Password reset (generate + reset)
@app.route("/generate", methods=("GET","POST"))
def generate():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        user = get_user_by_email(email)
        if user:
            try:
                token = serializer.dumps(email, salt="password-reset-salt")
                reset_url = url_for("reset_with_token", token=token, _external=True)
                msg = Message("ChickCare Password Reset", sender=MAIL_USERNAME, recipients=[email],
                              body=f"Hi {user['username']},\nClick to reset: {reset_url}")
                mail.send(msg)
                flash("Password reset link sent!", "info")
            except Exception:
                logger.exception("Failed to send reset email")
                flash("Failed to send reset email.", "danger")
        else:
            flash("Email not found.", "warning")
    return render_template("generate.html")

@app.route("/reset/<token>", methods=("GET","POST"))
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except SignatureExpired:
        flash("The link has expired.", "danger")
        return redirect(url_for("generate"))
    except BadSignature:
        flash("Invalid token.", "danger")
        return redirect(url_for("generate"))

    if request.method == "POST":
        password = request.form.get("password") or ""
        if not password:
            flash("Password cannot be empty.", "warning")
            return redirect(url_for("reset_with_token", token=token))
        db_execute("UPDATE users SET password=%s WHERE email=%s", (generate_password_hash(password), email))
        flash("Password reset successful!", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)

# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Flask app on 0.0.0.0:%s (DEBUG=%s)", port, DEBUG)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
