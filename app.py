# app.py - rewritten, preserves your routes and design, fixes DB connection issues
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

# optional pool
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

# Environment / secrets (use real env in production)
app.secret_key = os.environ.get("SECRET_KEY", "change_me_for_prod")
DB_URL_RAW = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/db")
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")

# ensure psycopg-friendly URL
DB_URL = DB_URL_RAW.replace("postgres://", "postgresql://", 1) if DB_URL_RAW.startswith("postgres://") else DB_URL_RAW

# Mail config
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=SMTP_PASSWORD
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Session cookie config
app.config.update(
    SESSION_COOKIE_SECURE=not DEBUG,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------------------------
# Connection pool (optional)
# -------------------------
POOL_MAX = int(os.environ.get("DB_POOL_MAX", 6))
pool = None
if ConnectionPool is None:
    logger.warning("psycopg_pool not installed — falling back to direct connections.")
else:
    try:
        pool = ConnectionPool(conninfo=DB_URL, max_size=POOL_MAX, row_factory=dict_row)
        logger.info("psycopg_pool ConnectionPool created (max_size=%s).", POOL_MAX)
    except Exception as e:
        logger.exception("Failed to create ConnectionPool, falling back to direct connections: %s", e)
        pool = None

# -------------------------
# DB connection helper
# -------------------------
def get_conn():
    """
    Context manager returning a connection (with dict_row).
    Usage:
        with get_conn() as conn, conn.cursor() as cur:
            ...
    """
    if pool:
        # pool.connection() returns a context manager
        return pool.connection()
    # fallback context manager that yields a new connection
    class _DirectConnCtx:
        def __enter__(self):
            self.conn = psycopg.connect(DB_URL, row_factory=dict_row)
            return self.conn
        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type:
                    self.conn.rollback()
                else:
                    self.conn.commit()
            finally:
                self.conn.close()
    return _DirectConnCtx()

# -------------------------
# Initialize tables (safe)
# -------------------------
def init_tables():
    try:
        with get_conn() as conn, conn.cursor() as cur:
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
                    weight REAL,
                    weighingcount INTEGER DEFAULT 0,
                    averageweight DECIMAL(8,3) DEFAULT 0.000
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
        logger.info("init_tables: ensured fallback tables exist.")
    except Exception:
        logger.exception("init_tables: failed to ensure tables")

init_tables()

# -------------------------
# Create superadmin account (if missing)
# -------------------------
def create_superadmin():
    """
    Create a known superadmin account if none exists.
    Per your request: email=admin123@gmail.com password=admin123
    (password is stored hashed)
    """
    try:
        with get_conn() as conn, conn.cursor() as cur:
            # If any superadmin exists, skip
            cur.execute("SELECT id FROM users WHERE role='superadmin' OR email=%s LIMIT 1", ("admin123@gmail.com",))
            if cur.fetchone():
                logger.info("Superadmin already exists or admin123@gmail.com present.")
                return
            hashed = generate_password_hash("admin123", method="pbkdf2:sha256")
            cur.execute(
                "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                ("superadmin", "admin123@gmail.com", hashed, "superadmin")
            )
            logger.info("Created superadmin: admin123@gmail.com (password 'admin123')")
    except Exception:
        logger.exception("create_superadmin: failed")

create_superadmin()

# -------------------------
# Utilities
# -------------------------
def normalize_env_records(rows):
    out = []
    for r in rows:
        try:
            rec = dict(r)
        except Exception:
            rec = r
        dt = rec.get("datetime") or rec.get("timestamp") or rec.get("date")
        date_str = ""
        time_str = ""
        if isinstance(dt, datetime.datetime):
            date_str = dt.strftime("%Y-%m-%d")
            time_str = dt.strftime("%H:%M:%S")
        else:
            try:
                parsed = datetime.datetime.fromisoformat(str(dt))
                date_str = parsed.strftime("%Y-%m-%d")
                time_str = parsed.strftime("%H:%M:%S")
            except Exception:
                date_str = str(dt) if dt is not None else ""
                time_str = ""
        record = {
            "temperature": rec.get("temperature") if rec.get("temperature") is not None else rec.get("temp"),
            "humidity": rec.get("humidity"),
            "ammonia": rec.get("ammonia"),
            "light1": rec.get("light1"),
            "light2": rec.get("light2"),
            "exhaustfan": rec.get("exhaustfan"),
            "date": date_str,
            "time": time_str,
            **rec
        }
        out.append(record)
    return out

def get_growth_chart_data(limit=20):
    dates, weights = [], []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, weight FROM sensordata3 ORDER BY id DESC LIMIT %s", (limit,))
            rows = list(reversed(cur.fetchall()))
            for r in rows:
                rec = dict(r)
                dt = rec.get("datetime")
                label = dt.strftime("%Y-%m-%d %H:%M") if isinstance(dt, datetime.datetime) else str(dt)
                dates.append(label)
                weights.append(rec.get("weight") or 0)
    except Exception:
        logger.exception("get_growth_chart_data failed")
    return dates, weights

def format_datetime_in_results(results, field_name="datetime"):
    for result in results:
        if result.get(field_name):
            try:
                d = result[field_name]
                if isinstance(d, datetime.datetime):
                    result[field_name] = d.strftime("%Y-%m-%d %I:%M:%S %p")
                else:
                    result[field_name] = datetime.datetime.fromisoformat(str(d)).strftime("%Y-%m-%d %I:%M:%S %p")
            except Exception:
                result[field_name] = str(result[field_name])
    return results

# -------------------------
# Decorators
# -------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
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
# User helpers
# -------------------------
def get_user_by_email(email):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            return cur.fetchone()
    except Exception:
        logger.exception("get_user_by_email error")
        return None

def get_user_by_username(username):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()
    except Exception:
        logger.exception("get_user_by_username error")
        return None

def get_user_by_id(user_id):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()
    except Exception:
        logger.exception("get_user_by_id error")
        return None

def get_current_user():
    uid = session.get("user_id")
    return get_user_by_id(uid) if uid else None

# -------------------------
# Routes - pages & auth
# -------------------------
@app.route("/")
def home():
    role = session.get("user_role")
    if role in ["admin", "superadmin"]:
        return redirect(url_for("admin_dashboard"))
    elif role:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if "user_id" in session:
        role = session.get("user_role")
        return redirect(url_for("admin_dashboard") if role in ["admin","superadmin"] else url_for("dashboard"))

    if request.method == "POST":
        login_identifier = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = None

        # If identifier contains @ treat as email, else username; allow 'admin123@gmail.com' or 'superadmin' etc.
        if "@" in login_identifier:
            user = get_user_by_email(login_identifier)
        else:
            # try username
            user = get_user_by_username(login_identifier)
            # fallback: allow using email without @ (rare)
            if not user:
                user = get_user_by_email(login_identifier)

        if user and check_password_hash(user["password"], password):
            session.update({
                "user_id": user["id"],
                "user_role": user.get("role", "user"),
                "user_username": user.get("username"),
                "user_email": user.get("email")
            })
            flash(f"Welcome, {user.get('username','User')}!", "success")
            return redirect(url_for("admin_dashboard") if user.get("role") in ["admin","superadmin"] else url_for("dashboard"))
        flash("Invalid email/username or password", "danger")

    return render_template("login.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if "user_id" in session:
        role = session.get("user_role")
        return redirect(url_for("admin_dashboard") if role in ["admin","superadmin"] else url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip()
        password = request.form.get("password","")
        if not username or not email or not password:
            flash("All fields are required.", "warning")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password, method="pbkdf2:sha256")
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,%s)",
                            (username, email, hashed, "user"))
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except pg_errors.UniqueViolation:
            flash("Email or Username already registered.", "danger")
        except Exception:
            logger.exception("Registration failed")
            flash("Database error. Try again later.", "danger")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    records = []
    total_chickens = 0
    temperature = 0
    humidity = 0
    upcoming_feeding = "N/A"
    try:
        with get_conn() as conn, conn.cursor() as cur:
            try:
                cur.execute("SELECT * FROM sensordata ORDER BY id DESC LIMIT 5")
                raw = cur.fetchall()
                records = normalize_env_records(raw)
            except psycopg.errors.UndefinedTable:
                logger.warning("sensordata table missing")

            try:
                cur.execute("SELECT COUNT(*) AS total FROM chickens")
                res = cur.fetchone()
                total_chickens = int(res["total"]) if res and res.get("total") is not None else 0
            except psycopg.errors.UndefinedTable:
                logger.warning("chickens table missing")

            if records:
                temperature = records[0].get("temperature", 0) or 0
                humidity = records[0].get("humidity", 0) or 0

            try:
                cur.execute("SELECT feed_time FROM feeding_schedule WHERE feed_time > NOW() ORDER BY feed_time ASC LIMIT 1")
                feed = cur.fetchone()
                if feed and feed.get("feed_time"):
                    ft = feed["feed_time"]
                    upcoming_feeding = ft.strftime("%H:%M") if isinstance(ft, datetime.datetime) else str(ft)
            except psycopg.errors.UndefinedTable:
                logger.warning("feeding_schedule table missing")
    except Exception:
        logger.exception("Failed to fetch dashboard data")
        flash("Could not load dashboard data.", "warning")

    return render_template("dashboard.html",
                           records=records,
                           total_chickens=total_chickens,
                           temperature=temperature,
                           humidity=humidity,
                           upcoming_feeding=upcoming_feeding)

@app.route("/main_dashboard")
@login_required
def main_dashboard():
    return render_template("main-dashboard.html")

@app.route("/admin-dashboard")
@role_required("admin","superadmin")
def admin_dashboard():
    active_users = 0
    recent_activities = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM users")
            r = cur.fetchone()
            active_users = int(r["c"]) if r and r.get("c") is not None else 0

            try:
                cur.execute("SELECT id, datetime FROM sensordata ORDER BY id DESC LIMIT 5")
                rows = cur.fetchall()
                for row in rows:
                    rec = dict(row)
                    dt = rec.get("datetime") or rec.get("timestamp") or ""
                    recent_activities.append({"user": "system", "action": "sensordata inserted", "date": str(dt)})
            except Exception:
                logger.debug("No sensordata for recent activities")
    except Exception:
        logger.exception("admin_dashboard: error")

    return render_template("admin-dashboard.html",
                           active_users=active_users,
                           reports_count=0,
                           active_farms=0,
                           alerts_count=0,
                           recent_activities=recent_activities)

@app.route("/profile")
@login_required
def profile():
    user = get_current_user()
    return render_template("profile.html", user=user)

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    user = get_current_user()
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip()
        new_pass = request.form.get("password","")
        if not username or not email:
            flash("Username and email cannot be empty.", "warning")
            return redirect(url_for("settings"))
        try:
            with get_conn() as conn, conn.cursor() as cur:
                if new_pass:
                    cur.execute("UPDATE users SET username=%s,email=%s,password=%s WHERE id=%s",
                                (username, email, generate_password_hash(new_pass, method="pbkdf2:sha256"), user["id"]))
                else:
                    cur.execute("UPDATE users SET username=%s,email=%s WHERE id=%s", (username, email, user["id"]))
            session.update({"user_username": username, "user_email": email})
            flash("Settings updated successfully.", "success")
            return redirect(url_for("settings"))
        except pg_errors.UniqueViolation:
            flash("Username or Email already exists.", "danger")
        except Exception:
            logger.exception("Failed to update settings")
            flash("Update failed. Try again later.", "danger")
    return render_template("settings.html", user=user)

@app.route("/manage-users")
@role_required("admin","superadmin")
def manage_users():
    users = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id,username,email,role FROM users ORDER BY id DESC")
            users = cur.fetchall()
    except Exception:
        logger.exception("Failed to load users")
    return render_template("manage-users.html", users=users)

@app.route("/generate", methods=["GET","POST"])
def generate():
    if request.method == "POST":
        email = request.form.get("email","").strip()
        user = get_user_by_email(email)
        if user:
            try:
                token = serializer.dumps(email, salt="password-reset-salt")
                reset_url = url_for("reset_with_token", token=token, _external=True)
                msg = Message("ChickCare Password Reset", sender=MAIL_USERNAME, recipients=[email],
                              body=f"Hi {user['username']},\nClick to reset: {reset_url}")
                mail.send(msg)
                flash("Password reset link sent! Check your email.", "info")
            except Exception:
                logger.exception("Failed to send reset email")
                flash("Failed to send reset email. Try again later.", "danger")
        else:
            flash("Email not found.", "warning")
    return render_template("generate.html")

@app.route("/reset/<token>", methods=["GET","POST"])
def reset_with_token(token):
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except SignatureExpired:
        flash("The link has expired.", "danger")
        return redirect(url_for("generate"))
    except BadSignature:
        flash("Invalid or tampered token.", "danger")
        return redirect(url_for("generate"))

    if request.method == "POST":
        password = request.form.get("password","")
        if not password:
            flash("Password cannot be empty.", "warning")
            return redirect(url_for("reset_with_token", token=token))
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("UPDATE users SET password=%s WHERE email=%s",
                            (generate_password_hash(password, method="pbkdf2:sha256"), email))
            flash("Password reset successful! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception:
            logger.exception("Password reset failed")
            flash("Could not reset password. Try again later.", "danger")
    return render_template("reset_password.html", token=token)

@app.route("/growth-monitoring")
@app.route("/webcam")
@login_required
def growth_monitoring():
    dates, weights = get_growth_chart_data(limit=50)
    return render_template("growth.html", dates=dates, weights=weights)

@app.route("/feeding_schedule")
def feeding_schedule_alias():
    return feed_schedule()

@app.route("/feed-schedule")
@app.route("/feeding")
@login_required
def feed_schedule():
    feeding_schedule = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, feed_time, feed_type, amount FROM feeding_schedule ORDER BY feed_time ASC")
            raw = cur.fetchall()
            for r in raw:
                rec = dict(r)
                ft = rec.get("feed_time")
                rec["time"] = ft.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ft, datetime.datetime) else str(ft)
                rec["feed_type"] = rec.get("feed_type") or rec.get("type") or ""
                rec["amount"] = rec.get("amount") or 0
                feeding_schedule.append(rec)
    except psycopg.errors.UndefinedTable:
        logger.warning("feeding_schedule missing")
    except Exception:
        logger.exception("Failed to load feeding data")
        flash("Could not load feeding data.", "warning")
    return render_template("feeding.html", feeding_schedule=feeding_schedule)

@app.route("/environment")
@login_required
def environment():
    environment_data = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM sensordata ORDER BY id DESC LIMIT 50")
            environment_data = normalize_env_records(cur.fetchall())
    except psycopg.errors.UndefinedTable:
        logger.warning("sensordata missing")
    except Exception:
        logger.exception("Failed to load environment data")
        flash("Could not load environment data.", "warning")
    return render_template("environment.html", environment_data=environment_data)

@app.route("/sanitization")
@login_required
def sanitization():
    return render_template("sanitization.html")

@app.route("/report")
@login_required
def report():
    return render_template("report.html")

# -------------------------
# Data API routes (aliases kept)
# -------------------------
@app.route('/get_all_data1')
@app.route('/get_growth_data')
def fetch_all_data1():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, chicknumber, weight FROM sensordata3 ORDER BY datetime DESC LIMIT 10")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception:
        logger.exception("Error in fetch_all_data1")
        return jsonify({'error': 'server error'}), 500

@app.route('/get_all_data2')
@app.route('/get_sanitization_data')
def fetch_all_data2():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT conveyor, sprinkle, uvlight FROM sensordata2 ORDER BY datetime DESC LIMIT 1")
            return jsonify(cur.fetchall())
    except Exception:
        logger.exception("Error in fetch_all_data2")
        return jsonify({'error': 'server error'}), 500

@app.route('/get_all_data3')
def fetch_all_data3():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, food, water FROM sensordata1 ORDER BY datetime DESC LIMIT 10")
            res = cur.fetchall()
            res = format_datetime_in_results(res, "datetime")
            return jsonify(res)
    except Exception:
        logger.exception("Error in fetch_all_data3")
        return jsonify({'error': 'server error'}), 500

@app.route('/get_all_data4')
@app.route('/get_supplies_data')
def fetch_all_data4():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, water_level, food_level FROM sensordata4 ORDER BY datetime DESC LIMIT 10")
            res = cur.fetchall()
            res = format_datetime_in_results(res, "datetime")
            return jsonify(res)
    except Exception:
        logger.exception("Error in fetch_all_data4")
        return jsonify({'error': 'server error'}), 500

@app.route('/get_all_data5')
@app.route('/get_environment_data')
@app.route('/get_all_data')
@app.route('/data')
def fetch_all_data5():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, humidity, temperature, ammonia, light1, light2, exhaustfan FROM sensordata ORDER BY datetime DESC LIMIT 10")
            res = cur.fetchall()
            res = format_datetime_in_results(res, "datetime")
            return jsonify(res)
    except Exception:
        logger.exception("Error in fetch_all_data5")
        return jsonify({'error': 'server error'}), 500

@app.route('/get_all_data6')
@app.route('/get_chickstatus_data')
def fetch_all_data6():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, chicknumber, status FROM chickstatus ORDER BY datetime DESC LIMIT 10")
            res = cur.fetchall()
            res = format_datetime_in_results(res, "datetime")
            return jsonify(res)
    except Exception:
        logger.exception("Error in fetch_all_data6")
        return jsonify({'error': 'server error'}), 500

@app.route('/get_all_data7')
@app.route('/get_notifications_data')
def fetch_all_data7():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT datetime, message FROM notifications ORDER BY datetime DESC LIMIT 5")
            res = cur.fetchall()
            res = format_datetime_in_results(res, "datetime")
            return jsonify(res)
    except Exception:
        logger.exception("Error in fetch_all_data7")
        return jsonify({'error': 'server error'}), 500

# image list for gallery
@app.route("/get_image_list")
@login_required
def get_image_list():
    try:
        image_dir = os.path.join(app.static_folder, "shots")
        if not os.path.exists(image_dir):
            logger.warning("Image dir not found: %s", image_dir)
            return jsonify([])
        files = [f for f in os.listdir(image_dir) if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif"))]
        files.sort()
        return jsonify(files)
    except Exception:
        logger.exception("Error in get_image_list")
        return jsonify({'error': 'server error'}), 500

# STOP routes (hardware actions recorded to DB)
@app.route("/stop_water_relay", methods=["POST"])
@login_required
def stop_water_relay():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, %s, %s)",
                        (datetime.datetime.now(), "OFF", "OFF"))
        return jsonify({"success": True})
    except Exception:
        logger.exception("stop_water_relay failed")
        return jsonify({"error": "server error"}), 500

@app.route("/stop_servo_food", methods=["POST"])
@login_required
def stop_servo_food():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, %s, %s)",
                        (datetime.datetime.now(), "OFF", "OFF"))
        return jsonify({"success": True})
    except Exception:
        logger.exception("stop_servo_food failed")
        return jsonify({"error": "server error"}), 500

@app.route("/stop_conveyor", methods=["POST"])
@login_required
def stop_conveyor():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)",
                        (datetime.datetime.now(), "OFF", "OFF", "OFF"))
        return jsonify({"success": True})
    except Exception:
        logger.exception("stop_conveyor failed")
        return jsonify({"error": "server error"}), 500

@app.route("/stop_sprinkle", methods=["POST"])
@login_required
def stop_sprinkle():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)",
                        (datetime.datetime.now(), "OFF", "OFF", "OFF"))
        return jsonify({"success": True})
    except Exception:
        logger.exception("stop_sprinkle failed")
        return jsonify({"error": "server error"}), 500

@app.route("/stop_uvlight", methods=["POST"])
@login_required
def stop_uvlight():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)",
                        (datetime.datetime.now(), "OFF", "OFF", "OFF"))
        return jsonify({"success": True})
    except Exception:
        logger.exception("stop_uvlight failed")
        return jsonify({"error": "server error"}), 500

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Flask app on 0.0.0.0:%s (DEBUG=%s)", port, DEBUG)
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
