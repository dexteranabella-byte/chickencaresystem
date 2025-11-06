# app.py (Combined Frontend/DB routes, uses Postgres Pool, AI/Hardware code removed)
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import logging
import datetime

import psycopg
from psycopg.rows import dict_row
import psycopg.errors as pg_errors

# connection pool from psycopg_pool
try:
    from psycopg_pool import ConnectionPool
except Exception:
    ConnectionPool = None

# -------------------------
# Flask App Setup
# -------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)

# -------------------------
# Required env vars
# -------------------------
required_env = ["SECRET_KEY", "DATABASE_URL", "MAIL_USERNAME", "SMTP_PASSWORD"]
missing_env = [v for v in required_env if v not in os.environ]
if missing_env:
    raise RuntimeError(f"Missing required environment variables: {', '.join(missing_env)}")

# load env
app.secret_key = os.environ["SECRET_KEY"]
DB_URL_RAW = os.environ["DATABASE_URL"]
MAIL_USERNAME = os.environ["MAIL_USERNAME"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]

# Optional debug flag for local/testing
DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")

# Fix Postgres scheme if needed (psycopg expects postgresql://)
DB_URL = DB_URL_RAW.replace("postgres://", "postgresql://", 1) if DB_URL_RAW.startswith("postgres://") else DB_URL_RAW

# -------------------------
# Database connection pool (psycopg_pool)
# -------------------------
POOL_MAX = int(os.environ.get("DB_POOL_MAX", 6))

if ConnectionPool is None:
    app.logger.warning("psycopg_pool not available. Falling back to direct connections (no pool).")
    pool = None
else:
    try:
        # ** FIX **: Added row_factory=dict_row to the pool
        pool = ConnectionPool(conninfo=DB_URL, max_size=POOL_MAX, row_factory=dict_row)
        app.logger.info("Postgres connection pool created (max_size=%s).", POOL_MAX)
    except Exception:
        app.logger.exception("Failed to create Postgres connection pool; falling back to None.")
        pool = None

# Helper to obtain a connection context manager (works with pool or raw psycopg.connect)
def get_conn():
    """
    Usage:
        with get_conn() as conn, conn.cursor() as cur:
            ...
    """
    if pool:
        return pool.connection()
    # fallback: provide a context manager that yields a direct connection
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
# Flask-Mail Setup
# -------------------------
app.config.update(
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=MAIL_USERNAME,
    MAIL_PASSWORD=SMTP_PASSWORD
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# -------------------------
# Session security
# -------------------------
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------------------------
# Auto-create safe fallback tables (won't drop/alter existing)
# -------------------------
def init_tables():
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(266) NOT NULL,
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
            # Added tables from Gist for data fetching
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
    except Exception:
        app.logger.exception("init_tables: failed to ensure tables")

# run once on startup (safe: CREATE IF NOT EXISTS)
init_tables()

# -------------------------
# Utilities
# -------------------------
def normalize_env_records(rows):
    """Normalize sensor/weight rows into dicts the templates expect."""
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
                # Try parsing as string if not datetime object
                parsed = datetime.datetime.fromisoformat(str(dt))
                date_str = parsed.strftime("%Y-%m-%d")
                time_str = parsed.strftime("%H:%M:%S")
            except Exception:
                date_str = str(dt) if dt is not None else ""
                time_str = ""
        
        # Combine all possible keys
        record = {
            "temperature": rec.get("temperature") if rec.get("temperature") is not None else rec.get("temp"),
            "humidity": rec.get("humidity"),
            "ammonia": rec.get("ammonia"),
            "light1": rec.get("light1"),
            "light2": rec.get("light2"),
            "exhaustfan": rec.get("exhaustfan"),
            "date": date_str,
            "time": time_str,
            **rec # Include all other fields from the row
        }
        out.append(record)
    return out

def get_growth_chart_data(limit=20):
    """Return dates and weights from sensordata3 for the growth chart."""
    dates = []
    weights = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            # Use postgres-style %s placeholders
            cur.execute("SELECT datetime, weight FROM sensordata3 ORDER BY id DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
            rows = list(reversed(rows))
            for r in rows:
                rec = dict(r)
                dt = rec.get("datetime")
                if isinstance(dt, datetime.datetime):
                    label = dt.strftime("%Y-%m-%d %H:%M")
                else:
                    label = str(dt)
                dates.append(label)
                weights.append(rec.get("weight") or 0)
    except Exception:
        app.logger.exception("get_growth_chart_data failed")
    return dates, weights

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
        app.logger.exception("Error fetching user by email")
        return None

def get_user_by_id(user_id):
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()
    except Exception:
        app.logger.exception("Error fetching user by ID")
        return None

def get_current_user():
    user_id = session.get("user_id")
    return get_user_by_id(user_id) if user_id else None

def create_superadmin():
    """Create default superadmin if none exists (safe)."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE role='superadmin' LIMIT 1")
            if not cur.fetchone():
                super_email = "superadmin@example.com"
                super_username = "admin"
                super_pass = generate_password_hash("admin")
                cur.execute(
                    "INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,%s)",
                    (super_username, super_email, super_pass, "superadmin")
                )
    except Exception:
        app.logger.exception("Failed to create superadmin")

create_superadmin()

# -------------------------
# Main Routes (Login, Dashboard, etc.)
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
        email = request.form.get("email","").strip()
        password = request.form.get("password","")
        user = get_user_by_email(email)
        
        # This works now because the pool uses dict_row
        if user and check_password_hash(user["password"], password):
            session.update({
                "user_id": user["id"],
                "user_role": user.get("role","user"),
                "user_username": user.get("username"),
                "user_email": user.get("email")
            })
            flash(f"Welcome, {user.get('username','User')}!", "success")
            return redirect(url_for("admin_dashboard") if user.get("role") in ["admin","superadmin"] else url_for("dashboard"))
        flash("Invalid email or password", "danger")
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
        hashed = generate_password_hash(password)
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,%s)",
                    (username,email,hashed,"user")
                )
        except pg_errors.UniqueViolation:
            flash("Email already registered.", "danger")
        except Exception:
            app.logger.exception("Registration failed")
            flash("Database error. Try again later.", "danger")
        else:
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
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
                app.logger.warning("Table 'sensordata' does not exist.")

            try:
                cur.execute("SELECT COUNT(*) AS total FROM chickens")
                res = cur.fetchone()
                total_chickens = int(res["total"]) if res and res.get("total") is not None else 0
            except psycopg.errors.UndefinedTable:
                app.logger.warning("Table 'chickens' does not exist.")

            if records:
                temperature = records[0].get("temperature", 0) or 0
                humidity = records[0].get("humidity", 0) or 0

            try:
                cur.execute("SELECT feed_time FROM feeding_schedule WHERE feed_time > NOW() ORDER BY feed_time ASC LIMIT 1")
                feed = cur.fetchone()
                if feed and feed.get("feed_time"):
                    ft = feed["feed_time"]
                    if isinstance(ft, datetime.datetime):
                        upcoming_feeding = ft.strftime("%H:%M")
                    else:
                        try:
                            upcoming_feeding = datetime.datetime.fromisoformat(str(ft)).strftime("%H:%M")
                        except Exception:
                            upcoming_feeding = str(ft)
            except psycopg.errors.UndefinedTable:
                app.logger.warning("Table 'feeding_schedule' does not exist.")
    except Exception:
        app.logger.exception("Failed to fetch dashboard data")
        flash("Could not load dashboard data.", "warning")

    return render_template(
        "dashboard.html",
        records=records,
        total_chickens=total_chickens,
        temperature=temperature,
        humidity=humidity,
        upcoming_feeding=upcoming_feeding
    )

# <-- FIX: Added route for main-dashboard.html
@app.route("/main_dashboard")
@login_required
def main_dashboard():
    # This is a basic route. You can add data-fetching logic here
    # similar to your other dashboard routes if this page needs it.
    return render_template("main-dashboard.html")

@app.route("/admin-dashboard")
@role_required("admin","superadmin")
def admin_dashboard():
    active_users = 0
    reports_count = 0
    active_farms = 0
    alerts_count = 0
    recent_activities = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            try:
                cur.execute("SELECT COUNT(*) AS c FROM users")
                r = cur.fetchone()
                active_users = int(r["c"]) if r and r.get("c") is not None else 0
            except Exception:
                app.logger.debug("admin_dashboard: users count failed")

            try:
                cur.execute("SELECT id, datetime FROM sensordata ORDER BY id DESC LIMIT 5")
                rows = cur.fetchall()
                for row in rows:
                    rec = dict(row)
                    dt = rec.get("datetime") or rec.get("timestamp") or ""
                    recent_activities.append({"user": "system", "action": "sensordata inserted", "date": str(dt)})
            except Exception:
                app.logger.debug("admin_dashboard: recent activities fetch failed")
    except Exception:
        app.logger.exception("admin_dashboard: error")

    return render_template("admin-dashboard.html",
                            active_users=active_users,
                            reports_count=reports_count,
                            active_farms=active_farms,
                            alerts_count=alerts_count,
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
                    cur.execute(
                        "UPDATE users SET username=%s,email=%s,password=%s WHERE id=%s",
                        (username,email,generate_password_hash(new_pass),user["id"])
                    )
                else:
                    cur.execute(
                        "UPDATE users SET username=%s,email=%s WHERE id=%s",
                        (username,email,user["id"])
                    )
        except Exception:
            app.logger.exception("Failed to update settings")
            flash("Update failed. Try again later.", "danger")
        else:
            session.update({"user_username":username,"user_email":email})
            flash("Settings updated successfully.", "success")
            return redirect(url_for("settings"))
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
        app.logger.exception("Failed to load users")
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
                msg = Message(
                    "ChickCare Password Reset",
                    sender=MAIL_USERNAME,
                    recipients=[email],
                    body=f"Hi {user['username']},\nClick the link below to reset your password:\n{reset_url}\nIf you didn't request this, ignore this email."
                )
                mail.send(msg)
            except Exception:
                app.logger.exception("Failed to send email")
                flash("Failed to send reset email. Try again later.", "danger")
            else:
                flash("Password reset link sent! Check your email.", "info")
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
                cur.execute(
                    "UPDATE users SET password=%s WHERE email=%s",
                    (generate_password_hash(password), email)
                )
        except Exception:
            app.logger.exception("Password reset failed")
            flash("Could not reset password. Try again later.", "danger")
        else:
            flash("Password reset successful! You can now log in.", "success")
            return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)

@app.route("/growth-monitoring")
@app.route("/webcam") # <-- FIX: Alias for /webcam to render growth.html
@login_required
def growth_monitoring():
    dates, weights = get_growth_chart_data(limit=50)
    return render_template("growth.html", dates=dates, weights=weights)

@app.route("/feeding_schedule")
def feeding_schedule_alias():
    return feed_schedule()

@app.route("/feed-schedule")
@app.route("/feeding") # <-- FIX: Alias for /feeding to render feeding.html
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
                if isinstance(ft, datetime.datetime):
                    rec["time"] = ft.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    rec["time"] = str(ft)
                rec["feed_type"] = rec.get("feed_type") or rec.get("type") or ""
                rec["amount"] = rec.get("amount") or 0
                feeding_schedule.append(rec)
    except psycopg.errors.UndefinedTable:
        app.logger.warning("Table 'feeding_schedule' does not exist.")
    except Exception:
        app.logger.exception("Failed to load feeding data")
        flash("Could not load feeding data.", "warning")
    return render_template("feeding.html", feeding_schedule=feeding_schedule)

@app.route("/environment")
@login_required
def environment():
    environment_data = []
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM sensordata ORDER BY id DESC LIMIT 50")
            raw = cur.fetchall()
            environment_data = normalize_env_records(raw)
    except psycopg.errors.UndefinedTable:
        app.logger.warning("Table 'sensordata' does not exist.")
    except Exception:
        app.logger.exception("Failed to load environment data")
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

# -----------------------------------------------
# Data Fetching API Routes (from Gist, converted to Postgres)
# -----------------------------------------------
#
# *** FIX APPLIED ***
# Added the "friendly" route aliases (e.g., /get_growth_data) that
# the frontend is requesting (seen in the 404 logs) to point to
# your existing data functions.
#
# -----------------------------------------------

def format_datetime_in_results(results, field_name="datetime"):
    """Helper to format datetime fields in a list of dicts."""
    for result in results:
        if result.get(field_name):
            try:
                original_datetime = result[field_name]
                if isinstance(original_datetime, datetime.datetime):
                    formatted_datetime = original_datetime.strftime("%Y-%m-%d %I:%M:%S %p")
                else:
                    formatted_datetime = datetime.datetime.fromisoformat(str(original_datetime)).strftime("%Y-%m-%d %I:%M:%S %p")
                result[field_name] = formatted_datetime
            except Exception:
                # Keep original string if parsing fails
                result[field_name] = str(result[field_name])
    return results

@app.route('/get_all_data1')
@app.route('/get_growth_data') # <-- FIXED: Alias for Growth Monitoring
def fetch_all_data1():
    """Fetches ChickNumber and Weight from sensordata3."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, ChickNumber, Weight FROM sensordata3 ORDER BY DateTime DESC LIMIT 10")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data1")
        return jsonify({'error': str(e)}), 500

@app.route('/get_all_data2')
@app.route('/get_sanitization_data') # <-- FIXED: Alias for Sanitization
def fetch_all_data2():
    """Fetches Sanitization data from sensordata2."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT Conveyor, Sprinkle, UVLight FROM sensordata2 ORDER BY DateTime DESC LIMIT 1")
            results = cur.fetchall()
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data2")
        return jsonify({'error': str(e)}), 500

@app.route('/get_all_data3')
def fetch_all_data3():
    """Fetches Food/Water stock from sensordata1."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, Food, Water FROM sensordata1 ORDER BY DateTime DESC LIMIT 10")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data3")
        return jsonify({'error': str(e)}), 500

@app.route('/get_all_data4')
@app.route('/get_supplies_data') # <-- FIXED: Alias for Supplies Level
def fetch_all_data4():
    """Fetches Water/Food Levels from sensordata4."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, Water_Level, Food_Level FROM sensordata4 ORDER BY DateTime DESC LIMIT 10")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data4")
        return jsonify({'error': str(e)}), 500

@app.route('/get_all_data5')
@app.route('/get_environment_data') # <-- FIXED: Alias for Environment
@app.route('/get_all_data')        # <-- FIXED: Alias for general data
@app.route('/data')                # <-- FIXED: Alias for report data
def fetch_all_data5():
    """Fetches Environment data from sensordata."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, Humidity, Temperature, Ammonia, Light1, Light2, ExhaustFan FROM sensordata ORDER BY DateTime DESC LIMIT 10")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data5")
        return jsonify({'error': str(e)}), 500

@app.route('/get_all_data6')
@app.route('/get_chickstatus_data') # <-- FIXED: Alias for Chick Status
def fetch_all_data6():
    """Fetches Chick Health Status from chickstatus."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, ChickNumber, status FROM chickstatus ORDER BY DateTime DESC LIMIT 10")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data6")
        return jsonify({'error': str(e)}), 500

@app.route('/get_all_data7')
@app.route('/get_notifications_data') # <-- FIXED: Alias for Notifications
def fetch_all_data7():
    """Fetches Notifications."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, message FROM notifications ORDER BY DateTime DESC LIMIT 5")
            results = cur.fetchall()
            results = format_datetime_in_results(results, "datetime")
            return jsonify(results)
    except Exception as e:
        app.logger.exception("Error in /get_all_data7")
        return jsonify({'error': str(e)}), 500

# -----------------------------------------------
# <-- ⭐️ FIX: Added missing route for growth.html image gallery
# -----------------------------------------------
@app.route("/get_image_list")
@login_required 
def get_image_list():
    try:
        # Assumes 'shots' is a folder inside your 'static' folder
        image_dir = os.path.join(app.static_folder, 'shots')
        
        if not os.path.exists(image_dir):
            app.logger.warning(f"Image directory not found: {image_dir}")
            return jsonify([])

        # Get all files and filter for common image extensions
        all_files = os.listdir(image_dir)
        image_files = [
            f for f in all_files 
            if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))
        ]
        
        # Sort them by name
        image_files.sort() 
        
        return jsonify(image_files)
    except Exception as e:
        app.logger.exception("Error in /get_image_list")
        return jsonify({'error': str(e)}), 500

# -------------------------
# Run App
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=DEBUG)
