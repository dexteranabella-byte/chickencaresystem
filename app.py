import eventlet # <-- MUST be line 1
eventlet.monkey_patch() # <-- MUST be line 2

# app.py (Upgraded with SocketIO, WTForms, and Eventlet)
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
from psycopg_pool import ConnectionPool

from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length

# -------------------------
# Flask App Setup
# -------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)

# -------------------------
# Required env vars (or defaults for local dev)
# -------------------------
# In a real app, load from .env or set in your environment
app.secret_key = os.environ.get("SECRET_KEY", "a_very_insecure_default_secret_key_change_me")
DB_URL_RAW = os.environ.get("DATABASE_URL", "postgresql://user:pass@host/db")
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "your_email@gmail.com")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "your_app_password")

DEBUG = os.environ.get("DEBUG", "False").lower() in ("1", "true", "yes")
DB_URL = DB_URL_RAW.replace("postgres://", "postgresql://", 1) if DB_URL_RAW.startswith("postgres://") else DB_URL_RAW

# -------------------------
# Database connection pool
# -------------------------
POOL_MAX = int(os.environ.get("DB_POOL_MAX", 6))
try:
    pool = ConnectionPool(conninfo=DB_URL, max_size=POOL_MAX, row_factory=dict_row)
    app.logger.info("Postgres connection pool created (max_size=%s).", POOL_MAX)
except Exception as e:
    app.logger.error(f"Failed to create Postgres connection pool. Error: {e}")
    pool = None

def get_conn():
    """Gets a connection context manager from the pool or creates a new one."""
    if pool:
        return pool.connection()
    # fallback: provide a context manager that yields a direct connection
    class _DirectConnCtx:
        def __enter__(self):
            self.conn = psycopg.connect(DB_URL, row_factory=dict_row)
            return self.conn
        def __exit__(self, exc_type, exc, tb):
            try:
                if exc_type: self.conn.rollback()
                else: self.conn.commit()
            finally: self.conn.close()
    return _DirectConnCtx()

# -------------------------
# Extensions Setup (Mail, SocketIO)
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
socketio = SocketIO(app, async_mode='eventlet')

# -------------------------
# Session security
# -------------------------
app.config.update(
    SESSION_COOKIE_SECURE=not DEBUG, # Secure cookies if not in debug mode
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# -------------------------
# WTForms Definitions
# -------------------------
class LoginForm(FlaskForm):
    """Form for user login."""
    email = StringField('Email or Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    """Form for user registration."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ForgotPasswordForm(FlaskForm):
    """Form for requesting a password reset email."""
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    """Form for resetting a password with a token."""
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class SettingsForm(FlaskForm):
    """Form for updating user settings."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password (optional)')
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Update Settings')

# -------------------------
# Database Init & Default Admin
# -------------------------
def init_tables():
    """Creates all tables if they don't exist."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY, username VARCHAR(266) UNIQUE NOT NULL,
                    email VARCHAR(266) UNIQUE NOT NULL, password VARCHAR(266) NOT NULL,
                    role TEXT DEFAULT 'user', reset_token TEXT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS sensordata (
                    id SERIAL PRIMARY KEY, datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                    humidity REAL, temperature REAL, ammonia REAL, light1 VARCHAR(266),
                    light2 VARCHAR(266), exhaustfan VARCHAR(266))""")
            cur.execute("""CREATE TABLE IF NOT EXISTS sensordata1 (
                    id SERIAL PRIMARY KEY, datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                    food VARCHAR(266), water VARCHAR(266))""")
            cur.execute("""CREATE TABLE IF NOT EXISTS sensordata2 (
                    id SERIAL PRIMARY KEY, datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                    conveyor VARCHAR(266), sprinkle VARCHAR(266), uvlight VARCHAR(266))""")
            cur.execute("""CREATE TABLE IF NOT EXISTS sensordata3 (
                    id SERIAL PRIMARY KEY, datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                    chicknumber VARCHAR(266), weight REAL, weighingcount INTEGER DEFAULT 0,
                    averageweight DECIMAL(8,3) DEFAULT 0.000)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS sensordata4 (
                    id SERIAL PRIMARY KEY, water_level REAL, food_level REAL,
                    datetime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW())""")
            cur.execute("""CREATE TABLE IF NOT EXISTS feeding_schedule (
                    id SERIAL PRIMARY KEY, feed_time TIMESTAMP WITHOUT TIME ZONE,
                    feed_type VARCHAR(266), amount FLOAT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS chickens (
                    id SERIAL PRIMARY KEY, name VARCHAR(100), age INTEGER, weight FLOAT)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS chickstatus (
                    id SERIAL PRIMARY KEY, ChickNumber VARCHAR(266), status VARCHAR(100),
                    DateTime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW())""")
            cur.execute("""CREATE TABLE IF NOT EXISTS notifications (
                    id SERIAL PRIMARY KEY, message TEXT,
                    DateTime TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW())""")
    except Exception:
        app.logger.exception("init_tables: failed to ensure tables")

def create_default_admin():
    """Create default admin (admin/admin) if one doesn't exist."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username = 'admin' OR email = 'admin' LIMIT 1")
            if not cur.fetchone():
                admin_user = "admin"
                admin_email = "admin"
                admin_pass = generate_password_hash("admin", method="pbkdf2:sha256")
                admin_role = "admin"
                cur.execute(
                    "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s)",
                    (admin_user, admin_email, admin_pass, admin_role)
                )
                app.logger.info("Default admin account created (user: admin, email: admin).")
    except Exception as e:
        app.logger.exception(f"Failed to create default admin: {e}")

# Run startup tasks
init_tables()
create_default_admin()

# -------------------------
# Utilities & User Helpers
# -------------------------
def normalize_env_records(rows):
    """Converts DB rows to a normalized dict for the frontend."""
    out = []
    for r in rows:
        try: rec = dict(r)
        except Exception: rec = r
        dt = rec.get("datetime") or rec.get("timestamp") or rec.get("date")
        date_str, time_str = "", ""
        if isinstance(dt, datetime.datetime):
            date_str, time_str = dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S")
        else:
            try:
                parsed = datetime.datetime.fromisoformat(str(dt))
                date_str, time_str = parsed.strftime("%Y-%m-%d"), parsed.strftime("%H:%M:%S")
            except Exception:
                date_str = str(dt) if dt is not None else ""
        record = {
            "temperature": rec.get("temperature") if rec.get("temperature") is not None else rec.get("temp"),
            "humidity": rec.get("humidity"), "ammonia": rec.get("ammonia"),
            "light1": rec.get("light1"), "light2": rec.get("light2"),
            "exhaustfan": rec.get("exhaustfan"), "date": date_str, "time": time_str,
            **rec }
        out.append(record)
    return out

def get_growth_chart_data(limit=20):
    """Fetches formatted data for the growth chart."""
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
        app.logger.exception("get_growth_chart_data failed")
    return dates, weights

def get_user_by_email(email):
    """Fetches a user by their email address."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            return cur.fetchone()
    except Exception: return None

def get_user_by_username(username):
    """Fetches a user by their username."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()
    except Exception: return None

def get_user_by_id(user_id):
    """Fetches a user by their ID."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()
    except Exception: return None

def get_current_user():
    """Gets the currently logged-in user from the session."""
    return get_user_by_id(session.get("user_id"))

# -------------------------
# Decorators
# -------------------------
def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    """Decorator to require a specific role (e.g., 'admin')."""
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
# Main Routes (Login, Dashboard, etc. using WTForms)
# -------------------------
@app.route("/")
def home():
    """Redirects logged-in users to their respective dashboards."""
    if "user_id" in session:
        role = session.get("user_role")
        return redirect(url_for("admin_dashboard") if role in ["admin","superadmin"] else url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    """Handles user login."""
    if "user_id" in session:
        return redirect(url_for("home"))
    
    form = LoginForm()
    if form.validate_on_submit():
        login_identifier = form.email.data.strip() # Field is named 'email' in WTForm
        password = form.password.data
        
        user = None
        # Check if identifier is email or username
        if '@' in login_identifier or login_identifier == 'admin':
            user = get_user_by_email(login_identifier)
            if not user and login_identifier == 'admin':
                 user = get_user_by_username(login_identifier)
        else:
            user = get_user_by_username(login_identifier)
        
        if user and check_password_hash(user["password"], password):
            session.update({
                "user_id": user["id"], "user_role": user.get("role","user"),
                "user_username": user.get("username"), "user_email": user.get("email")
            })
            flash(f"Welcome, {user.get('username','User')}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials", "danger")
            
    return render_template("login.html", form=form)

@app.route("/register", methods=["GET","POST"])
def register():
    """Handles user registration."""
    if "user_id" in session:
        return redirect(url_for("home"))
        
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        hashed = generate_password_hash(form.password.data, method="pbkdf2:sha256")
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username,email,password,role) VALUES (%s,%s,%s,%s)",
                    (username,email,hashed,"user")
                )
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except pg_errors.UniqueViolation:
            flash("Email or Username already registered.", "danger")
        except Exception as e:
            app.logger.exception("Registration failed")
            flash(f"Database error: {e}", "danger")
            
    return render_template("register.html", form=form)

@app.route("/logout")
def logout():
    """Logs the user out by clearing the session."""
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    """Renders the main user dashboard."""
    return render_template("dashboard.html") # Data sent via SocketIO

@app.route("/main_dashboard")
@login_required
def main_dashboard():
    """Renders the main dashboard (alternative)."""
    return render_template("main-dashboard.html") # Data sent via SocketIO

@app.route("/admin-dashboard")
@role_required("admin","superadmin")
def admin_dashboard():
    """Renders the admin dashboard."""
    return render_template("admin-dashboard.html") # Data sent via SocketIO

@app.route("/profile")
@login_required
def profile():
    """Renders the user's profile page."""
    return render_template("profile.html", user=get_current_user())

@app.route("/settings", methods=["GET","POST"])
@login_required
def settings():
    """Handles updating user settings."""
    user = get_current_user()
    form = SettingsForm(obj=user) # Pre-populate form with user's current data
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip()
        new_pass = form.password.data
        
        try:
            with get_conn() as conn, conn.cursor() as cur:
                if new_pass:
                    hashed_pass = generate_password_hash(new_pass, method="pbkdf2:sha256")
                    cur.execute(
                        "UPDATE users SET username=%s, email=%s, password=%s WHERE id=%s",
                        (username, email, hashed_pass, user["id"])
                    )
                else:
                    cur.execute(
                        "UPDATE users SET username=%s, email=%s WHERE id=%s",
                        (username, email, user["id"])
                    )
            session.update({"user_username": username, "user_email": email})
            flash("Settings updated successfully.", "success")
            return redirect(url_for("settings"))
        except pg_errors.UniqueViolation:
             flash("Username or Email already exists.", "danger")
        except Exception:
            app.logger.exception("Failed to update settings")
            flash("Update failed. Try again later.", "danger")
            
    return render_template("settings.html", user=user, form=form)

@app.route("/manage-users")
@role_required("admin","superadmin")
def manage_users():
    """Renders the user management page for admins."""
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
    """Handles the 'Forgot Password' request."""
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data.strip()
        user = get_user_by_email(email)
        if user:
            try:
                token = serializer.dumps(email, salt="password-reset-salt")
                reset_url = url_for("reset_with_token", token=token, _external=True)
                msg = Message(
                    "ChickCare Password Reset",
                    sender=MAIL_USERNAME, recipients=[email],
                    body=f"Hi {user['username']},\nClick the link to reset your password:\n{reset_url}"
                )
                mail.send(msg)
                flash("Password reset link sent! Check your email.", "info")
            except Exception:
                app.logger.exception("Failed to send email")
                flash("Failed to send reset email. Try again later.", "danger")
        else:
            flash("Email not found.", "warning")
    return render_template("generate.html", form=form)

@app.route("/reset/<token>", methods=["GET","POST"])
def reset_with_token(token):
    """Handles the password reset using the token."""
    try:
        email = serializer.loads(token, salt="password-reset-salt", max_age=3600)
    except (SignatureExpired, BadSignature):
        flash("The reset link is invalid or has expired.", "danger")
        return redirect(url_for("generate"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_pass = generate_password_hash(form.password.data, method="pbkdf2:sha256")
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password=%s WHERE email=%s",
                    (hashed_pass, email)
                )
            flash("Password reset successful! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception:
            app.logger.exception("Password reset failed")
            flash("Could not reset password. Try again later.", "danger")
            
    return render_template("reset_password.html", token=token, form=form)

# -------------------------
# Page Rendering Routes (for HTML templates)
# -------------------------

@app.route("/growth-monitoring")
@app.route("/webcam")
@login_required
def growth_monitoring():
    return render_template("growth.html") # Data sent via SocketIO

@app.route("/feed-schedule")
@app.route("/feeding")
@login_required
def feed_schedule():
    return render_template("feeding.html") # Data sent via SocketIO

@app.route("/environment")
@login_required
def environment():
    return render_template("environment.html") # Data sent via SocketIO

@app.route("/sanitization")
@login_required
def sanitization():
    return render_template("sanitization.html") # Data sent via SocketIO

@app.route("/report")
@login_required
def report():
    return render_template("report.html")

# -----------------------------------------------
# Internal Data-Fetching Functions (for SocketIO)
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
                result[field_name] = str(result[field_name])
    return results

def get_growth_data():
    """Fetches ChickNumber and Weight from sensordata3."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, ChickNumber, Weight FROM sensordata3 ORDER BY DateTime DESC LIMIT 10")
            return format_datetime_in_results(cur.fetchall(), "datetime")
    except Exception: return []

def get_sanitization_data():
    """Fetches Sanitization data from sensordata2."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT Conveyor, Sprinkle, UVLight FROM sensordata2 ORDER BY DateTime DESC LIMIT 1")
            return cur.fetchall()
    except Exception: return []

def get_feeding_stock_data():
    """Fetches Food/Water stock from sensordata1."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, Food, Water FROM sensordata1 ORDER BY DateTime DESC LIMIT 10")
            return format_datetime_in_results(cur.fetchall(), "datetime")
    except Exception: return []

def get_supplies_level_data():
    """Fetches Water/Food Levels from sensordata4."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, Water_Level, Food_Level FROM sensordata4 ORDER BY DateTime DESC LIMIT 10")
            return format_datetime_in_results(cur.fetchall(), "datetime")
    except Exception: return []

def get_environment_data():
    """Fetches Environment data from sensordata."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, Humidity, Temperature, Ammonia, Light1, Light2, ExhaustFan FROM sensordata ORDER BY DateTime DESC LIMIT 10")
            return format_datetime_in_results(cur.fetchall(), "datetime")
    except Exception: return []

def get_chickstatus_data():
    """Fetches Chick Health Status from chickstatus."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, ChickNumber, status FROM chickstatus ORDER BY DateTime DESC LIMIT 10")
            return format_datetime_in_results(cur.fetchall(), "datetime")
    except Exception: return []

def get_notifications_data():
    """Fetches Notifications."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT DateTime, message FROM notifications ORDER BY DateTime DESC LIMIT 5")
            return format_datetime_in_results(cur.fetchall(), "datetime")
    except Exception: return []

def get_image_list_data():
    """Fetches list of images from static/shots."""
    try:
        image_dir = os.path.join(app.static_folder, 'shots')
        if not os.path.exists(image_dir): return []
        all_files = os.listdir(image_dir)
        image_files = [f for f in all_files if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))]
        image_files.sort()
        return image_files
    except Exception: return []

# -----------------------------------------------
# Data Fetching API Routes (for external calls or polling)
# -----------------------------------------------

@app.route('/get_all_data1')
@app.route('/get_growth_data')
def api_get_growth_data():
    return jsonify(get_growth_data())

@app.route('/get_all_data2')
@app.route('/get_sanitization_data')
def api_get_sanitization_data():
    return jsonify(get_sanitization_data())

@app.route('/get_all_data3')
def api_get_feeding_stock_data():
    return jsonify(get_feeding_stock_data())

@app.route('/get_all_data4')
@app.route('/get_supplies_data')
def api_get_supplies_level_data():
    return jsonify(get_supplies_level_data())

@app.route('/get_all_data5')
@app.route('/get_environment_data')
@app.route('/get_all_data')
@app.route('/data')
def api_get_environment_data():
    return jsonify(get_environment_data())

@app.route('/get_all_data6')
@app.route('/get_chickstatus_data')
def api_get_chickstatus_data():
    return jsonify(get_chickstatus_data())

@app.route('/get_all_data7')
@app.route('/get_notifications_data')
def api_get_notifications_data():
    return jsonify(get_notifications_data())
        
@app.route("/get_image_list")
@login_required 
def api_get_image_list():
    return jsonify(get_image_list_data())
        
# -----------------------------------------------
# Hardware "STOP" Button Routes
# -----------------------------------------------

@app.route("/stop_water_relay", methods=["POST"])
@login_required
def stop_water_relay():
    """Handles the 'STOP' button for the water relay."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, %s, %s)",
                (datetime.datetime.now(), 'OFF', 'OFF')
            )
        return jsonify({"success": "Water relay stopped"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stop_servo_food", methods=["POST"])
@login_required
def stop_servo_food():
    """Handles the 'STOP' button for the food servo."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, %s, %s)",
                (datetime.datetime.now(), 'OFF', 'OFF')
            )
        return jsonify({"success": "Servo food stopped"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stop_conveyor", methods=["POST"])
@login_required
def stop_conveyor():
    """Handles the 'STOP' button for the conveyor."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)",
                (datetime.datetime.now(), 'OFF', 'OFF', 'OFF')
            )
        return jsonify({"success": "Conveyor stopped"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stop_sprinkle", methods=["POST"])
@login_required
def stop_sprinkle():
    """Handles the 'STOP' button for the sprinkler."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)",
                (datetime.datetime.now(), 'OFF', 'OFF', 'OFF')
            )
        return jsonify({"success": "Sprinkle stopped"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stop_uvlight", methods=["POST"])
@login_required
def stop_uvlight():
    """Handles the 'STOP' button for the UV light."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)",
                (datetime.datetime.now(), 'OFF', 'OFF', 'OFF')
            )
        return jsonify({"success": "UV light stopped"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# -------------------------
# SocketIO Real-time Events
# -------------------------

# Background thread to send data
def background_data_emitter():
    """Fetches data and emits it to clients every 5 seconds."""
    app.logger.info("Starting background data emitter...")
    while True:
        try:
            # Fetch all data
            env_data = get_environment_data()
            growth_data = get_growth_data()
            sanitization_data = get_sanitization_data()
            supplies_level = get_supplies_level_data()
            feeding_stock = get_feeding_stock_data()
            chick_status = get_chickstatus_data()
            notifications = get_notifications_data()
            image_list = get_image_list_data()

            # Emit all data to clients
            socketio.emit('update_environment', {'data': env_data})
            socketio.emit('update_growth', {'data': growth_data})
            socketio.emit('update_sanitization', {'data': sanitization_data})
            socketio.emit('update_supplies_level', {'data': supplies_level})
            socketio.emit('update_feeding_stock', {'data': feeding_stock})
            socketio.emit('update_chickstatus', {'data': chick_status})
            socketio.emit('update_notifications', {'data': notifications})
            socketio.emit('update_image_list', {'data': image_list})

        except Exception as e:
            app.logger.error(f"Error in background data emitter: {e}")
        
        socketio.sleep(5) # Use socketio.sleep() for eventlet

@socketio.on('connect')
def handle_connect():
    app.logger.info('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info('Client disconnected')

# ------------------------
# Main
# ------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    # Start the background task
    socketio.start_background_task(background_data_emitter)
    # Run the app with SocketIO and eventlet
    app.logger.info(f"Starting SocketIO server on host=0.0.0.0, port={port}")
    socketio.run(app, debug=DEBUG, host="0.0.0.0", port=port)
