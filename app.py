# app.py - full rewrite
# This version is identical to cpdetxt.txt,
# except for the init-db command, which now points to the fixed SQL file.

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

# -------------------------\
# App config
# -------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)
logger = app.logger

# Environment / secrets (use real env in production)
# You can set these in Render / your environment:
# SUPER_ADMIN_USER, SUPER_ADMIN_EMAIL, SUPER_ADMIN_PASS
app.secret_key = os.environ.get("SECRET_KEY", "change_me_for_prod")
DB_URL_RAW = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/db")
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1")

# Superadmin fallback credentials (from environment)
SUPER_ADMIN_USER = os.environ.get("SUPER_ADMIN_USER", "superadmin")
SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL", "superadmin@example.com")
SUPER_ADMIN_PASS = os.environ.get("SUPER_ADMIN_PASS", "superadmin_pass")

# Global pool object
db_pool = None

# Mail config
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = MAIL_USERNAME
app.config["MAIL_PASSWORD"] = SMTP_PASSWORD
app.config["MAIL_DEFAULT_SENDER"] = ("Admin", MAIL_USERNAME)
mail = Mail(app)

# Token serializer for password reset
serializer = URLSafeTimedSerializer(app.secret_key)
SALT = "password-reset-salt"

# -------------------------\
# Role-based access decorator
# -------------------------
def role_required(*roles):
    """Decorator to restrict access to specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "role" not in session:
                flash("Please log in to access this page.", "danger")
                return redirect(url_for("login"))
            if session["role"] not in roles:
                flash("You do not have permission to view this page.", "danger")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# -------------------------\
# Login required decorator
# -------------------------
def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------\
# Auth Routes (Login, Logout, Register)
# -------------------------
@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email_or_user = request.form["email"]
        password = request.form["password"]

        try:
            with get_conn() as conn, conn.cursor() as cur:
                # Check database first
                cur.execute(
                    "SELECT * FROM users WHERE email = %s OR username = %s",
                    (email_or_user, email_or_user),
                )
                user = cur.fetchone()

                if user and check_password_hash(user["password"], password):
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    logger.info(f"User {user['username']} (role: {user['role']}) logged in.")
                    
                    if user["role"] == "admin":
                        return redirect(url_for("admin_dashboard"))
                    else:
                        return redirect(url_for("dashboard"))
                
                # --- Superadmin Fallback ---
                # If DB login fails, check against superadmin env vars
                is_super_email = (email_or_user == SUPER_ADMIN_EMAIL)
                is_super_user = (email_or_user == SUPER_ADMIN_USER)
                is_super_pass = (password == SUPER_ADMIN_PASS)

                if (is_super_email or is_super_user) and is_super_pass:
                    session["user_id"] = "superadmin"
                    session["username"] = "Superadmin"
                    session["role"] = "superadmin"
                    logger.info("Superadmin logged in.")
                    return redirect(url_for("admin_dashboard"))

                flash("Invalid email/username or password.", "danger")

        except Exception as e:
            logger.error(f"Login error: {e}")
            flash("An error occurred during login. Please try again.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles user registration."""
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        
        # Default role is 'user'
        role = "user" 

        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (email, username, password, role) VALUES (%s, %s, %s, %s)",
                    (email, username, hashed_password, role),
                )
                conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        
        except pg_errors.UniqueViolation:
            flash("Email or username already exists.", "danger")
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash("An error occurred. Please try again.", "danger")

    return render_template("register.html")


@app.route("/logout")
def logout():
    """Logs the user out."""
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# -------------------------\
# Database Connection
# -------------------------
def get_db_pool():
    """Initializes and returns the connection pool."""
    global db_pool
    if db_pool is None and ConnectionPool is not None:
        try:
            db_pool = ConnectionPool(
                conninfo=DB_URL_RAW,
                min_size=2,
                max_size=10,
                timeout=30,
                max_lifetime=300,
                # --- THIS IS THE ONLY LINE I ADDED ---
                kwargs={"row_factory": dict_row}
                # ---------------------------------------
            )
            logger.info("Connection pool created.")
        except Exception as e:
            logger.error(f"Failed to create connection pool: {e}")
            db_pool = None # Ensure it's None if creation fails
    return db_pool

def get_conn():
    """Gets a connection from the pool or creates a new one."""
    pool = get_db_pool()
    if pool:
        try:
            # This connection will now use dict_row from the pool's config
            return pool.getconn()
        except Exception as e:
            logger.error(f"Error getting connection from pool: {e}")
            # Fallback to direct connection if pool fails
            return psycopg.connect(DB_URL_RAW, row_factory=dict_row)
    else:
        # Fallback if pooling is not available or failed to init
        return psycopg.connect(DB_URL_RAW, row_factory=dict_row)

def release_conn(conn):
    """Releases a connection back to the pool."""
    pool = get_db_pool()
    if pool and conn:
        try:
            pool.putconn(conn)
        except Exception as e:
            logger.error(f"Error releasing connection to pool: {e}")
            conn.close() # Close if it can't be put back
    elif conn:
        conn.close() # Close if no pool


@app.cli.command("init-db")
def init_tables():
    """Create all tables defined in init_postgres_fixed.sql."""
    with get_conn() as conn, conn.cursor() as cur:
        try:
            # --- THIS IS THE ONLY LINE I CHANGED ---
            with open("init_postgres_fixed.sql", "r") as f:
            # ---------------------------------------
                sql = f.read()
                cur.execute(sql)
            conn.commit()
            logger.info("Database tables created.")
        except pg_errors.UndefinedTable:
            conn.rollback()
            logger.error("Error: Could not drop tables (they may not exist). Retrying...")
            # If tables don't exist, DROP will fail. Try again without DROP.
            try:
                with open("init_postgres_fixed.sql", "r") as f:
                    # A bit crude, but remove DROP commands
                    sql_no_drops = "\n".join(
                        line for line in f.read().splitlines() 
                        if not line.strip().upper().startswith("DROP TABLE")
                    )
                    cur.execute(sql_no_drops)
                conn.commit()
                logger.info("Database tables created (without drops).")
            except Exception as e_retry:
                conn.rollback()
                logger.error(f"Failed to init tables on retry: {e_retry}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to init tables: {e}")


# -------------------------\
# Password Reset Routes
# -------------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Page for requesting a password reset."""
    if request.method == "POST":
        email = request.form["email"]
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
            
            if user:
                token = serializer.dumps(email, salt=SALT)
                reset_url = url_for("reset_password", token=token, _external=True)
                
                # Send email logic
                msg_title = "Password Reset Request"
                msg_body = f"Click the link to reset your password: {reset_url}"
                msg = Message(msg_title, recipients=[email], body=msg_body)
                
                try:
                    mail.send(msg)
                    flash("A password reset link has been sent to your email.", "success")
                except Exception as e:
                    logger.error(f"Mail send error: {e}")
                    flash("Failed to send reset email. Please check server config.", "danger")
            else:
                flash("Email not found.", "warning")
                
        except Exception as e:
            logger.error(f"Forgot password error: {e}")
            flash("An error occurred. Please try again.", "danger")
            
    return render_template("forgot-password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Page for resetting password using the token."""
    try:
        email = serializer.loads(token, salt=SALT, max_age=3600) # Token valid for 1 hour
    except SignatureExpired:
        flash("The password reset link has expired.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid password reset link.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["password"]
        hashed_password = generate_password_hash(new_password, method="pbkdf2:sha256")
        
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password = %s, reset_token = NULL WHERE email = %s",
                    (hashed_password, email)
                )
                conn.commit()
            flash("Your password has been updated successfully!", "success")
            return redirect(url_for("login"))
        except Exception as e:
            logger.error(f"Reset password error: {e}")
            flash("An error occurred while updating your password.", "danger")

    return render_template("reset-password.html", token=token)


# -------------------------\
# User Dashboard Routes
# -------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    """User dashboard."""
    return render_template("dashboard.html")

@app.route("/profile")
@login_required
def profile():
    """User profile page."""
    user_id = session["user_id"]
    if user_id == "superadmin":
        # Handle superadmin profile (no DB entry)
        user_data = {
            "username": "Superadmin",
            "email": SUPER_ADMIN_EMAIL,
            "role": "superadmin"
        }
        return render_template("profile.html", user=user_data)

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
        
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("login"))
            
        return render_template("profile.html", user=user)
    except Exception as e:
        logger.error(f"Profile load error: {e}")
        flash("Error loading profile.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/update-profile", methods=["POST"])
@login_required
def update_profile():
    """Handles profile updates."""
    user_id = session["user_id"]
    if user_id == "superadmin":
        flash("Superadmin profile cannot be modified via this form.", "warning")
        return redirect(url_for("profile"))

    username = request.form["username"]
    email = request.form["email"]
    
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET username = %s, email = %s WHERE id = %s",
                (username, email, user_id)
            )
            conn.commit()
            
        # Update session
        session["username"] = username
        flash("Profile updated successfully!", "success")
        
    except pg_errors.UniqueViolation:
        flash("Email or username already in use.", "danger")
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        flash("Error updating profile.", "danger")
        
    return redirect(url_for("profile"))


@app.route("/update-password", methods=["POST"])
@login_required
def update_password():
    """Handles password updates from profile page."""
    user_id = session["user_id"]
    if user_id == "superadmin":
        flash("Superadmin password must be changed via environment variables.", "danger")
        return redirect(url_for("profile"))

    old_pass = request.form["old_password"]
    new_pass = request.form["new_password"]

    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            
            if not user or not check_password_hash(user["password"], old_pass):
                flash("Incorrect old password.", "danger")
                return redirect(url_for("profile"))
                
            new_hashed_pass = generate_password_hash(new_pass, method="pbkdf2:sha256")
            cur.execute(
                "UPDATE users SET password = %s WHERE id = %s",
                (new_hashed_pass, user_id)
            )
            conn.commit()
            
        flash("Password updated successfully!", "success")
        
    except Exception as e:
        logger.error(f"Password update error: {e}")
        flash("Error updating password.", "danger")
        
    return redirect(url_for("profile"))


# -------------------------\
# Admin Routes
# -------------------------
@app.route("/admin-dashboard")
@role_required("admin", "superadmin")
def admin_dashboard():
    """Admin dashboard."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            # Get user count
            cur.execute("SELECT COUNT(*) AS user_count FROM users")
            user_count = cur.fetchone()["user_count"]
            
            # Get recent activity (example: recent sensor data)
            cur.execute("SELECT * FROM sensordata ORDER BY datetime DESC LIMIT 5")
            recent_activity = cur.fetchall()
            
        return render_template(
            "admin-dashboard.html",
            user_count=user_count,
            recent_activity=recent_activity
        )
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        flash("Error loading admin dashboard.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/manage-users")
@role_required("admin", "superadmin")
def manage_users():
    """Page to manage users."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role FROM users")
            users = cur.fetchall()
        return render_template("manage-users.html", users=users)
    except Exception as e:
        logger.error(f"Manage users error: {e}")
        flash("Error loading user management page.", "danger")
        return redirect(url_for("admin_dashboard"))

# Note: Add routes for admin to edit/delete users (omitted for brevity)

# -------------------------\
# Sensor Data API (Mock)
# -------------------------
# These routes provide data to the frontend charts
@app.route("/api/sensor_data")
@login_required
def get_sensor_data():
    """API endpoint to fetch main sensor data."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM sensordata ORDER BY datetime DESC LIMIT 1")
            latest_data = cur.fetchone()
            
            cur.execute("SELECT * FROM sensordata4 ORDER BY datetime DESC LIMIT 1")
            latest_data4 = cur.fetchone()

            cur.execute("SELECT * FROM sensordata3 ORDER BY datetime DESC LIMIT 1")
            latest_data3 = cur.fetchone()

            if not latest_data: latest_data = {}
            if not latest_data4: latest_data4 = {}
            if not latest_data3: latest_data3 = {}

            # Combine latest data from all tables
            combined_data = {**latest_data, **latest_data4, **latest_data3}
            
        return jsonify(combined_data)
    except Exception as e:
        logger.error(f"API sensor_data error: {e}")
        return jsonify({"error": "server error"}), 500


@app.route("/api/chart_data")
@login_required
def get_chart_data():
    """API endpoint for chart history."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT datetime, temperature, humidity, ammonia 
                FROM sensordata 
                ORDER BY datetime DESC 
                LIMIT 50
            """)
            # Fetchall() returns a list of dicts, which is JSON-serializable
            data = cur.fetchall()
        return jsonify(data)
    except Exception as e:
        logger.error(f"API chart_data error: {e}")
        return jsonify({"error": "server error"}), 500

# -------------------------\
# Hardware Control API
# -------------------------
# These routes receive POST requests (e.g., from buttons)
# to log a control action.

@app.route("/toggle_light1", methods=["POST"])
@login_required
def toggle_light1():
    try:
        state = request.json.get("state", "OFF") # "ON" or "OFF"
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sensordata (datetime, humidity, temperature, ammonia, light1, light2, exhaustfan) 
                   VALUES (%s, 0, 0, 0, %s, 'N/A', 'N/A')""",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_light1 failed")
        return jsonify({"error": "server error"}), 500

@app.route("/toggle_light2", methods=["POST"])
@login_required
def toggle_light2():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sensordata (datetime, humidity, temperature, ammonia, light1, light2, exhaustfan) 
                   VALUES (%s, 0, 0, 0, 'N/A', %s, 'N/A')""",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_light2 failed")
        return jsonify({"error": "server error"}), 500

@app.route("/toggle_exhaust", methods=["POST"])
@login_required
def toggle_exhaust():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO sensordata (datetime, humidity, temperature, ammonia, light1, light2, exhaustfan) 
                   VALUES (%s, 0, 0, 0, 'N/A', 'N/A', %s)""",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_exhaust failed")
        return jsonify({"error": "server error"}), 500

# Control routes for sensordata1
@app.route("/toggle_food", methods=["POST"])
@login_required
def toggle_food():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, %s, 'N/A')",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_food failed")
        return jsonify({"error": "server error"}), 500

@app.route("/toggle_water", methods=["POST"])
@login_required
def toggle_water():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, 'N/A', %s)",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_water failed")
        return jsonify({"error": "server error"}), 500

# Control routes for sensordata2
@app.route("/toggle_conveyor", methods=["POST"])
@login_required
def toggle_conveyor():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, 'N/A', 'N/A')",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_conveyor failed")
        return jsonify({"error": "server error"}), 500

@app.route("/toggle_sprinkle", methods=["POST"])
@login_required
def toggle_sprinkle():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, 'N/A', %s, 'N/A')",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_sprinkle failed")
        return jsonify({"error": "server error"}), 500

@app.route("/toggle_uvlight", methods=["POST"])
@login_required
def toggle_uvlight():
    try:
        state = request.json.get("state", "OFF")
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, 'N/A', 'N/A', %s)",
                (datetime.datetime.now(), state)
            )
            conn.commit()
        return jsonify({"success": True, "state": state})
    except Exception as e:
        logger.exception("toggle_uvlight failed")
        return jsonify({"error": "server error"}), 500

# Mock "stop all" functions
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

# -------------------------\
# Run
# -------------------------
if __name__ == "__GUNICORN__":
    # Gunicorn entry point
    # Init pool on worker start
    get_db_pool()

if __name__ == "__main__":
    # Flask dev server entry point
    if not DEBUG:
        logger.warning("Running in production mode. Use Gunicorn for production.")
    
    # Init pool for dev server
    get_db_pool()
    
    app.run(debug=DEBUG, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
