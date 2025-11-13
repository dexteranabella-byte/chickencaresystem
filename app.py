# app.py
#
# This version removes all SMTP (flask_mail) and password reset
# functionality, as requested.
#
# It includes all other fixes:
# 1. Routes for ALL 16 form/template pages.
# 2. Correct database connection pooling for stable connections.
# 3. Fixed logic for /stop_conveyor, /stop_sprinkle, /stop_uvlight.
# 4. Added placeholder /get_all_data6 to remove frontend errors.
# 5. Full user management (add, edit, delete) with security checks.
# 6. Correct template filenames (main-dashboard.html, manage-users.html).
# 7. Moved init_db_pool() to the global scope to ensure it runs
#    when Gunicorn starts. This fixes "Connection pool is not initialized".
# 8. Added redirect routes for /sanitization and /report to fix 404 errors.
#

import os
import logging
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
# Removed flask_mail and itsdangerous imports
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg
from psycopg.rows import dict_row
import psycopg.errors as pg_errors

# optional pool
try:
    from psycopg_pool import ConnectionPool
    logging.getLogger("psycopg.pool").setLevel(logging.WARNING) # quiet pool logs
except Exception:
    ConnectionPool = None

# -------------------------
# App config
# -------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)
logger = app.logger

# Environment / secrets
app.secret_key = os.environ.get("SECRET_KEY", "change_me_for_prod")
DB_URL_RAW = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/db")
# Removed MAIL and SMTP env variables
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1")

# Superadmin fallback
SUPERADMIN_USER = os.environ.get("SUPERADMIN_USER", "superadmin")
SUPERADMIN_PASS_RAW = os.environ.get("SUPERADMIN_PASS", "superadminpass")
SUPERADMIN_PASS_HASH = generate_password_hash(SUPERADMIN_PASS_RAW)
SUPERADMIN_EMAIL = os.environ.get("SUPERADMIN_EMAIL", "admin@example.com")

# Removed Mail config section

# -------------------------
# DB Connection Pool
# -------------------------
db_pool = None

# ---- FIX: Initialize the pool when the app is imported ----
# This ensures Gunicorn workers will have an initialized pool.
def init_db_pool():
    global db_pool
    if ConnectionPool is None:
        logger.error("psycopg_pool library is not installed. App cannot use connection pooling.")
        return

    try:
        db_pool = ConnectionPool(
            conninfo=DB_URL_RAW,
            min_size=2,
            max_size=10,
            max_idle=30,
            max_lifetime=300,
            timeout=30
        )
        logger.info(f"Connection pool created. Min: 2, Max: 10")
    except Exception as e:
        logger.error(f"Failed to create connection pool: {e}")
        db_pool = None

def get_db_conn():
    if db_pool is None:
        logger.error("Connection pool is not initialized.")
        raise Exception("Database pool not available")
    return db_pool.getconn()

def put_db_conn(conn):
    if db_pool:
        db_pool.putconn(conn)

def close_db_pool():
    if db_pool:
        db_pool.close()
        logger.info("Connection pool closed.")

# For Gunicorn
def on_boot(server):
    init_db_pool()

def on_exit(server):
    close_db_pool()

# ---- NEW: Call init_db_pool() immediately ----
init_db_pool()
# ----------------------------------------------------

# -------------------------
# Auth / Helpers
# -------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        if session.get("role") not in ("admin", "superadmin"):
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for("main_dashboard"))
        return f(*args, **kwargs)
    return decorated_function

def get_user_by_id(user_id):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            return user
    except Exception as e:
        logger.error(f"Error getting user by ID {user_id}: {e}")
        return None
    finally:
        if conn:
            put_db_conn(conn)

def execute_control_command(query, params):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error executing control command: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            put_db_conn(conn)

# -------------------------
# Main Routes
# -------------------------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("main_dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("main_dashboard"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Superadmin Fallback
        if username == SUPERADMIN_USER and check_password_hash(SUPERADMIN_PASS_HASH, password):
            conn = None
            try:
                conn = get_db_conn()
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute("SELECT * FROM users WHERE username = %s", (SUPERADMIN_USER,))
                    user = cur.fetchone()
                    if not user:
                        cur.execute(
                            "INSERT INTO users (email, username, password, role) VALUES (%s, %s, %s, %s) RETURNING id",
                            (SUPERADMIN_EMAIL, SUPERADMIN_USER, SUPERADMIN_PASS_HASH, "superadmin")
                        )
                        user_id = cur.fetchone()['id']
                        conn.commit()
                    else:
                        user_id = user['id']
                        if user['role'] != 'superadmin':
                            cur.execute("UPDATE users SET role = 'superadmin' WHERE id = %s", (user_id,))
                            conn.commit()
                    
                    session.clear()
                    session["user_id"] = user_id
                    session["username"] = SUPERADMIN_USER
                    session["role"] = "superadmin"
                    return redirect(url_for("main_dashboard"))
            except Exception as e:
                logger.error(f"Error during superadmin login/creation: {e}")
                if conn: conn.rollback()
                flash("Server error during superadmin login.", "danger")
            finally:
                if conn: put_db_conn(conn)
        
        # Regular User Login
        conn = None
        try:
            conn = get_db_conn()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user = cur.fetchone()
                if user and check_password_hash(user["password"], password):
                    session.clear()
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session["role"] = user["role"]
                    return redirect(url_for("main_dashboard"))
                else:
                    flash("Invalid username or password.", "danger")
        except Exception as e:
            logger.error(f"Error during user login: {e}")
            flash("An error occurred during login. Please try again.", "danger")
        finally:
            if conn:
                put_db_conn(conn)

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("main_dashboard"))
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password)
        conn = None
        try:
            conn = get_db_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (email, username, password, role) VALUES (%s, %s, %s, %s)",
                    (email, username, hashed_password, "user"),
                )
            conn.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except pg_errors.UniqueViolation:
            if conn: conn.rollback()
            flash("Email or username already exists.", "danger")
        except Exception as e:
            if conn: conn.rollback()
            logger.error(f"Error during registration: {e}")
            flash("An error occurred during registration.", "danger")
        finally:
            if conn:
                put_db_conn(conn)
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/profile")
@login_required
def profile():
    user = get_user_by_id(session["user_id"])
    if not user:
        flash("Could not find user data.", "danger")
        return redirect(url_for("main_dashboard"))
    return render_template("profile.html", user=user)

# ------------------------------------------------
# NEW SECTION: REDIRECTS FOR 404 ERRORS
# ------------------------------------------------

@app.route("/sanitization")
@login_required
def redirect_sanitization():
    # Fixes 404 error for /sanitization
    return redirect(url_for("sanitization_controls"))

@app.route("/report")
@login_required
def redirect_report():
    # Fixes 404 error for /report
    return redirect(url_for("reports"))

# ------------------------------------------------
# SECTION: ROUTES FOR ALL TEMPLATE PAGES
# (This fixes your "inaccessible forms" problem)
# ------------------------------------------------

@app.route("/main_dashboard")
@login_required
def main_dashboard():
    # Renders 'main-dashboard.html'
    return render_template("main-dashboard.html", username=session.get("username"))

@app.route("/admin_dashboard")
@admin_required
def admin_dashboard():
    # Renders 'admin-dashboard.html'
    return render_template("admin-dashboard.html")

@app.route("/dashboard")
@login_required
def dashboard():
    # Renders 'dashboard.html'
    return render_template("dashboard.html")

@app.route("/environment_controls")
@login_required
def environment_controls():
    # Renders 'environment.html'
    return render_template("environment.html")

@app.route("/feed_controls")
@login_required
def feed_controls():
    # Renders 'feed.html'
    return render_template("feed.html")

@app.route("/growth_monitoring")
@login_required
def growth_monitoring():
    # Renders 'growth.html'
    return render_template("growth.html")

@app.route("/sanitization_controls")
@login_required
def sanitization_controls():
    # Renders 'sanitization.html'
    return render_template("sanitization.html")

@app.route("/reports")
@login_required
def reports():
    # Renders 'report.html'
    return render_template("report.html")

@app.route("/generate_report")
@admin_required
def generate_report():
    # Renders 'generate.html'
    return render_template("generate.html")

@app.route("/settings")
@login_required
def settings():
    # Renders 'settings.html'
    return render_template("settings.html")

# -------------------------
# User Management (Admin)
# -------------------------
@app.route("/user_management")
@admin_required
def user_management():
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM users WHERE role != 'superadmin' ORDER BY id")
            users = cur.fetchall()
    except Exception as e:
        logger.error(f"Error fetching users for management: {e}")
        flash("Could not load users.", "danger")
        users = []
    finally:
        if conn:
            put_db_conn(conn)
    # Renders 'manage-users.html'
    return render_template("manage-users.html", users=users, current_user_role=session.get("role"))

@app.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    role = request.form.get("role")

    if not all([email, username, password, role]):
        flash("All fields are required.", "danger")
        return redirect(url_for("user_management"))
    if role == "admin" and session.get("role") != "superadmin":
        flash("You do not have permission to create admin users.", "danger")
        return redirect(url_for("user_management"))

    hashed_password = generate_password_hash(password)
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (email, username, password, role) VALUES (%s, %s, %s, %s)",
                (email, username, hashed_password, role)
            )
        conn.commit()
        flash("User added successfully.", "success")
    except pg_errors.UniqueViolation:
        if conn: conn.rollback()
        flash("Email or username already exists.", "danger")
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error adding user: {e}")
        flash("An error occurred while adding the user.", "danger")
    finally:
        if conn:
            put_db_conn(conn)
    return redirect(url_for("user_management"))

@app.route("/edit_user/<int:user_id>", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    if request.method == "POST":
        # This is the logic for processing the form
        email = request.form.get("email")
        username = request.form.get("username")
        role = request.form.get("role")

        if not all([email, username, role]):
            flash("Email, username, and role are required.", "danger")
            return redirect(url_for("user_management"))
        
        if role == "admin" and session.get("role") != "superadmin":
            flash("You do not have permission to edit admin users.", "danger")
            return redirect(url_for("user_management"))

        conn = None
        try:
            conn = get_db_conn()
            with conn.cursor() as cur:
                cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
                target_user = cur.fetchone()
                if target_user and target_user[0] == 'superadmin':
                    flash("Cannot edit a superadmin user.", "danger")
                else:
                    cur.execute(
                        "UPDATE users SET email = %s, username = %s, role = %s WHERE id = %s",
                        (email, username, role, user_id)
                    )
                    conn.commit()
                    flash("User updated successfully.", "success")
        except pg_errors.UniqueViolation:
            if conn: conn.rollback()
            flash("Email or username already exists for another user.", "danger")
        except Exception as e:
            if conn: conn.rollback()
            logger.error(f"Error editing user {user_id}: {e}")
            flash("An error occurred while editing the user.", "danger")
        finally:
            if conn:
                put_db_conn(conn)
        # On POST success or fail, redirect back to the main list
        return redirect(url_for("user_management"))

    # This is the logic for GET requests
    # Fetch the user's data to pre-fill the form
    user_to_edit = get_user_by_id(user_id)
    if not user_to_edit:
        flash("User not found.", "danger")
        return redirect(url_for("user_management"))
    
    if user_to_edit['role'] == 'superadmin':
            flash("Cannot edit a superadmin user.", "danger")
            return redirect(url_for("user_management"))

    # Renders 'edit-user.html'
    return render_template("edit-user.html", user=user_to_edit)

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("user_management"))

    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            target_user = cur.fetchone()
            if target_user and target_user[0] == 'superadmin':
                flash("Cannot delete a superadmin user.", "danger")
            else:
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                conn.commit()
                flash("User deleted successfully.", "success")
    except Exception as e:
        if conn: conn.rollback()
        logger.error(f"Error deleting user {user_id}: {e}")
        flash("An error occurred while deleting the user.", "danger")
    finally:
        if conn:
            put_db_conn(conn)
    return redirect(url_for("user_management"))

# -------------------------
# Password Reset (REMOVED)
# -------------------------
# @app.route("/forgot_password", ...) and
# @app.route("/reset_password/<token>", ...)
# have been removed as requested.

# Renders 'forgot_password.html'
@app.route("/forgot_password", methods=["GET"])
def forgot_password():
    # Renders the page, but functionality is disabled.
    # You can add a message to the template if you like.
    return render_template("forgot_password.html")

# Renders 'reset_password.html'
@app.route("/reset_password/<token>", methods=["GET"])
def reset_password(token):
    # Renders the page, but functionality is disabled.
    return render_template("reset_password.html", token=token)

# -------------------------
# Data API Routes (for Dashboard)
# -------------------------
def fetch_data_from_db(query, params=None, fetch_one=False):
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(query, params)
            data = cur.fetchone() if fetch_one else cur.fetchall()
        return data
    except Exception as e:
        logger.error(f"Error fetching data with query '{query}': {e}")
        return None if fetch_one else []
    finally:
        if conn:
            put_db_conn(conn)

@app.route("/data")
@login_required
def get_all_data():
    query = "SELECT * FROM sensordata ORDER BY datetime DESC LIMIT 1"
    data = fetch_data_from_db(query, fetch_one=True)
    return jsonify(data or {})

@app.route("/get_all_data3")
@login_required
def get_all_data3():
    query = "SELECT * FROM sensordata3 ORDER BY datetime DESC LIMIT 1"
    data = fetch_data_from_db(query, fetch_one=True)
    return jsonify(data or {})

@app.route("/get_all_data4")
@login_required
def get_all_data4():
    query = "SELECT * FROM sensordata4 ORDER BY datetime DESC LIMIT 1"
    data = fetch_data_from_db(query, fetch_one=True)
    return jsonify(data or {})

@app.route("/get_growth_data")
@login_required
def get_growth_data():
    query = "SELECT averageweight, datetime FROM sensordata3 ORDER BY datetime DESC LIMIT 20"
    data = fetch_data_from_db(query)
    return jsonify(list(reversed(data)))

@app.route("/get_chickstatus_data")
@login_required
def get_chickstatus_data():
    query = "SELECT * FROM chickstatus ORDER BY datetime DESC LIMIT 1"
    data = fetch_data_from_db(query, fetch_one=True)
    return jsonify(data or {})

@app.route("/get_notifications_data")
@login_required
def get_notifications_data():
    query = "SELECT * FROM notifications ORDER BY datetime DESC LIMIT 5"
    data = fetch_data_from_db(query)
    return jsonify(data)

@app.route("/get_all_data1")
@login_required
def get_all_data1():
    query = "SELECT * FROM sensordata1 ORDER BY datetime DESC LIMIT 1"
    data = fetch_data_from_db(query, fetch_one=True)
    return jsonify(data or {})

@app.route("/get_all_data2")
@login_required
def get_all_data2():
    query = "SELECT * FROM sensordata2 ORDER BY datetime DESC LIMIT 1"
    data = fetch_data_from_db(query, fetch_one=True)
    return jsonify(data or {})

@app.route("/get_all_data6")
@login_required
def get_all_data6():
    logger.warning("Frontend called /get_all_data6, which has no data source. Returning empty.")
    return jsonify({})

# -------------------------
# Control API Routes
# -------------------------
@app.route("/submit_data", methods=["POST"])
@login_required
def submit_data():
    light1 = request.form.get("light1", "OFF")
    light2 = request.form.get("light2", "OFF")
    exhaustfan = request.form.get("exhaustfan", "OFF")
    latest_data = fetch_data_from_db("SELECT humidity, temperature, ammonia FROM sensordata ORDER BY datetime DESC LIMIT 1", fetch_one=True)
    humidity, temperature, ammonia = (latest_data['humidity'], latest_data['temperature'], latest_data['ammonia']) if latest_data else (0, 0, 0)
    query = "INSERT INTO sensordata (datetime, humidity, temperature, ammonia, light1, light2, exhaustfan) VALUES (%s, %s, %s, %s, %s, %s, %s)"
    params = (datetime.datetime.now(), humidity, temperature, ammonia, light1, light2, exhaustfan)
    if execute_control_command(query, params):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/submit_data1", methods=["POST"])
@login_required
def submit_data1():
    food = request.form.get("food", "OFF")
    water = request.form.get("water", "OFF")
    query = "INSERT INTO sensordata1 (datetime, food, water) VALUES (%s, %s, %s)"
    params = (datetime.datetime.now(), food, water)
    if execute_control_command(query, params):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

def get_latest_sensordata2_state():
    default_state = {"conveyor": "OFF", "sprinkle": "OFF", "uvlight": "OFF"}
    latest_state = fetch_data_from_db("SELECT conveyor, sprinkle, uvlight FROM sensordata2 ORDER BY datetime DESC LIMIT 1", fetch_one=True)
    return latest_state or default_state

@app.route("/submit_data2", methods=["POST"])
@login_required
def submit_data2():
    current_state = get_latest_sensordata2_state()
    conveyor = request.form.get("conveyor", current_state["conveyor"])
    sprinkle = request.form.get("sprinkle", current_state["sprinkle"])
    uvlight = request.form.get("uvlight", current_state["uvlight"])
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    params = (datetime.datetime.now(), conveyor, sprinkle, uvlight)
    if execute_control_command(query, params):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/stop_conveyor", methods=["POST"])
@login_required
def stop_conveyor():
    current_state = get_latest_sensordata2_state()
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    params = (datetime.datetime.now(), "OFF", current_state["sprinkle"], current_state["uvlight"])
    if execute_control_command(query, params):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/stop_sprinkle", methods=["POST"])
@login_required
def stop_sprinkle():
    current_state = get_latest_sensordata2_state()
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    params = (datetime.datetime.now(), current_state["conveyor"], "OFF", current_state["uvlight"])
    if execute_control_command(query, params):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/stop_uvlight", methods=["POST"])
@login_required
def stop_uvlight():
    current_state = get_latest_sensordata2_state()
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    params = (datetime.datetime.now(), current_state["conveyor"], current_state["sprinkle"], "OFF")
    if execute_control_command(query, params):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    # This block now only runs for local testing (e.g., python app.py)
    # Gunicorn will import the file and run init_db_pool() automatically.
    app.run(host="0.0.0.0", port=10000, debug=DEBUG)
