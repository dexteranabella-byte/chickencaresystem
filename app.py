# app.py
# ----------
# This is a rewritten version of the application.
# - All SMTP/email/password-reset functionality has been REMOVED.
# - Database connections are now correctly managed using a connection pool
#   and helper functions (get_db_conn, close_db_conn).
# - All routes have been updated to use this new connection logic.

import os
import logging
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg
from psycopg.rows import dict_row
import psycopg.errors as pg_errors

# -------------------------\
# App config
# -------------------------\
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)
logger = app.logger

# Use psycopg_pool if available
try:
    from psycopg_pool import ConnectionPool
    logger.info("psycopg_pool imported successfully.")
except ImportError:
    ConnectionPool = None
    logger.warning("psycopg_pool not found. Connection pooling will be disabled.")

# -------------------------\
# App config
# -------------------------\
app = Flask(__name__, static_folder="static", template_folder="templates")
logging.basicConfig(level=logging.INFO)
logger = app.logger

# --- Environment / Secrets ---
# Use real environment variables in production
app.secret_key = os.environ.get("SECRET_KEY", "change_me_for_prod_a9sd8f7a9s8df")
DB_URL_RAW = os.environ.get("DATABASE_URL", "postgresql://user:pass@localhost/db")
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1")

# --- Superadmin fallback ---
# This creates a default admin if the users table is empty
SUPERADMIN_USER = os.environ.get("SUPERADMIN_USER", "admin")
SUPERADMIN_PASS = os.environ.get("SUPERADMIN_PASS", "adminpass")
SUPERADMIN_EMAIL = os.environ.get("SUPERADMIN_EMAIL", "admin@example.com")

# -------------------------\
# Database Pool Setup
# -------------------------\
db_url = DB_URL_RAW
pool = None

if ConnectionPool:
    try:
        pool = ConnectionPool(conninfo=db_url, min_size=2, max_size=10)
        logger.info("Psycopg ConnectionPool created.")
    except Exception as e:
        logger.error(f"Failed to create ConnectionPool: {e}")
        ConnectionPool = None # Disable pooling if setup fails
else:
    logger.warning("ConnectionPool not available. Using simple (less efficient) psycopg connections.")

def get_db_conn():
    """Gets a connection from the pool or creates a new one."""
    if pool:
        return pool.getconn()
    logger.warning("No pool. Creating new ad-hoc connection.")
    return psycopg.connect(db_url, row_factory=dict_row)

def close_db_conn(conn):
    """Returns a connection to the pool or closes it."""
    if pool:
        pool.putconn(conn)
    else:
        conn.close()

def execute_control_command(query, params=None):
    """
    Helper function to execute sensor control commands (INSERTs).
    Handles its own connection.
    """
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(query, params)
        conn.commit()
        return True
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"DB Error in execute_control_command: {error}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            close_db_conn(conn)

def init_superadmin():
    """Checks for users and creates a superadmin if table is empty."""
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users LIMIT 1")
            if cur.fetchone() is None:
                logger.info("No users found. Creating superadmin...")
                hashed_password = generate_password_hash(SUPERADMIN_PASS)
                cur.execute(
                    "INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)",
                    (SUPERADMIN_USER, hashed_password, SUPERADMIN_EMAIL, 'admin')
                )
                conn.commit()
                logger.info(f"Superadmin '{SUPERADMIN_USER}' created.")
            else:
                logger.info("Database already has users.")
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Superadmin creation error: {error}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            close_db_conn(conn)

# -------------------------\
# Auth Decorators
# -------------------------\
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash("Please login to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash("You do not have permission to access this page.", "danger")
            # Redirect to user dashboard if they are logged in but not admin
            if 'loggedin' in session:
                return redirect(url_for('main_dashboard'))
            # Redirect to login if session is completely missing
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -------------------------\
# Auth Routes
# -------------------------\
@app.route('/')
def home():
    """Redirects root to login page."""
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    if 'loggedin' in session:
        return redirect(url_for('main_dashboard')) # Already logged in

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        hashed_password = generate_password_hash(password)
        conn = None
        
        try:
            conn = get_db_conn()
            with conn.cursor(row_factory=dict_row) as cur:
                # Check if account already exists
                cur.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
                account = cur.fetchone()
                
                if account:
                    flash('Account already exists!', 'danger')
                else:
                    # Insert new account
                    cur.execute(
                        "INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)",
                        (username, hashed_password, email, 'user')
                    )
                    conn.commit()
                    flash('You have successfully registered! Please log in.', 'success')
                    return redirect(url_for('login'))
        except (Exception, pg_errors.DatabaseError) as error:
            logger.error(f"Registration Error: {error}")
            if conn:
                conn.rollback()
            flash('Database error during registration. Please try again.', 'danger')
        finally:
            if conn:
                close_db_conn(conn)
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page."""
    if 'loggedin' in session:
        # User is already logged in, send to appropriate dashboard
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('main_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = None
        
        try:
            conn = get_db_conn()
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                account = cur.fetchone()
                
                if account and check_password_hash(account['password'], password):
                    # Create session data
                    session['loggedin'] = True
                    session['id'] = account['id']
                    session['username'] = account['username']
                    session['role'] = account['role']
                    
                    logger.info(f"User {username} (Role: {account['role']}) logged in.")
                    
                    # Redirect based on role
                    if account['role'] == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    else:
                        return redirect(url_for('main_dashboard'))
                else:
                    flash('Incorrect username or password!', 'danger')
        except (Exception, pg_errors.DatabaseError) as error:
            logger.error(f"Login Error: {error}")
            flash('Database error during login. Please try again.', 'danger')
        finally:
            if conn:
                close_db_conn(conn)
                
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# -------------------------\
# User Profile Routes
# -------------------------\
@app.route('/profile')
@login_required
def profile():
    """Displays the user's profile page."""
    conn = None
    account = None
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (session['id'],))
            account = cur.fetchone()
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Profile load error for user {session.get('id')}: {error}")
        flash("Error loading profile.", "danger")
    finally:
        if conn:
            close_db_conn(conn)
    
    if account:
        return render_template('profile.html', account=account)
    
    # Failsafe if user isn't found (e.g., deleted)
    flash("Could not find your account.", "danger")
    return redirect(url_for('logout'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    """Handles submission of the profile update form."""
    username = request.form['username']
    email = request.form['email']
    password = request.form.get('password') # Optional
    
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            # Check for conflicts
            cur.execute(
                "SELECT id FROM users WHERE (username = %s OR email = %s) AND id != %s",
                (username, email, session['id'])
            )
            if cur.fetchone():
                flash("Username or email already taken.", "danger")
                return redirect(url_for('profile'))

            if password:
                # User wants to update password
                hashed_password = generate_password_hash(password)
                cur.execute(
                    "UPDATE users SET username = %s, email = %s, password = %s WHERE id = %s",
                    (username, email, hashed_password, session['id'])
                )
            else:
                # User does not want to update password
                cur.execute(
                    "UPDATE users SET username = %s, email = %s WHERE id = %s",
                    (username, email, session['id'])
                )
            conn.commit()
            
            # Update session
            session['username'] = username
            flash("Profile updated successfully!", "success")
            
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Profile update error for user {session.get('id')}: {error}")
        if conn:
            conn.rollback()
        flash("Error updating profile.", "danger")
    finally:
        if conn:
            close_db_conn(conn)
    
    return redirect(url_for('profile'))

@app.route('/settings')
@login_required
def settings():
    """Renders the settings page."""
    return render_template('settings.html')

# -------------------------\
# Admin Routes
# -------------------------\
@app.route('/admin-dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin-specific dashboard."""
    return render_template('admin-dashboard.html')

@app.route('/manage-users')
@login_required
@admin_required
def manage_users():
    """Page to list, edit, and delete users."""
    conn = None
    users = []
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            # Select all users EXCEPT the superadmin, if configured
            # For simplicity, we'll just show all users
            cur.execute("SELECT id, username, email, role FROM users")
            users = cur.fetchall()
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Manage users load error: {error}")
        flash("Error loading user list.", "danger")
    finally:
        if conn:
            close_db_conn(conn)
            
    return render_template('manage-users.html', users=users)

@app.route('/edit_user/<int:user_id>')
@login_required
@admin_required
def edit_user(user_id):
    """Page to edit a specific user's details."""
    conn = None
    user = None
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Edit user load error: {error}")
    finally:
        if conn:
            close_db_conn(conn)
    
    if user:
        return render_template('edit-user.html', user=user)
    
    flash("User not found.", "danger")
    return redirect(url_for('manage_users'))

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    """Handles submission of the admin's user update form."""
    username = request.form['username']
    email = request.form['email']
    role = request.form['role']
    password = request.form.get('password') # Optional

    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            # Check for conflicts
            cur.execute(
                "SELECT id FROM users WHERE (username = %s OR email = %s) AND id != %s",
                (username, email, user_id)
            )
            if cur.fetchone():
                flash("Username or email already taken by another user.", "danger")
                return redirect(url_for('edit_user', user_id=user_id))
                
            if password:
                hashed_password = generate_password_hash(password)
                cur.execute(
                    "UPDATE users SET username = %s, email = %s, role = %s, password = %s WHERE id = %s",
                    (username, email, role, hashed_password, user_id)
                )
            else:
                cur.execute(
                    "UPDATE users SET username = %s, email = %s, role = %s WHERE id = %s",
                    (username, email, role, user_id)
                )
            conn.commit()
            flash("User updated successfully!", "success")
            
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Admin update user error for user {user_id}: {error}")
        if conn:
            conn.rollback()
        flash("Error updating user.", "danger")
    finally:
        if conn:
            close_db_conn(conn)
            
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    """Deletes a user."""
    if user_id == session['id']:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('manage_users'))
        
    conn = None
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
        flash("User deleted successfully.", "success")
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Delete user error for user {user_id}: {error}")
        if conn:
            conn.rollback()
        flash("Error deleting user.", "danger")
    finally:
        if conn:
            close_db_conn(conn)
            
    return redirect(url_for('manage_users'))

# -------------------------\
# Main App Page Routes
# -------------------------\
@app.route('/main-dashboard')
@login_required
def main_dashboard():
    """Main dashboard for non-admin users."""
    return render_template('main-dashboard.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """(Legacy?) dashboard. Kept as it was in the template list."""
    return render_template('dashboard.html')

@app.route('/environment')
@login_required
def environment():
    """Environment monitoring page."""
    return render_template('environment.html')

@app.route('/get_env_data')
@login_required
def get_env_data():
    """AJAX endpoint to get environment data."""
    conn = None
    data = []
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            # Get latest 100 records
            cur.execute("SELECT * FROM sensordata ORDER BY datetime DESC LIMIT 100")
            data = cur.fetchall()
            # Convert datetime to ISO format for JSON
            for row in data:
                if 'datetime' in row and isinstance(row['datetime'], datetime.datetime):
                    row['datetime'] = row['datetime'].isoformat()
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Get env data error: {error}")
    finally:
        if conn:
            close_db_conn(conn)
    return jsonify(data)

@app.route('/feeding')
@login_required
def feeding():
    """Feeding and control page."""
    return render_template('feeding.html')

@app.route('/get_feeding_data')
@login_required
def get_feeding_data():
    """AJAX endpoint to get feeding/control data."""
    conn = None
    data = []
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM sensordata2 ORDER BY datetime DESC LIMIT 100")
            data = cur.fetchall()
            # Convert datetime to ISO format for JSON
            for row in data:
                if 'datetime' in row and isinstance(row['datetime'], datetime.datetime):
                    row['datetime'] = row['datetime'].isoformat()
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Get feeding data error: {error}")
    finally:
        if conn:
            close_db_conn(conn)
    return jsonify(data)

@app.route('/report')
@login_required
def report():
    """Page for viewing reports."""
    return render_template('report.html')

@app.route('/get_report_data')
@login_required
def get_report_data():
    """AJAX endpoint for combined report data."""
    conn = None
    env_data = []
    feed_data = []
    try:
        conn = get_db_conn()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM sensordata ORDER BY datetime DESC LIMIT 50")
            env_data = cur.fetchall()
            cur.execute("SELECT * FROM sensordata2 ORDER BY datetime DESC LIMIT 50")
            feed_data = cur.fetchall()
            
            # Convert datetimes for JSON
            for row in env_data:
                if 'datetime' in row and isinstance(row['datetime'], datetime.datetime):
                    row['datetime'] = row['datetime'].isoformat()
            for row in feed_data:
                if 'datetime' in row and isinstance(row['datetime'], datetime.datetime):
                    row['datetime'] = row['datetime'].isoformat()
                    
    except (Exception, pg_errors.DatabaseError) as error:
        logger.error(f"Get report data error: {error}")
    finally:
        if conn:
            close_db_conn(conn)
            
    return jsonify({'environment': env_data, 'feeding': feed_data})

@app.route('/webcam')
@login_required
def webcam():
    """Webcam streaming page."""
    return render_template('webcam.html')

# -------------------------\
# Control Routes (AJAX)
# -------------------------\
@app.route("/control_conveyor", methods=["POST"])
@login_required
def control_conveyor():
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    if execute_control_command(query, (datetime.datetime.now(), "ON", "OFF", "OFF")):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/control_sprinkle", methods=["POST"])
@login_required
def control_sprinkle():
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    if execute_control_command(query, (datetime.datetime.now(), "OFF", "ON", "OFF")):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/control_uvlight", methods=["POST"])
@login_required
def control_uvlight():
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    if execute_control_command(query, (datetime.datetime.now(), "OFF", "OFF", "ON")):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/stop_conveyor", methods=["POST"])
@login_required
def stop_conveyor():
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    if execute_control_command(query, (datetime.datetime.now(), "OFF", "OFF", "OFF")):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/stop_sprinkle", methods=["POST"])
@login_required
def stop_sprinkle():
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    if execute_control_command(query, (datetime.datetime.now(), "OFF", "OFF", "OFF")):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

@app.route("/stop_uvlight", methods=["POST"])
@login_required
def stop_uvlight():
    query = "INSERT INTO sensordata2 (datetime, conveyor, sprinkle, uvlight) VALUES (%s, %s, %s, %s)"
    if execute_control_command(query, (datetime.datetime.now(), "OFF", "OFF", "OFF")):
        return jsonify({"success": True})
    return jsonify({"error": "server error"}), 500

# -------------------------\
# Run
# -------------------------\
if __name__ == "__main__":
    # Run init_superadmin on startup
    with app.app_context():
        init_superadmin()
    
    # Run the app
    # Use 0.0.0.0 to be accessible externally (e.g., in Docker)
    app.run(debug=DEBUG, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
