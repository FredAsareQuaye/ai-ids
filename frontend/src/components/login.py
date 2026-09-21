import streamlit as st
import hashlib
import hmac
import base64
import os
import json
import time
import sqlite3
import uuid
import smtplib
from datetime import datetime, timedelta
from pathlib import Path
from email.mime.text import MIMEText

# Session token file path
SESSION_TOKEN_FILE = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'session_token.json')

# Database path for user management
DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')

# Initialize database with enhanced tables
def init_enhanced_database():
    """Initialize database with user management tables"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create users table with enhanced fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                active INTEGER DEFAULT 1,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT,
                reset_token TEXT,
                reset_token_expires TEXT
            )
        ''')
        
        # Check and add missing columns to existing users table
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add missing columns if they don't exist
        missing_columns = {
            'active': 'INTEGER DEFAULT 1',
            'failed_attempts': 'INTEGER DEFAULT 0',
            'locked_until': 'TEXT',
            'last_login': 'TEXT',
            'reset_token': 'TEXT',
            'reset_token_expires': 'TEXT',
            'email': 'TEXT',
            'role': 'TEXT DEFAULT "user"'
        }
        
        for column_name, column_def in missing_columns.items():
            if column_name not in columns:
                try:
                    cursor.execute(f'ALTER TABLE users ADD COLUMN {column_name} {column_def}')
                    print(f"Added missing column: {column_name}")
                except sqlite3.OperationalError as e:
                    if "duplicate column name" not in str(e).lower():
                        print(f"Error adding column {column_name}: {e}")
        
        # Update existing users to have default values
        cursor.execute('''
            UPDATE users SET 
                active = COALESCE(active, 1),
                failed_attempts = COALESCE(failed_attempts, 0),
                role = COALESCE(role, 'user')
            WHERE active IS NULL OR failed_attempts IS NULL OR role IS NULL
        ''')
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT,
                jwt_token TEXT,
                expires_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create notifications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT DEFAULT 'info',
                read INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create processed_logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_entry TEXT NOT NULL,
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                severity TEXT DEFAULT 'info'
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
        if cursor.fetchone()[0] == 0:
            admin_password = hash_password('admin123')
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role) 
                VALUES (?, ?, ?, ?)
            ''', ('admin', admin_password, 'admin@siem.local', 'admin'))
            
            # Add some sample notifications
            cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
            admin_id = cursor.fetchone()[0]
            
            sample_notifications = [
                ('System Alert', 'Enhanced authentication system activated', 'success'),
                ('Security Update', 'New login security features enabled', 'info'),
                ('Welcome', 'Welcome to the enhanced AI-IDS system', 'info')
            ]
            
            for title, message, ntype in sample_notifications:
                cursor.execute('''
                    INSERT INTO notifications (user_id, title, message, type) 
                    VALUES (?, ?, ?, ?)
                ''', (admin_id, title, message, ntype))
        
        conn.commit()
        conn.close()
        print("✅ Enhanced database initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        try:
            if 'conn' in locals():
                conn.close()
        except:
            pass
        return False

def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt"""
    salt = "siem_salt_2024"
    return hashlib.sha256((password + salt).encode()).hexdigest()

def save_session_token(username, token):
    """Save session token to file"""
    try:
        os.makedirs(os.path.dirname(SESSION_TOKEN_FILE), exist_ok=True)
        session_data = {
            'username': username,
            'token': token,
            'timestamp': time.time()
        }
        with open(SESSION_TOKEN_FILE, 'w') as f:
            json.dump(session_data, f)
    except Exception as e:
        print(f"Error saving session token: {e}")

def load_session_token():
    """Load session token from file with enhanced security checks"""
    try:
        if os.path.exists(SESSION_TOKEN_FILE):
            with open(SESSION_TOKEN_FILE, 'r') as f:
                session_data = json.load(f)
            
            # Check if token is less than 7 days old (reduced from 30 days for security)
            token_age = time.time() - session_data.get('timestamp', 0)
            max_age = 7 * 24 * 3600  # 7 days
            
            if token_age < max_age:
                # Validate token format (base64 encoded, 24 bytes = 32 chars when encoded)
                token = session_data.get('token', '')
                if len(token) == 32 and token.replace('/', '').replace('+', '').replace('=', '').isalnum():
                    return session_data.get('username'), token
                else:
                    # Invalid token format, clear it
                    clear_session_token()
            else:
                # Token expired, clear it
                clear_session_token()
    except Exception as e:
        # If any error occurs, clear the potentially corrupted token
        clear_session_token()
        pass  # Don't expose error details
    return None, None

def clear_session_token():
    """Clear session token file"""
    try:
        if os.path.exists(SESSION_TOKEN_FILE):
            os.remove(SESSION_TOKEN_FILE)
    except Exception as e:
        print(f"Error clearing session token: {e}")

def verify_password(username, password, stored_password=None):
    """Verify a password against a stored password hash"""
    try:
        # Load settings to check stored password hash
        from _pages.settings import load_settings
        settings = load_settings()
        
        # Get stored hash from settings
        stored_hash = settings.get("password_hash")
        
        # For backward compatibility, check default admin password if no hash is stored
        if not stored_hash and username.lower() == "admin":
            # Default password is 'admin' (for initial setup only)
            default_hash = hashlib.sha256("admin".encode()).hexdigest()
            provided_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # If default password is used, update it in settings
            if hmac.compare_digest(provided_hash, default_hash):
                # Save the default hash to settings for future use
                settings["password_hash"] = default_hash
                from _pages.settings import save_settings
                save_settings(settings)
                return True
            return False
        
        if not stored_hash:
            return False
        
        # Hash the provided password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Compare with the stored hash using constant-time comparison
        return hmac.compare_digest(password_hash, stored_hash)
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        return False

def authenticate_user_db(username: str, password: str):
    """Authenticate user against database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if user exists - handle missing columns gracefully
        try:
            cursor.execute('''
                SELECT id, username, password_hash, 
                       COALESCE(role, 'user') as role,
                       COALESCE(active, 1) as active,
                       COALESCE(failed_attempts, 0) as failed_attempts,
                       locked_until 
                FROM users WHERE username = ?
            ''', (username,))
        except sqlite3.OperationalError:
            # Fallback for old database structure
            cursor.execute('''
                SELECT id, username, password_hash, 'user' as role, 1 as active, 0 as failed_attempts, NULL as locked_until 
                FROM users WHERE username = ?
            ''', (username,))
        
        user = cursor.fetchone()
        if not user:
            conn.close()
            return False, None, "Invalid username or password"
        
        user_id, db_username, stored_hash, role, active, failed_attempts, locked_until = user
        
        # Check if account is locked
        if locked_until:
            lock_time = datetime.fromisoformat(locked_until)
            if datetime.utcnow() < lock_time:
                conn.close()
                return False, None, f"Account locked until {lock_time.strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Check if account is active
        if not active:
            conn.close()
            return False, None, "Account is disabled"
        
        # Verify password
        password_hash = hash_password(password)
        if password_hash == stored_hash:
            # Reset failed attempts on successful login
            cursor.execute('''
                UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? 
                WHERE id = ?
            ''', (datetime.utcnow().isoformat(), user_id))
            conn.commit()
            conn.close()
            
            user_data = {
                'id': user_id,
                'username': db_username,
                'role': role
            }
            return True, user_data, "Login successful"
        else:
            # Increment failed attempts
            new_attempts = failed_attempts + 1
            locked_until_time = None
            
            # Lock account after 5 failed attempts for 30 minutes
            if new_attempts >= 5:
                locked_until_time = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
            
            cursor.execute('''
                UPDATE users SET failed_attempts = ?, locked_until = ? 
                WHERE id = ?
            ''', (new_attempts, locked_until_time, user_id))
            conn.commit()
            conn.close()
            
            if locked_until_time:
                return False, None, "Too many failed attempts. Account locked for 30 minutes."
            else:
                remaining = 5 - new_attempts
                return False, None, f"Invalid password. {remaining} attempts remaining."
                
    except Exception as e:
        return False, None, f"Authentication error: {str(e)}"

def render_login():
    """Enhanced login page with database authentication"""
    # Initialize database
    init_enhanced_database()
    
    # Initialize session state
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = st.session_state.authenticated
    if "login_mode" not in st.session_state:
        st.session_state.login_mode = "login"
    if "username" not in st.session_state:
        st.session_state.username = ""
    if "user_role" not in st.session_state:
        st.session_state.user_role = "user"
    
    # Check for persistent session token
    if not st.session_state.authenticated and not st.session_state.get("session_checked", False):
        st.session_state.session_checked = True
        stored_username, stored_token = load_session_token()
        
        if stored_username and stored_token:
            # Verify the user still exists in database
            success, user_data, _ = authenticate_user_db(stored_username, "dummy")
            if success or user_data:  # Token exists, restore session
                st.session_state.authenticated = True
                st.session_state.logged_in = True
                st.session_state.username = stored_username
                st.session_state.user_role = user_data.get('role', 'user') if user_data else 'user'
                return True
    
    # If already authenticated, return True
    if st.session_state.authenticated:
        return True
    
    # Show login form
    if not st.session_state.authenticated:
        # Hide the sidebar when on login page
        st.markdown("""
        <style>
            [data-testid="stSidebar"] {display: none !important;}
        </style>
        """, unsafe_allow_html=True)
        # Add custom CSS for login page with 3D box styling
        st.markdown(
            """
            <style>
            .login-container {
                max-width: 400px;
                margin: 0 auto;
                padding: 2rem;
                border-radius: 10px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1), 0 1px 3px rgba(0, 0, 0, 0.08);
                background-color: #1e1e32;
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .login-header {
                text-align: center;
                margin-bottom: 2rem;
                color: white;
            }
            .login-header h1 {
                margin-bottom: 0.5rem;
                color: white;
            }
            .login-header h3 {
                font-weight: normal;
                opacity: 0.8;
                margin-top: 0;
                color: white;
            }
            /* Style for the box-3d effect */
            .box-3d {
                background: linear-gradient(145deg, #2a2a45, #1e1e32);
                border-radius: 10px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.1);
                padding: 20px;
                position: relative;
                overflow: hidden;
                color: white;
            }
            .box-3d::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: linear-gradient(45deg, transparent, rgba(255, 255, 255, 0.05), transparent);
                pointer-events: none;
            }
            </style>
            """,
            unsafe_allow_html=True
        )
        
        # Center the login form
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            # Use the box-3d class for the container
            st.markdown('<div class="box-3d login-container">', unsafe_allow_html=True)
            st.markdown('<div class="login-header"><h1>🛡️ AI-IDS</h1><h3>Intrusion Detection System</h3></div>', unsafe_allow_html=True)
            
            # Login form
            username = st.text_input("Username", placeholder="Enter your username", value="admin")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            remember_me = st.checkbox("Remember me")
            
            login_button = st.button("Login", use_container_width=True)
            
            if login_button:
                if username and password:
                    # Try database authentication first
                    success, user_data, message = authenticate_user_db(username, password)
                    
                    if success and user_data:
                        st.session_state.authenticated = True
                        st.session_state.logged_in = True
                        st.session_state.username = user_data['username']
                        st.session_state.user_role = user_data['role']
                        st.session_state.remember_me = remember_me
                        
                        # Create a secure auth token with timestamp and username hash
                        token_data = f"{username}:{time.time()}:{os.urandom(16).hex()}"
                        token = base64.b64encode(token_data.encode()).decode('utf-8')
                        st.session_state.auth_token = token
                        st.session_state.login_time = time.time()
                        
                        # Save session token if remember me is checked
                        if remember_me:
                            token = base64.urlsafe_b64encode(os.urandom(24)).decode()
                            save_session_token(username, token)
                        
                        # Set the initial view to main after successful login
                        st.session_state.view = 'main'
                        st.success(f"Welcome back, {user_data['username']}!")
                        time.sleep(1)
                        st.rerun()
                        
                    elif not success:
                        # Database authentication failed, try fallback
                        if verify_password(username, password):
                            st.session_state.authenticated = True
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.session_state.user_role = 'admin' if username.lower() == 'admin' else 'user'
                            st.session_state.remember_me = remember_me
                            st.session_state.login_time = time.time()
                            
                            if remember_me:
                                token = base64.urlsafe_b64encode(os.urandom(24)).decode()
                                save_session_token(username, token)
                            
                            st.session_state.view = 'main'
                            st.success(f"Welcome, {username}!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error(message if message else "Invalid username or password")
                    else:
                        st.error(message)
                else:
                    st.warning("Please enter both username and password")
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Add a note about default credentials
            st.markdown("""
            <div style="text-align: center; margin-top: 1rem; opacity: 0.7;">
            <small>Default credentials: username <code>admin</code> password <code>admin123</code></small>
            </div>
            """, unsafe_allow_html=True)
        
        return False
    
    return True

def logout():
    """Log out the user by clearing authentication state securely"""
    # Clear session token file
    clear_session_token()
    
    # Clear all authentication-related session state
    auth_keys = [
        "authenticated", "logged_in", "auth_token", "username", 
        "remember_me", "session_checked", "login_time", "login_attempts"
    ]
    
    for key in auth_keys:
        if key in st.session_state:
            del st.session_state[key]
    
    # Clear any sensitive data
    sensitive_keys = [
        "sudo_password_encoded", "selected_scan_for_display", 
        "scan_notifications", "last_log_check"
    ]
    
    for key in sensitive_keys:
        if key in st.session_state:
            del st.session_state[key]
    
    # Reset authentication state
    st.session_state.authenticated = False

def add_notification(message, title="System Alert", ntype="info"):
    """Add a notification - fallback for compatibility"""
    try:
        if 'username' in st.session_state and st.session_state.username:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get user ID
            cursor.execute('SELECT id FROM users WHERE username = ?', (st.session_state.username,))
            user = cursor.fetchone()
            
            if user:
                cursor.execute('''
                    INSERT INTO notifications (user_id, title, message, type) 
                    VALUES (?, ?, ?, ?)
                ''', (user[0], title, message, ntype))
                conn.commit()
            
            conn.close()
    except:
        # Fallback to streamlit message
        if ntype == "success":
            st.success(f"{title}: {message}")
        elif ntype == "error":
            st.error(f"{title}: {message}")
        elif ntype == "warning":
            st.warning(f"{title}: {message}")
        else:
            st.info(f"{title}: {message}")

def check_for_new_logs():
    """Check for new logs and notify if found"""
    try:
        import json
        from pathlib import Path
        from datetime import datetime, timedelta
        
        # Get the logs file path
        possible_paths = [
            Path("../server/data/dummy_logs.json"),
            Path("./server/data/dummy_logs.json"),
            Path("../data/dummy_logs.json"),
            Path("./data/dummy_logs.json"),
            Path("../../server/data/dummy_logs.json"),
        ]
        
        for log_path in possible_paths:
            if log_path.exists():
                try:
                    with open(log_path, 'r') as f:
                        logs = json.load(f)
                    
                    # Check for logs in the last 30 seconds
                    cutoff_time = datetime.now() - timedelta(seconds=30)
                    new_logs = []
                    
                    for log in logs:
                        try:
                            log_time = datetime.fromisoformat(log.get('timestamp', '').replace('Z', ''))
                            if log_time >= cutoff_time:
                                new_logs.append(log)
                        except:
                            continue
                    
                    if new_logs:
                        high_severity = sum(1 for log in new_logs if log.get('severity', '').lower() in ['high', 'critical'])
                        if high_severity > 0:
                            add_notification(
                                f"Found {len(new_logs)} new logs ({high_severity} high/critical severity)", 
                                "New Security Events", 
                                "warning"
                            )
                        else:
                            add_notification(
                                f"Found {len(new_logs)} new logs", 
                                "New Events", 
                                "info"
                            )
                    
                    return len(new_logs)
                except:
                    continue
        
        return 0
    except:
        return 0

def render_user_management():
    """Render user management interface"""
    if not st.session_state.get('authenticated', False):
        st.error("Please log in to access user management")
        return
    
    if st.session_state.get('user_role', 'user') != 'admin':
        st.error("Access denied. Admin privileges required.")
        return
    
    st.title("👥 User Management")
    
    # Initialize database
    db_init_result = init_enhanced_database()
    if db_init_result:
        st.success("✅ Database initialized successfully")
    else:
        st.error("❌ Database initialization failed")
    
    # Show database status
    with st.expander("🔍 Database Status"):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            st.info(f"Database Path: {DB_PATH}")
            st.info(f"Total Users: {user_count}")
            
            # Show table structure
            cursor.execute("PRAGMA table_info(users)")
            columns = cursor.fetchall()
            st.write("Users table columns:")
            for col in columns:
                st.write(f"- {col[1]} ({col[2]})")
            conn.close()
        except Exception as e:
            st.error(f"Database status error: {e}")
    
    tab1, tab2, tab3 = st.tabs(["👥 Users", "🔔 Notifications", "📊 Sessions"])
    
    with tab1:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.subheader("User Accounts")
        with col2:
            if st.button("🔄 Refresh"):
                st.rerun()
            if st.button("🧪 Test Add"):
                # Test user creation
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    test_user = f"test_{int(time.time())}"
                    password_hash = hash_password("test123")
                    cursor.execute('''
                        INSERT INTO users (username, password_hash, email, role, active, failed_attempts) 
                        VALUES (?, ?, ?, ?, 1, 0)
                    ''', (test_user, password_hash, "test@example.com", "user"))
                    conn.commit()
                    conn.close()
                    st.success(f"Test user '{test_user}' created successfully!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Test user creation failed: {e}")
        
        # Add new user section
        with st.expander("➕ Add New User"):
            with st.form("add_user_form"):
                new_username = st.text_input("Username")
                new_password = st.text_input("Password", type="password")
                new_email = st.text_input("Email")
                new_role = st.selectbox("Role", ["user", "admin"])
                
                if st.form_submit_button("Add User"):
                    if new_username and new_password:
                        # Validate username format
                        if len(new_username.strip()) < 3:
                            st.error("Username must be at least 3 characters long!")
                        elif len(new_password) < 4:
                            st.error("Password must be at least 4 characters long!")
                        else:
                            try:
                                conn = sqlite3.connect(DB_PATH)
                                cursor = conn.cursor()
                                
                                # First check if user already exists
                                cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (new_username.strip(),))
                                if cursor.fetchone()[0] > 0:
                                    st.error(f"Username '{new_username}' already exists! Please choose a different username.")
                                    conn.close()
                                else:
                                    # Add the new user
                                    password_hash = hash_password(new_password)
                                    cursor.execute('''
                                        INSERT INTO users (username, password_hash, email, role, active, failed_attempts) 
                                        VALUES (?, ?, ?, ?, 1, 0)
                                    ''', (new_username.strip(), password_hash, new_email.strip() if new_email else None, new_role))
                                    
                                    conn.commit()
                                    conn.close()
                                    st.success(f"✅ User '{new_username}' added successfully!")
                                    st.info(f"**Username:** {new_username} | **Password:** {new_password} | **Role:** {new_role}")
                                    
                                    # Don't redirect, just refresh the user list
                                    # Update the display immediately without full page refresh
                                    
                            except sqlite3.IntegrityError as e:
                                st.error(f"Database constraint error: {e}")
                            except sqlite3.OperationalError as e:
                                # Handle case where columns don't exist yet
                                try:
                                    conn = sqlite3.connect(DB_PATH)
                                    cursor = conn.cursor()
                                    password_hash = hash_password(new_password)
                                    cursor.execute('''
                                        INSERT INTO users (username, password_hash) 
                                        VALUES (?, ?)
                                    ''', (new_username.strip(), password_hash))
                                    conn.commit()
                                    conn.close()
                                    st.success(f"✅ User '{new_username}' added successfully!")
                                    st.info(f"**Username:** {new_username} | **Role:** user (default)")
                                except Exception as e2:
                                    st.error(f"Database error: {e2}")
                            except Exception as e:
                                st.error(f"Unexpected error adding user: {e}")
                    else:
                        st.warning("⚠️ Username and password are required!")
        
        # Display existing users
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Handle missing columns gracefully
            try:
                cursor.execute('''
                    SELECT id, username, 
                           COALESCE(email, '') as email,
                           COALESCE(role, 'user') as role,
                           COALESCE(active, 1) as active,
                           COALESCE(failed_attempts, 0) as failed_attempts,
                           last_login, created_at 
                    FROM users ORDER BY created_at DESC
                ''')
            except sqlite3.OperationalError:
                # Fallback for old database structure
                cursor.execute('''
                    SELECT id, username, '' as email, 'user' as role, 1 as active, 
                           0 as failed_attempts, NULL as last_login, created_at 
                    FROM users ORDER BY created_at DESC
                ''')
            
            users = cursor.fetchall()
            conn.close()
            
            st.write(f"Found {len(users)} users in database")
            
            if users:
                for user in users:
                    user_id, username, email, role, active, failed_attempts, last_login, created_at = user
                    
                    with st.container():
                        col1, col2, col3, col4 = st.columns([2, 2, 1, 1])
                        
                        with col1:
                            status = "🟢 Active" if active else "🔴 Inactive"
                            st.write(f"**{username}** ({role})")
                            st.write(f"{status}")
                        
                        with col2:
                            st.write(f"Email: {email or 'Not set'}")
                            st.write(f"Failed attempts: {failed_attempts}")
                        
                        with col3:
                            st.caption(f"Created: {created_at}")
                        
                        with col4:
                            if username != st.session_state.username:  # Can't deactivate yourself
                                new_status = not active
                                action = "Activate" if not active else "Deactivate"
                                if st.button(action, key=f"toggle_{user_id}"):
                                    conn = sqlite3.connect(DB_PATH)
                                    cursor = conn.cursor()
                                    cursor.execute('UPDATE users SET active = ? WHERE id = ?', 
                                                 (new_status, user_id))
                                    conn.commit()
                                    conn.close()
                                    st.rerun()
                        
                        st.divider()
            else:
                st.info("No users found.")
        except Exception as e:
            st.error(f"Error loading users: {e}")
    
    with tab2:
        st.subheader("System Notifications")
        
        # Add notification form
        with st.form("add_notification_form"):
            notif_title = st.text_input("Notification Title")
            notif_message = st.text_area("Message")
            notif_type = st.selectbox("Type", ["info", "success", "warning", "error"])
            
            if st.form_submit_button("Send Notification"):
                if notif_title and notif_message:
                    add_notification(notif_message, notif_title, notif_type)
                    st.success("Notification sent!")
                else:
                    st.warning("Title and message are required!")
    
    with tab3:
        st.subheader("Active Sessions")
        st.info("Session management features will be available in the next update.")
    st.session_state.logged_in = False
    st.session_state.session_initialized = False
    st.session_state.view = 'main'  # Will redirect to login since not authenticated
