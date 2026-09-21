"""
Advanced Authentication Manager with JWT, User Management, Password Reset, and TOTP 2FA
"""
import streamlit as st
import base64
import json
import hmac
import hashlib
import sqlite3
import smtplib
import json
import os
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, List, Tuple
import secrets
import bcrypt

try:
    import pyotp
    import qrcode
    import io
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

class AuthManager:
    def __init__(self):
        self.db_path = Path(__file__).parent.parent.parent / "data" / "siem.db"
        self.settings_path = Path(__file__).parent.parent.parent / "data" / "user_settings.json"
        self.jwt_secret = self._get_or_create_jwt_secret()
        self.jwt_algorithm = "HS256"
        self.token_expiry_hours = 24 * 7  # 7 days
        self.init_database()
        
    def _get_or_create_jwt_secret(self) -> str:
        """Get or create JWT secret key"""
        secret_file = Path(__file__).parent.parent.parent / "data" / ".jwt_secret"
        
        if secret_file.exists():
            return secret_file.read_text().strip()
        else:
            # Generate a secure random secret
            secret = secrets.token_urlsafe(64)
            secret_file.write_text(secret)
            secret_file.chmod(0o600)  # Secure file permissions
            return secret
    
    def init_database(self):
        """Initialize user management database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Users table with comprehensive fields
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                role TEXT DEFAULT 'user',
                is_active BOOLEAN DEFAULT 1,
                is_verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                two_factor_enabled BOOLEAN DEFAULT 0,
                two_factor_secret TEXT
            )
            """)
            
            # Password reset tokens table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)
            
            # User sessions table for tracking active sessions
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                jwt_token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                ip_address TEXT,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)
            
            # Notification preferences table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS notification_preferences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email_notifications BOOLEAN DEFAULT 1,
                log_alerts BOOLEAN DEFAULT 1,
                vulnerability_alerts BOOLEAN DEFAULT 1,
                system_alerts BOOLEAN DEFAULT 1,
                notification_frequency TEXT DEFAULT 'real-time',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)
            
            # Processed logs table (main log storage)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT,
                analysis TEXT,
                processed_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
            # Log tracking for notifications
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                log_id INTEGER,
                notification_type TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read BOOLEAN DEFAULT 0,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                read_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            """)
            
            # Create default admin user if not exists
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
            if cursor.fetchone()[0] == 0:
                self._create_default_admin(cursor)
            
            conn.commit()
            print("✅ Authentication database initialized successfully")
            
        except Exception as e:
            print(f"❌ Error initializing authentication database: {e}")
            raise
        finally:
            conn.close()
    
    def _create_default_admin(self, cursor):
        """Create default admin user"""
        admin_password = "admin123"
        password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        cursor.execute("""
        INSERT INTO users (username, email, password_hash, first_name, last_name, role, is_active, is_verified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, ("admin", "admin@siem.local", password_hash, "System", "Administrator", "admin", 1, 1))
        
        user_id = cursor.lastrowid
        
        # Create notification preferences for admin
        cursor.execute("""
        INSERT INTO notification_preferences (user_id, email_notifications, log_alerts, vulnerability_alerts, system_alerts)
        VALUES (?, ?, ?, ?, ?)
        """, (user_id, 1, 1, 1, 1))
        
        print("✅ Default admin user created")
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            # Fallback for legacy SHA-256 hashes
            sha256_hash = hashlib.sha256(password.encode()).hexdigest()
            return sha256_hash == password_hash
    
    def generate_jwt_token(self, user_data: Dict) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user_data['id'],
            'username': user_data['username'],
            'email': user_data['email'],
            'role': user_data['role'],
            'exp': datetime.utcnow() + timedelta(hours=self.token_expiry_hours),
            'iat': datetime.utcnow(),
            'jti': str(uuid.uuid4())  # JWT ID for token invalidation
        }
        
        return self._simple_jwt_encode(payload, self.jwt_secret)
    
    def _simple_jwt_encode(self, payload, secret):
        """Simple JWT encode implementation"""
        header = {'typ': 'JWT', 'alg': 'HS256'}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, default=str).encode()).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{message}.{signature_b64}"
    
    def verify_jwt_token(self, token: str) -> Optional[Dict]:
        """Verify and decode JWT token"""
        try:
            return self._simple_jwt_decode(token, self.jwt_secret)
        except:
            return None
    
    def _simple_jwt_decode(self, token, secret):
        """Simple JWT decode implementation"""
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token")
        
        header_b64, payload_b64, signature_b64 = parts
        
        # Add padding if needed
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64.encode()))
        
        # Check expiration
        if 'exp' in payload_data:
            exp = payload_data['exp']
            if isinstance(exp, str):
                exp = datetime.fromisoformat(exp).timestamp()
            if datetime.utcnow().timestamp() > exp:
                raise ValueError("Token expired")
        
        return payload_data
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, Optional[Dict], str]:
        """Authenticate user and return success status, user data, and message"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if user exists and get user data
            cursor.execute("""
            SELECT id, username, email, password_hash, first_name, last_name, role, 
                   is_active, is_verified, failed_login_attempts, locked_until
            FROM users WHERE username = ? OR email = ?
            """, (username, username))
            
            user = cursor.fetchone()
            
            if not user:
                return False, None, "Invalid username or password"
            
            user_data = {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'password_hash': user[3],
                'first_name': user[4],
                'last_name': user[5],
                'role': user[6],
                'is_active': user[7],
                'is_verified': user[8],
                'failed_login_attempts': user[9],
                'locked_until': user[10]
            }
            
            # Check if account is locked
            if user_data['locked_until']:
                locked_until = datetime.fromisoformat(user_data['locked_until'])
                if datetime.now() < locked_until:
                    remaining_time = locked_until - datetime.now()
                    minutes = int(remaining_time.total_seconds() / 60)
                    return False, None, f"Account locked for {minutes} more minutes"
            
            # Check if account is active
            if not user_data['is_active']:
                return False, None, "Account is deactivated"
            
            # Verify password
            if not self.verify_password(password, user_data['password_hash']):
                # Increment failed login attempts
                failed_attempts = user_data['failed_login_attempts'] + 1
                locked_until = None
                
                # Lock account after 5 failed attempts for 30 minutes
                if failed_attempts >= 5:
                    locked_until = datetime.now() + timedelta(minutes=30)
                
                cursor.execute("""
                UPDATE users SET failed_login_attempts = ?, locked_until = ?
                WHERE id = ?
                """, (failed_attempts, locked_until.isoformat() if locked_until else None, user_data['id']))
                
                conn.commit()
                
                if locked_until:
                    return False, None, "Too many failed attempts. Account locked for 30 minutes."
                
                return False, None, "Invalid username or password"
            
            # Reset failed login attempts on successful login
            cursor.execute("""
            UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
            WHERE id = ?
            """, (user_data['id'],))
            
            conn.commit()
            
            return True, user_data, "Login successful"
            
        except Exception as e:
            print(f"❌ Authentication error: {e}")
            return False, None, "Authentication error occurred"
        finally:
            conn.close()
    
    def create_user_session(self, user_data: Dict, remember_me: bool = False) -> Tuple[str, str]:
        """Create user session and return session token and JWT token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Generate tokens
            session_token = secrets.token_urlsafe(32)
            jwt_token = self.generate_jwt_token(user_data)
            
            # Set expiry based on remember me
            if remember_me:
                expires_at = datetime.now() + timedelta(days=30)
            else:
                expires_at = datetime.now() + timedelta(hours=self.token_expiry_hours)
            
            # Store session in database
            cursor.execute("""
            INSERT INTO user_sessions 
            (user_id, session_token, jwt_token, expires_at, user_agent, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user_data['id'],
                session_token,
                jwt_token,
                expires_at.isoformat(),
                st.session_state.get('user_agent', 'Unknown'),
                st.session_state.get('client_ip', 'Unknown')
            ))
            
            conn.commit()
            
            # Always persist session to disk so page refresh restores login
            self._store_persistent_session(session_token, jwt_token)
            
            return session_token, jwt_token
            
        except Exception as e:
            print(f"❌ Error creating session: {e}")
            raise
        finally:
            conn.close()
    
    def _store_persistent_session(self, session_token: str, jwt_token: str):
        """Store session data for persistence"""
        session_file = Path(__file__).parent.parent.parent / "data" / ".user_session"
        session_data = {
            'session_token': session_token,
            'jwt_token': jwt_token,
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            with open(session_file, 'w') as f:
                json.dump(session_data, f)
            session_file.chmod(0o600)  # Secure file permissions
        except Exception as e:
            print(f"❌ Error storing persistent session: {e}")
    
    def load_persistent_session(self) -> Optional[Tuple[str, str]]:
        """Load persistent session data"""
        session_file = Path(__file__).parent.parent.parent / "data" / ".user_session"
        
        if not session_file.exists():
            return None
        
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            session_token = session_data.get('session_token')
            jwt_token = session_data.get('jwt_token')
            
            if session_token and jwt_token:
                # Verify session is still valid
                if self._verify_session(session_token, jwt_token):
                    return session_token, jwt_token
            
            # Clean up invalid session
            session_file.unlink()
            return None
            
        except Exception as e:
            print(f"❌ Error loading persistent session: {e}")
            return None
    
    def _verify_session(self, session_token: str, jwt_token: str) -> bool:
        """Verify session is valid and not expired"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
            SELECT expires_at, is_active FROM user_sessions 
            WHERE session_token = ? AND jwt_token = ?
            """, (session_token, jwt_token))
            
            result = cursor.fetchone()
            if not result:
                return False
            
            expires_at_str, is_active = result
            
            if not is_active:
                return False
            
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now() > expires_at:
                # Mark session as inactive
                cursor.execute("""
                UPDATE user_sessions SET is_active = 0 WHERE session_token = ?
                """, (session_token,))
                conn.commit()
                return False
            
            # Update last accessed time
            cursor.execute("""
            UPDATE user_sessions SET last_accessed = CURRENT_TIMESTAMP 
            WHERE session_token = ?
            """, (session_token,))
            conn.commit()
            
            # Verify JWT token
            payload = self.verify_jwt_token(jwt_token)
            return payload is not None
            
        except Exception as e:
            print(f"❌ Error verifying session: {e}")
            return False
        finally:
            conn.close()
    
    def logout_user(self, session_token: str = None):
        """Logout user and invalidate session"""
        if session_token:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            try:
                cursor.execute("""
                UPDATE user_sessions SET is_active = 0 WHERE session_token = ?
                """, (session_token,))
                conn.commit()
            except Exception as e:
                print(f"❌ Error logging out user: {e}")
            finally:
                conn.close()
        
        # Remove persistent session file
        session_file = Path(__file__).parent.parent.parent / "data" / ".user_session"
        if session_file.exists():
            session_file.unlink()
        
        # Clear session state
        auth_keys = [
            "authenticated", "logged_in", "auth_token", "session_token",
            "username", "user_data", "remember_me", "session_checked"
        ]
        
        for key in auth_keys:
            if key in st.session_state:
                del st.session_state[key]
    
    def register_user(self, username: str, email: str, password: str, 
                     first_name: str = "", last_name: str = "") -> Tuple[bool, str]:
        """Register new user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if username or email already exists
            cursor.execute("""
            SELECT username, email FROM users WHERE username = ? OR email = ?
            """, (username, email))
            
            existing = cursor.fetchone()
            if existing:
                if existing[0] == username:
                    return False, "Username already exists"
                else:
                    return False, "Email already exists"
            
            # Hash password
            password_hash = self.hash_password(password)
            
            # Insert new user
            cursor.execute("""
            INSERT INTO users (username, email, password_hash, first_name, last_name, role)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (username, email, password_hash, first_name, last_name, "user"))
            
            user_id = cursor.lastrowid
            
            # Create default notification preferences
            cursor.execute("""
            INSERT INTO notification_preferences (user_id)
            VALUES (?)
            """, (user_id,))
            
            conn.commit()
            
            return True, "User registered successfully"
            
        except Exception as e:
            print(f"❌ Error registering user: {e}")
            return False, f"Registration error: {str(e)}"
        finally:
            conn.close()
    
    def request_password_reset(self, email: str) -> Tuple[bool, str]:
        """Request password reset for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Check if user exists
            cursor.execute("SELECT id, username FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
            if not user:
                # Don't reveal if email exists or not for security
                return True, "If the email exists, a reset link will be sent"
            
            user_id, username = user
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)  # 1 hour expiry
            
            # Store reset token
            cursor.execute("""
            INSERT INTO password_reset_tokens (user_id, token, expires_at)
            VALUES (?, ?, ?)
            """, (user_id, reset_token, expires_at.isoformat()))
            
            conn.commit()
            
            # Send email (simulate for now)
            reset_link = f"http://localhost:8501/?reset_token={reset_token}"
            success = self._send_password_reset_email(email, username, reset_link)
            
            if success:
                return True, "Password reset email sent successfully"
            else:
                return False, "Failed to send password reset email"
                
        except Exception as e:
            print(f"❌ Error requesting password reset: {e}")
            return False, "Error processing password reset request"
        finally:
            conn.close()
    
    def _send_password_reset_email(self, email: str, username: str, reset_link: str) -> bool:
        """Send password reset email (simulation)"""
        try:
            # For now, just print the reset link (in production, send actual email)
            print(f"🔗 Password Reset Link for {username} ({email}): {reset_link}")
            
            # Store notification for user to see in UI
            self._add_system_notification(
                email, 
                "Password Reset Requested", 
                f"A password reset was requested for your account. Use this link: {reset_link}"
            )
            
            return True
        except Exception as e:
            print(f"❌ Error sending password reset email: {e}")
            return False
    
    def reset_password(self, token: str, new_password: str) -> Tuple[bool, str]:
        """Reset password using token"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Verify token
            cursor.execute("""
            SELECT user_id, expires_at, used FROM password_reset_tokens 
            WHERE token = ?
            """, (token,))
            
            result = cursor.fetchone()
            if not result:
                return False, "Invalid reset token"
            
            user_id, expires_at_str, used = result
            
            if used:
                return False, "Reset token already used"
            
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now() > expires_at:
                return False, "Reset token has expired"
            
            # Update password
            password_hash = self.hash_password(new_password)
            cursor.execute("""
            UPDATE users SET password_hash = ? WHERE id = ?
            """, (password_hash, user_id))
            
            # Mark token as used
            cursor.execute("""
            UPDATE password_reset_tokens SET used = 1 WHERE token = ?
            """, (token,))
            
            conn.commit()
            
            return True, "Password reset successfully"
            
        except Exception as e:
            print(f"❌ Error resetting password: {e}")
            return False, "Error resetting password"
        finally:
            conn.close()
    
    def _add_system_notification(self, email: str, title: str, message: str):
        """Add system notification for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
            if user:
                cursor.execute("""
                INSERT INTO log_notifications (user_id, notification_type, message)
                VALUES (?, ?, ?)
                """, (user[0], title, message))
                conn.commit()
                
        except Exception as e:
            print(f"❌ Error adding system notification: {e}")
        finally:
            conn.close()
    
    def get_user_notifications(self, user_id: int, unread_only: bool = False) -> List[Dict]:
        """Get notifications for user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            query = """
            SELECT id, notification_type, message, is_read, sent_at, read_at
            FROM log_notifications WHERE user_id = ?
            """
            params = [user_id]
            
            if unread_only:
                query += " AND is_read = 0"
            
            query += " ORDER BY sent_at DESC LIMIT 50"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            notifications = []
            for result in results:
                notifications.append({
                    'id': result[0],
                    'type': result[1],
                    'message': result[2],
                    'is_read': bool(result[3]),
                    'sent_at': result[4],
                    'read_at': result[5]
                })
            
            return notifications
            
        except Exception as e:
            print(f"❌ Error getting notifications: {e}")
            return []
        finally:
            conn.close()
    
    def mark_notification_read(self, notification_id: int, user_id: int):
        """Mark notification as read"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
            UPDATE log_notifications 
            SET is_read = 1, read_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND user_id = ?
            """, (notification_id, user_id))
            conn.commit()
            
        except Exception as e:
            print(f"❌ Error marking notification as read: {e}")
        finally:
            conn.close()
    
    # ------------------------------------------------------------------ #
    #  TOTP Two-Factor Authentication                                    #
    # ------------------------------------------------------------------ #

    def setup_totp(self, user_id: int) -> Optional[Dict]:
        """Generate a new TOTP secret for a user. Returns secret + provisioning URI."""
        if not TOTP_AVAILABLE:
            return None
        secret = pyotp.random_base32()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT username, email FROM users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            username, email = row
            # Store the (unconfirmed) secret — enabled stays 0 until user confirms
            cursor.execute(
                "UPDATE users SET two_factor_secret = ? WHERE id = ?",
                (secret, user_id),
            )
            conn.commit()
        finally:
            conn.close()

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name="AI-IDS")

        # Generate QR code as PNG bytes
        qr_bytes = None
        try:
            img = qrcode.make(uri)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_bytes = buf.getvalue()
        except Exception:
            pass

        return {"secret": secret, "uri": uri, "qr_png": qr_bytes}

    def verify_totp_code(self, user_id: int, code: str) -> bool:
        """Verify a TOTP code against the stored secret (window=1 = 30s grace)."""
        if not TOTP_AVAILABLE:
            return False
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT two_factor_secret FROM users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
            if not row or not row[0]:
                return False
            totp = pyotp.TOTP(row[0])
            return totp.verify(code, valid_window=1)
        finally:
            conn.close()

    def enable_totp(self, user_id: int, code: str) -> Tuple[bool, str]:
        """Enable 2FA after user confirms the setup code is working."""
        if not self.verify_totp_code(user_id, code):
            return False, "Invalid verification code"
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE users SET two_factor_enabled = 1 WHERE id = ?", (user_id,)
            )
            conn.commit()
        finally:
            conn.close()
        return True, "Two-factor authentication enabled"

    def disable_totp(self, user_id: int) -> bool:
        """Disable 2FA for a user and clear the secret."""
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?",
                (user_id,),
            )
            conn.commit()
        finally:
            conn.close()
        return True

    def get_user_2fa_status(self, user_id: int) -> Dict:
        """Return 2FA status for a user."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT two_factor_enabled, two_factor_secret FROM users WHERE id = ?",
                (user_id,),
            )
            row = cursor.fetchone()
            if not row:
                return {"enabled": False, "has_secret": False}
            return {
                "enabled": bool(row[0]),
                "has_secret": bool(row[1]),
                "totp_available": TOTP_AVAILABLE,
            }
        finally:
            conn.close()

    def get_user_2fa_required(self, username: str) -> Tuple[bool, Optional[int]]:
        """Check if a user has 2FA enabled. Returns (required, user_id)."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT id, two_factor_enabled FROM users WHERE username = ? OR email = ?",
                (username, username),
            )
            row = cursor.fetchone()
            if not row:
                return False, None
            return bool(row[1]), row[0]
        finally:
            conn.close()

    def add_log_notification(self, log_data: Dict):
        """Add notification when new log is detected"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get all users with log alerts enabled
            cursor.execute("""
            SELECT u.id, u.username, u.email, np.notification_frequency
            FROM users u
            JOIN notification_preferences np ON u.id = np.user_id
            WHERE np.log_alerts = 1 AND u.is_active = 1
            """)
            
            users = cursor.fetchall()
            
            for user in users:
                user_id, username, email, frequency = user
                
                # Create notification message
                severity = log_data.get('severity', 'INFO')
                source = log_data.get('source', 'Unknown')
                message = f"New {severity} log from {source}: {log_data.get('message', '')[:100]}..."
                
                cursor.execute("""
                INSERT INTO log_notifications (user_id, notification_type, message)
                VALUES (?, ?, ?)
                """, (user_id, f"New {severity} Log", message))
            
            conn.commit()
            
        except Exception as e:
            print(f"❌ Error adding log notification: {e}")
        finally:
            conn.close()

# Global auth manager instance
auth_manager = AuthManager()