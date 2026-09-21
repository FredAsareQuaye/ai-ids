"""
User Management System for Admin Users
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from .auth_manager import auth_manager
from .enhanced_login import get_current_user, require_auth

@require_auth(role="admin")
def render_user_management():
    """Render the user management interface"""
    st.title("👥 User Management")
    
    # User statistics
    col1, col2, col3, col4 = st.columns(4)
    
    user_stats = get_user_statistics()
    
    with col1:
        st.metric("Total Users", user_stats['total'])
    with col2:
        st.metric("Active Users", user_stats['active'])
    with col3:
        st.metric("Locked Accounts", user_stats['locked'])
    with col4:
        st.metric("New This Month", user_stats['new_month'])
    
    st.divider()
    
    # Tabs for different user management functions
    tab1, tab2, tab3, tab4 = st.tabs(["All Users", "User Sessions", "Password Resets", "Notifications"])
    
    with tab1:
        render_users_table()
    
    with tab2:
        render_active_sessions()
    
    with tab3:
        render_password_reset_management()
    
    with tab4:
        render_notification_management()

def get_user_statistics():
    """Get user statistics"""
    import sqlite3
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        # Total users
        cursor.execute("SELECT COUNT(*) FROM users")
        total = cursor.fetchone()[0]
        
        # Active users
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active = cursor.fetchone()[0]
        
        # Locked accounts
        cursor.execute("SELECT COUNT(*) FROM users WHERE locked_until IS NOT NULL AND locked_until > CURRENT_TIMESTAMP")
        locked = cursor.fetchone()[0]
        
        # New users this month
        cursor.execute("SELECT COUNT(*) FROM users WHERE created_at > date('now', '-1 month')")
        new_month = cursor.fetchone()[0]
        
        return {
            'total': total,
            'active': active,
            'locked': locked,
            'new_month': new_month
        }
    
    except Exception as e:
        st.error(f"Error getting user statistics: {e}")
        return {'total': 0, 'active': 0, 'locked': 0, 'new_month': 0}
    finally:
        conn.close()

def render_users_table():
    """Render the users management table"""
    import sqlite3
    
    st.subheader("All Users")
    
    # Get all users
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
        SELECT id, username, email, first_name, last_name, role, is_active, 
               is_verified, created_at, last_login, failed_login_attempts, locked_until
        FROM users ORDER BY created_at DESC
        """)
        
        users = cursor.fetchall()
        
        if not users:
            st.info("No users found")
            return
        
        # Convert to DataFrame for better display
        df = pd.DataFrame(users, columns=[
            'ID', 'Username', 'Email', 'First Name', 'Last Name', 'Role', 
            'Active', 'Verified', 'Created', 'Last Login', 'Failed Attempts', 'Locked Until'
        ])
        
        # Format dates
        df['Created'] = pd.to_datetime(df['Created']).dt.strftime('%Y-%m-%d %H:%M')
        df['Last Login'] = pd.to_datetime(df['Last Login'], errors='coerce').dt.strftime('%Y-%m-%d %H:%M')
        df['Locked Until'] = pd.to_datetime(df['Locked Until'], errors='coerce').dt.strftime('%Y-%m-%d %H:%M')
        
        # Display the table
        st.dataframe(df, use_container_width=True)
        
        # User actions
        st.subheader("User Actions")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Select user for actions
            user_options = {f"{user[1]} ({user[2]})": user[0] for user in users}
            selected_user = st.selectbox("Select User", options=list(user_options.keys()))
            
            if selected_user:
                user_id = user_options[selected_user]
                
                # Action buttons
                action_col1, action_col2, action_col3 = st.columns(3)
                
                with action_col1:
                    if st.button("Toggle Active", key=f"toggle_active_{user_id}"):
                        toggle_user_active(user_id)
                        st.rerun()
                
                with action_col2:
                    if st.button("Reset Password", key=f"reset_pwd_{user_id}"):
                        reset_user_password(user_id)
                        st.rerun()
                
                with action_col3:
                    if st.button("Unlock Account", key=f"unlock_{user_id}"):
                        unlock_user_account(user_id)
                        st.rerun()
        
        with col2:
            # Add new user form
            st.subheader("Add New User")
            
            with st.form("add_user_form"):
                new_username = st.text_input("Username")
                new_email = st.text_input("Email")
                new_password = st.text_input("Password", type="password")
                new_first_name = st.text_input("First Name")
                new_last_name = st.text_input("Last Name")
                new_role = st.selectbox("Role", ["user", "admin"])
                
                if st.form_submit_button("Add User"):
                    if new_username and new_email and new_password:
                        success, message = auth_manager.register_user(
                            new_username, new_email, new_password, 
                            new_first_name, new_last_name
                        )
                        
                        if success:
                            # Update role if admin
                            if new_role == "admin":
                                update_user_role(new_username, "admin")
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
                    else:
                        st.error("Please fill in all required fields")
    
    except Exception as e:
        st.error(f"Error loading users: {e}")
    finally:
        conn.close()

def render_active_sessions():
    """Render active user sessions"""
    import sqlite3
    
    st.subheader("Active User Sessions")
    
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
        SELECT us.id, u.username, u.email, us.created_at, us.last_accessed, 
               us.user_agent, us.ip_address, us.is_active
        FROM user_sessions us
        JOIN users u ON us.user_id = u.id
        WHERE us.is_active = 1 AND us.expires_at > CURRENT_TIMESTAMP
        ORDER BY us.last_accessed DESC
        """)
        
        sessions = cursor.fetchall()
        
        if not sessions:
            st.info("No active sessions found")
            return
        
        # Display sessions
        for session in sessions:
            session_id, username, email, created_at, last_accessed, user_agent, ip_address, is_active = session
            
            with st.expander(f"{username} - {ip_address}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**User:** {username} ({email})")
                    st.write(f"**IP Address:** {ip_address}")
                    st.write(f"**User Agent:** {user_agent[:50]}..." if user_agent and len(user_agent) > 50 else user_agent)
                
                with col2:
                    st.write(f"**Session Started:** {created_at}")
                    st.write(f"**Last Accessed:** {last_accessed}")
                    st.write(f"**Status:** {'Active' if is_active else 'Inactive'}")
                
                if st.button(f"Terminate Session", key=f"terminate_{session_id}"):
                    terminate_user_session(session_id)
                    st.success("Session terminated")
                    st.rerun()
    
    except Exception as e:
        st.error(f"Error loading sessions: {e}")
    finally:
        conn.close()

def render_password_reset_management():
    """Render password reset token management"""
    import sqlite3
    
    st.subheader("Password Reset Tokens")
    
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
        SELECT prt.id, u.username, u.email, prt.created_at, prt.expires_at, prt.used
        FROM password_reset_tokens prt
        JOIN users u ON prt.user_id = u.id
        ORDER BY prt.created_at DESC
        LIMIT 50
        """)
        
        tokens = cursor.fetchall()
        
        if not tokens:
            st.info("No password reset tokens found")
            return
        
        # Display tokens
        df = pd.DataFrame(tokens, columns=[
            'Token ID', 'Username', 'Email', 'Created', 'Expires', 'Used'
        ])
        
        df['Created'] = pd.to_datetime(df['Created']).dt.strftime('%Y-%m-%d %H:%M')
        df['Expires'] = pd.to_datetime(df['Expires']).dt.strftime('%Y-%m-%d %H:%M')
        df['Used'] = df['Used'].map({0: 'No', 1: 'Yes'})
        
        st.dataframe(df, use_container_width=True)
        
        # Clean up expired tokens
        if st.button("Clean Up Expired Tokens"):
            cursor.execute("DELETE FROM password_reset_tokens WHERE expires_at < CURRENT_TIMESTAMP")
            conn.commit()
            deleted_count = cursor.rowcount
            st.success(f"Deleted {deleted_count} expired tokens")
            st.rerun()
    
    except Exception as e:
        st.error(f"Error loading password reset tokens: {e}")
    finally:
        conn.close()

def render_notification_management():
    """Render notification management"""
    import sqlite3
    
    st.subheader("System Notifications")
    
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        # Notification statistics
        cursor.execute("SELECT COUNT(*) FROM log_notifications")
        total_notifications = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM log_notifications WHERE is_read = 0")
        unread_notifications = cursor.fetchone()[0]
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Notifications", total_notifications)
        with col2:
            st.metric("Unread Notifications", unread_notifications)
        
        # Recent notifications
        cursor.execute("""
        SELECT ln.id, u.username, ln.notification_type, ln.message, 
               ln.is_read, ln.sent_at
        FROM log_notifications ln
        JOIN users u ON ln.user_id = u.id
        ORDER BY ln.sent_at DESC
        LIMIT 20
        """)
        
        notifications = cursor.fetchall()
        
        if notifications:
            st.subheader("Recent Notifications")
            
            for notification in notifications:
                notif_id, username, notif_type, message, is_read, sent_at = notification
                
                with st.expander(f"{notif_type} - {username} - {'✅' if is_read else '🔴'}"):
                    st.write(f"**User:** {username}")
                    st.write(f"**Type:** {notif_type}")
                    st.write(f"**Message:** {message}")
                    st.write(f"**Sent:** {sent_at}")
                    st.write(f"**Status:** {'Read' if is_read else 'Unread'}")
        
        # Send bulk notification
        st.subheader("Send Bulk Notification")
        
        with st.form("bulk_notification"):
            notif_title = st.text_input("Notification Title")
            notif_message = st.text_area("Message")
            notif_users = st.multiselect("Send to Users", options=["All Users", "Active Users Only"])
            
            if st.form_submit_button("Send Notification"):
                if notif_title and notif_message:
                    send_bulk_notification(notif_title, notif_message, notif_users)
                    st.success("Notification sent successfully")
                    st.rerun()
                else:
                    st.error("Please provide title and message")
    
    except Exception as e:
        st.error(f"Error loading notifications: {e}")
    finally:
        conn.close()

def toggle_user_active(user_id):
    """Toggle user active status"""
    import sqlite3
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET is_active = NOT is_active WHERE id = ?", (user_id,))
        conn.commit()
        st.success("User status updated")
    except Exception as e:
        st.error(f"Error updating user status: {e}")
    finally:
        conn.close()

def reset_user_password(user_id):
    """Reset user password"""
    import sqlite3
    import secrets
    
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        # Generate temporary password
        temp_password = secrets.token_urlsafe(12)
        password_hash = auth_manager.hash_password(temp_password)
        
        cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()
        
        st.success(f"Password reset. Temporary password: `{temp_password}`")
        st.warning("Make sure to share this password securely with the user")
    except Exception as e:
        st.error(f"Error resetting password: {e}")
    finally:
        conn.close()

def unlock_user_account(user_id):
    """Unlock user account"""
    import sqlite3
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
        UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?
        """, (user_id,))
        conn.commit()
        st.success("Account unlocked successfully")
    except Exception as e:
        st.error(f"Error unlocking account: {e}")
    finally:
        conn.close()

def update_user_role(username, role):
    """Update user role"""
    import sqlite3
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        conn.commit()
    except Exception as e:
        st.error(f"Error updating user role: {e}")
    finally:
        conn.close()

def terminate_user_session(session_id):
    """Terminate a user session"""
    import sqlite3
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE user_sessions SET is_active = 0 WHERE id = ?", (session_id,))
        conn.commit()
    except Exception as e:
        st.error(f"Error terminating session: {e}")
    finally:
        conn.close()

def send_bulk_notification(title, message, target_users):
    """Send bulk notification to users"""
    import sqlite3
    conn = sqlite3.connect(auth_manager.db_path)
    cursor = conn.cursor()
    
    try:
        if "All Users" in target_users:
            cursor.execute("SELECT id FROM users")
        else:
            cursor.execute("SELECT id FROM users WHERE is_active = 1")
        
        user_ids = [row[0] for row in cursor.fetchall()]
        
        for user_id in user_ids:
            cursor.execute("""
            INSERT INTO log_notifications (user_id, notification_type, message)
            VALUES (?, ?, ?)
            """, (user_id, title, message))
        
        conn.commit()
        st.success(f"Notification sent to {len(user_ids)} users")
        
    except Exception as e:
        st.error(f"Error sending bulk notification: {e}")
    finally:
        conn.close()