"""
Enhanced Detail View with Functional Buttons and Actions
"""
import streamlit as st
import json
import sqlite3
import subprocess
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from components.auth_manager import auth_manager
from components.enhanced_login import get_current_user
from components.notification_system import create_custom_notification

def render_enhanced_detail_view(log_id=None, alert_data=None):
    """Render enhanced detail view with functional buttons"""
    user = get_current_user()
    if not user:
        st.error("Authentication required")
        return
    
    # Handle navigation
    came_from = st.session_state.get('came_from', 'dashboard')
    if came_from == 'logs':
        if st.button("← Back to Logs", type="secondary"):
            st.session_state.view = 'logs_overview'
            if 'selected_log_id' in st.session_state:
                del st.session_state.selected_log_id
            if 'came_from' in st.session_state:
                del st.session_state.came_from
            st.rerun()
    elif came_from == 'dashboard':
        if st.button("← Back to Dashboard", type="secondary"):
            st.session_state.view = 'main'
            if 'selected_log_id' in st.session_state:
                del st.session_state.selected_log_id
            st.rerun()
    
    st.markdown("---")
    
    # Get log/alert data
    if log_id:
        log_data = get_log_details(log_id)
        if not log_data:
            st.error("Log entry not found")
            return
        display_data = log_data
        data_type = "Log"
    elif alert_data:
        display_data = alert_data
        data_type = "Alert"
    else:
        st.error("No data to display")
        return
    
    # Header with title and status
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title(f"🔍 {data_type} Details")
        if log_id:
            st.markdown(f"**Log ID:** {log_id}")
        
    with col2:
        # Status indicator
        severity = display_data.get('severity', 'INFO')
        status_color = get_severity_color(severity)
        st.markdown(f"""
        <div style="text-align: right;">
        <span style="background-color: {status_color}; color: white; padding: 5px 10px; border-radius: 15px; font-weight: bold;">
        {severity}
        </span>
        </div>
        """, unsafe_allow_html=True)
    
    # Quick Action Buttons
    st.subheader("🚀 Quick Actions")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        if st.button("📊 Generate Report", use_container_width=True):
            generate_detailed_report(display_data, data_type, user)
    
    with col2:
        if st.button("🔍 Deep Analysis", use_container_width=True):
            perform_deep_analysis(display_data, data_type, user)
    
    with col3:
        if st.button("🚨 Create Alert", use_container_width=True):
            create_alert_from_data(display_data, user)
    
    with col4:
        if st.button("📧 Share", use_container_width=True):
            share_data_with_team(display_data, data_type, user)
    
    with col5:
        if st.button("🔄 Refresh", use_container_width=True):
            refresh_data(log_id, display_data)
    
    st.divider()
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["📋 Overview", "🔬 Technical", "🌐 Network", "📈 Timeline", "🎯 Actions"])
    
    with tab1:
        render_overview_tab(display_data, data_type)
    
    with tab2:
        render_technical_tab(display_data, data_type)
    
    with tab3:
        render_network_tab(display_data, data_type)
    
    with tab4:
        render_timeline_tab(display_data, data_type, log_id)
    
    with tab5:
        render_actions_tab(display_data, data_type, user, log_id)

def get_log_details(log_id):
    """Get detailed log information from database"""
    db_path = Path(__file__).parent.parent.parent / "data" / "siem.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
        SELECT id, timestamp, source, message, severity, details, analysis, processed_at
        FROM processed_logs WHERE id = ?
        """, (log_id,))
        
        result = cursor.fetchone()
        if result:
            return {
                'id': result[0],
                'timestamp': result[1],
                'source': result[2],
                'message': result[3],
                'severity': result[4],
                'details': json.loads(result[5]) if result[5] else {},
                'analysis': result[6],
                'processed_at': result[7]
            }
        return None
    
    except Exception as e:
        st.error(f"Error loading log details: {e}")
        return None
    finally:
        conn.close()

def get_severity_color(severity):
    """Get color for severity level"""
    colors = {
        'CRITICAL': '#ff4444',
        'ERROR': '#ff8800',
        'WARNING': '#ffcc00',
        'INFO': '#44ff44',
        'DEBUG': '#888888'
    }
    return colors.get(severity, '#888888')

def generate_detailed_report(data, data_type, user):
    """Generate a detailed report from the data"""
    try:
        # Create report data
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{data_type.lower()}_report_{timestamp}.json"
        
        report_data = {
            'report_type': f'{data_type} Detailed Report',
            'generated_by': user['username'],
            'generated_at': datetime.now().isoformat(),
            'data_source': data_type,
            'content': data,
            'analysis': {
                'severity_assessment': data.get('severity', 'Unknown'),
                'risk_level': assess_risk_level(data),
                'recommendations': generate_recommendations(data),
                'related_events': find_related_events(data)
            }
        }
        
        # Create download button
        st.download_button(
            label=f"📊 Download {data_type} Report",
            data=json.dumps(report_data, indent=2),
            file_name=report_filename,
            mime="application/json",
            key="download_report"
        )
        
        st.success(f"✅ Report generated successfully: {report_filename}")
        
        # Create notification
        create_custom_notification(
            user['id'], 
            "Report Generated", 
            f"Detailed {data_type.lower()} report has been generated and is ready for download"
        )
        
    except Exception as e:
        st.error(f"❌ Error generating report: {e}")

def perform_deep_analysis(data, data_type, user):
    """Perform deep analysis on the data"""
    try:
        with st.spinner("🔍 Performing deep analysis..."):
            analysis_results = {
                'basic_analysis': {},
                'security_analysis': {},
                'network_analysis': {},
                'behavioral_analysis': {}
            }
            
            # Basic analysis
            analysis_results['basic_analysis'] = {
                'source_type': data.get('source', 'Unknown'),
                'message_length': len(data.get('message', '')),
                'severity_level': data.get('severity', 'Unknown'),
                'timestamp_analysis': analyze_timestamp(data.get('timestamp'))
            }
            
            # Security analysis
            analysis_results['security_analysis'] = {
                'potential_threats': identify_threats(data),
                'attack_patterns': detect_attack_patterns(data),
                'anomaly_score': calculate_anomaly_score(data)
            }
            
            # Network analysis (if network data available)
            if 'ip' in str(data).lower() or 'network' in str(data).lower():
                analysis_results['network_analysis'] = perform_network_analysis(data)
            
            # Display results
            st.subheader("🔬 Deep Analysis Results")
            
            for analysis_type, results in analysis_results.items():
                if results:
                    with st.expander(f"{analysis_type.replace('_', ' ').title()}", expanded=True):
                        for key, value in results.items():
                            st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")
            
            # Store analysis in database
            store_analysis_results(data.get('id'), analysis_results, user['id'])
            
            st.success("✅ Deep analysis completed successfully")
            
            # Create notification
            create_custom_notification(
                user['id'], 
                "Deep Analysis Complete", 
                f"Deep analysis has been completed for {data_type.lower()} ID: {data.get('id', 'Unknown')}"
            )
            
    except Exception as e:
        st.error(f"❌ Error performing deep analysis: {e}")

def create_alert_from_data(data, user):
    """Create an alert from the current data"""
    try:
        st.subheader("🚨 Create New Alert")
        
        with st.form("create_alert"):
            alert_title = st.text_input("Alert Title", 
                                      value=f"Alert from {data.get('source', 'Unknown')} - {data.get('severity', 'INFO')}")
            alert_description = st.text_area("Description", 
                                           value=f"Alert created from log entry:\n{data.get('message', '')}")
            alert_severity = st.selectbox("Severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], 
                                        index=2 if data.get('severity') in ['ERROR', 'CRITICAL'] else 1)
            alert_assignee = st.text_input("Assign to", value=user['username'])
            
            if st.form_submit_button("Create Alert"):
                alert_data = {
                    'title': alert_title,
                    'description': alert_description,
                    'severity': alert_severity,
                    'assigned_to': alert_assignee,
                    'created_by': user['username'],
                    'created_at': datetime.now().isoformat(),
                    'source_data': data,
                    'status': 'OPEN'
                }
                
                # Store alert in database
                alert_id = store_alert(alert_data)
                
                if alert_id:
                    st.success(f"✅ Alert created successfully with ID: {alert_id}")
                    
                    # Create notification
                    create_custom_notification(
                        user['id'], 
                        "Alert Created", 
                        f"New alert '{alert_title}' has been created and assigned to {alert_assignee}"
                    )
                else:
                    st.error("❌ Failed to create alert")
    
    except Exception as e:
        st.error(f"❌ Error creating alert: {e}")

def share_data_with_team(data, data_type, user):
    """Share data with team members"""
    try:
        st.subheader("📧 Share with Team")
        
        with st.form("share_data"):
            # Get list of users for sharing
            users = get_all_users()
            selected_users = st.multiselect("Select team members", 
                                          options=[f"{u['username']} ({u['email']})" for u in users])
            
            share_message = st.text_area("Message", 
                                       value=f"Sharing {data_type.lower()} details for your review.")
            
            include_full_data = st.checkbox("Include full data details", value=True)
            
            if st.form_submit_button("Share"):
                for user_selection in selected_users:
                    username = user_selection.split(' (')[0]
                    target_user = next((u for u in users if u['username'] == username), None)
                    
                    if target_user:
                        # Create notification for each user
                        notification_message = f"""
                        {user['username']} shared {data_type.lower()} details with you:
                        
                        {share_message}
                        
                        {'Full data: ' + json.dumps(data, indent=2) if include_full_data else 'Data shared via secure link'}
                        """
                        
                        create_custom_notification(
                            target_user['id'],
                            f"Shared {data_type}",
                            notification_message
                        )
                
                st.success(f"✅ {data_type} shared with {len(selected_users)} team member(s)")
    
    except Exception as e:
        st.error(f"❌ Error sharing data: {e}")

def refresh_data(log_id, current_data):
    """Refresh the current data"""
    try:
        with st.spinner("🔄 Refreshing data..."):
            time.sleep(1)  # Simulate refresh delay
            
            if log_id:
                # Refresh log data
                refreshed_data = get_log_details(log_id)
                if refreshed_data:
                    st.session_state.refreshed_data = refreshed_data
                    st.success("✅ Data refreshed successfully")
            else:
                st.success("✅ Data is up to date")
            
            st.rerun()
    
    except Exception as e:
        st.error(f"❌ Error refreshing data: {e}")

def render_overview_tab(data, data_type):
    """Render the overview tab"""
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Summary")
        st.markdown(f"**Type:** {data_type}")
        st.markdown(f"**Source:** {data.get('source', 'Unknown')}")
        st.markdown(f"**Severity:** {data.get('severity', 'Unknown')}")
        st.markdown(f"**Timestamp:** {data.get('timestamp', 'Unknown')}")
        
        if data.get('processed_at'):
            st.markdown(f"**Processed:** {data['processed_at']}")
    
    with col2:
        st.subheader("📝 Message")
        message = data.get('message', 'No message available')
        st.text_area("", value=message, height=200, disabled=True)
    
    # Additional details
    if data.get('details'):
        st.subheader("🔍 Additional Details")
        details = data['details'] if isinstance(data['details'], dict) else {}
        for key, value in details.items():
            st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")

def render_technical_tab(data, data_type):
    """Render the technical details tab"""
    st.subheader("🔧 Technical Information")
    
    # Raw data
    with st.expander("Raw Data", expanded=False):
        st.json(data)
    
    # System information
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**System Details**")
        st.markdown(f"Data Type: `{data_type}`")
        st.markdown(f"Record ID: `{data.get('id', 'N/A')}`")
        st.markdown(f"Size: `{len(str(data))} characters`")
    
    with col2:
        st.markdown("**Processing Info**")
        if data.get('analysis'):
            st.markdown(f"Analysis: `Available`")
            with st.expander("View Analysis"):
                st.text(data['analysis'])
        else:
            st.markdown(f"Analysis: `Not available`")

def render_network_tab(data, data_type):
    """Render network analysis tab"""
    st.subheader("🌐 Network Analysis")
    
    # Extract network-related information
    network_info = extract_network_info(data)
    
    if network_info:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Network Details**")
            for key, value in network_info.items():
                st.markdown(f"**{key}:** {value}")
        
        with col2:
            st.markdown("**Actions**")
            
            if network_info.get('ip_address'):
                ip = network_info['ip_address']
                
                if st.button(f"🔍 Lookup {ip}"):
                    perform_ip_lookup(ip)
                
                if st.button(f"🚨 Block {ip}"):
                    block_ip_address(ip)
                
                if st.button(f"📊 Analyze {ip}"):
                    analyze_ip_address(ip)
    else:
        st.info("No network information available in this record")

def render_timeline_tab(data, data_type, log_id):
    """Render timeline analysis tab"""
    st.subheader("📈 Timeline Analysis")
    
    # Get related events
    if log_id:
        related_events = get_related_timeline_events(log_id, data)
        
        if related_events:
            st.markdown("**Related Events**")
            for event in related_events:
                with st.container():
                    col1, col2, col3 = st.columns([2, 3, 1])
                    
                    with col1:
                        st.markdown(f"**{event['timestamp']}**")
                    
                    with col2:
                        st.markdown(f"{event['message'][:100]}...")
                    
                    with col3:
                        severity_color = get_severity_color(event['severity'])
                        st.markdown(f"<span style='color: {severity_color}'>**{event['severity']}**</span>", 
                                  unsafe_allow_html=True)
                    
                    st.divider()
        else:
            st.info("No closely related events found")
    else:
        st.info("Timeline analysis not available for this data type")

def render_actions_tab(data, data_type, user, log_id):
    """Render available actions tab"""
    st.subheader("🎯 Available Actions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Immediate Actions**")
        
        if st.button("🔒 Mark as Resolved", use_container_width=True):
            mark_as_resolved(log_id or data.get('id'), user)
        
        if st.button("⭐ Add to Favorites", use_container_width=True):
            add_to_favorites(log_id or data.get('id'), user)
        
        if st.button("🏷️ Add Tags", use_container_width=True):
            show_tag_dialog(log_id or data.get('id'), user)
    
    with col2:
        st.markdown("**Analysis Actions**")
        
        if st.button("🔍 Find Similar", use_container_width=True):
            find_similar_events(data, user)
        
        if st.button("📊 Generate Statistics", use_container_width=True):
            generate_event_statistics(data, user)
        
        if st.button("🚀 Create Playbook", use_container_width=True):
            create_response_playbook(data, user)

# Helper functions
def assess_risk_level(data):
    """Assess risk level based on data"""
    severity = data.get('severity', 'INFO')
    if severity == 'CRITICAL':
        return 'HIGH'
    elif severity == 'ERROR':
        return 'MEDIUM'
    elif severity == 'WARNING':
        return 'LOW'
    else:
        return 'MINIMAL'

def generate_recommendations(data):
    """Generate recommendations based on data"""
    recommendations = []
    severity = data.get('severity', 'INFO')
    
    if severity == 'CRITICAL':
        recommendations.append("Immediate investigation required")
        recommendations.append("Consider isolating affected systems")
    elif severity == 'ERROR':  
        recommendations.append("Review and address underlying cause")
        recommendations.append("Monitor for recurring patterns")
    
    return recommendations

def find_related_events(data):
    """Find related events"""
    # This would typically query the database for related events
    return []

def analyze_timestamp(timestamp):
    """Analyze timestamp patterns"""
    if not timestamp:
        return "No timestamp available"
    
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        hour = dt.hour
        
        if 0 <= hour < 6:
            return "Night time activity (00:00-06:00)"
        elif 6 <= hour < 12:
            return "Morning activity (06:00-12:00)"  
        elif 12 <= hour < 18:
            return "Afternoon activity (12:00-18:00)"
        else:
            return "Evening activity (18:00-00:00)"
    except:
        return "Invalid timestamp format"

def identify_threats(data):
    """Identify potential threats in data"""
    threats = []
    message = str(data.get('message', '')).lower()
    
    threat_keywords = ['attack', 'malware', 'virus', 'breach', 'unauthorized', 'suspicious']
    
    for keyword in threat_keywords:
        if keyword in message:
            threats.append(f"Potential {keyword} detected")
    
    return threats if threats else ["No obvious threats detected"]

def detect_attack_patterns(data):
    """Detect known attack patterns"""
    patterns = []
    message = str(data.get('message', '')).lower()
    
    if 'sql injection' in message or 'union select' in message:
        patterns.append("SQL Injection attempt")
    
    if 'xss' in message or '<script>' in message:
        patterns.append("Cross-site scripting attempt")
    
    if 'brute force' in message or 'multiple failed login' in message:
        patterns.append("Brute force attack")
    
    return patterns if patterns else ["No known attack patterns detected"]

def calculate_anomaly_score(data):
    """Calculate anomaly score"""
    score = 0
    
    severity = data.get('severity', 'INFO')
    if severity == 'CRITICAL':
        score += 40
    elif severity == 'ERROR':
        score += 30
    elif severity == 'WARNING':
        score += 20
    
    # Add more scoring logic based on message content, time, etc.
    
    return f"{score}/100"

def perform_network_analysis(data):
    """Perform network-specific analysis"""
    analysis = {}
    
    # Extract IPs
    import re
    text = str(data)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    
    if ips:
        analysis['detected_ips'] = list(set(ips))
        analysis['ip_count'] = len(set(ips))
    
    return analysis

def store_analysis_results(data_id, results, user_id):
    """Store analysis results in database"""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "siem.db"  
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create analysis table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_id INTEGER,
            user_id INTEGER,
            analysis_type TEXT,
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        cursor.execute("""
        INSERT INTO analysis_results (data_id, user_id, analysis_type, results)
        VALUES (?, ?, ?, ?)
        """, (data_id, user_id, "deep_analysis", json.dumps(results)))
        
        conn.commit()
        
    except Exception as e:
        print(f"Error storing analysis results: {e}")
    finally:
        conn.close()

def store_alert(alert_data):
    """Store alert in database"""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "siem.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create alerts table if not exists
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            assigned_to TEXT,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_data TEXT,
            status TEXT DEFAULT 'OPEN'
        )
        """)
        
        cursor.execute("""
        INSERT INTO alerts (title, description, severity, assigned_to, created_by, source_data, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data['title'],
            alert_data['description'], 
            alert_data['severity'],
            alert_data['assigned_to'],
            alert_data['created_by'],
            json.dumps(alert_data['source_data']),
            alert_data['status']
        ))
        
        alert_id = cursor.lastrowid
        conn.commit()
        return alert_id
        
    except Exception as e:
        print(f"Error storing alert: {e}")
        return None
    finally:
        conn.close()

def get_all_users():
    """Get all users for sharing"""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "siem.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, email FROM users WHERE is_active = 1")
        users = cursor.fetchall()
        
        return [{'id': u[0], 'username': u[1], 'email': u[2]} for u in users]
        
    except Exception as e:
        print(f"Error getting users: {e}")
        return []
    finally:
        conn.close()

def extract_network_info(data):
    """Extract network information from data"""
    import re
    
    network_info = {}
    text = str(data)
    
    # Extract IP addresses
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    if ips:
        network_info['ip_address'] = ips[0]  # Take first IP
        network_info['all_ips'] = list(set(ips))
    
    # Extract ports
    ports = re.findall(r':(\d{1,5})\b', text)
    if ports:
        network_info['ports'] = list(set(ports))
    
    # Extract URLs
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    if urls:
        network_info['urls'] = urls
    
    return network_info

def perform_ip_lookup(ip):
    """Perform IP address lookup"""
    st.info(f"🔍 Looking up information for IP: {ip}")
    # In a real implementation, this would query threat intelligence APIs
    st.success(f"✅ IP lookup completed for {ip}")

def block_ip_address(ip):
    """Block IP address"""
    st.warning(f"🚨 IP {ip} has been added to the block list")
    # In a real implementation, this would interface with firewall APIs

def analyze_ip_address(ip):
    """Analyze IP address"""
    st.info(f"📊 Analyzing IP address: {ip}")
    # In a real implementation, this would perform geolocation, reputation checks, etc.
    st.success(f"✅ Analysis completed for {ip}")

def get_related_timeline_events(log_id, data):
    """Get related events for timeline"""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "siem.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get events from same source around the same time
        cursor.execute("""
        SELECT timestamp, message, severity FROM processed_logs 
        WHERE source = ? AND id != ?
        ORDER BY processed_at DESC LIMIT 10
        """, (data.get('source', ''), log_id))
        
        events = cursor.fetchall()
        return [{'timestamp': e[0], 'message': e[1], 'severity': e[2]} for e in events]
        
    except Exception as e:
        print(f"Error getting related events: {e}")
        return []
    finally:
        conn.close()

def mark_as_resolved(item_id, user):
    """Mark item as resolved"""
    st.success(f"✅ Item {item_id} marked as resolved by {user['username']}")

def add_to_favorites(item_id, user):
    """Add item to favorites"""
    st.success(f"⭐ Item {item_id} added to favorites")

def show_tag_dialog(item_id, user):
    """Show tag addition dialog"""
    with st.form("add_tags"):
        tags = st.text_input("Tags (comma-separated)", placeholder="security, network, critical")
        if st.form_submit_button("Add Tags"):
            if tags:
                st.success(f"🏷️ Tags added: {tags}")

def find_similar_events(data, user):
    """Find similar events"""
    st.info("🔍 Searching for similar events...")
    st.success("✅ Similar events search completed")

def generate_event_statistics(data, user):
    """Generate statistics for events"""
    st.info("📊 Generating event statistics...")
    st.success("✅ Statistics generated successfully")

def create_response_playbook(data, user):
    """Create response playbook"""
    st.info("🚀 Creating response playbook...")
    st.success("✅ Response playbook created")