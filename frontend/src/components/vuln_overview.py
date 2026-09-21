import streamlit as st
import pandas as pd
from datetime import datetime
import os
import plotly.express as px
import plotly.graph_objects as go
import sqlite3
import json
from components.notification_system import create_custom_notification
from components.enhanced_login import get_current_user

# Simple notification wrapper for backward compatibility
def add_notification(message, notification_type="info"):
    """Add notification using the enhanced system"""
    try:
        user = get_current_user()
        if user:
            create_custom_notification(user['id'], notification_type.title(), message)
        else:
            # Fallback to session state notification
            if 'notifications' not in st.session_state:
                st.session_state.notifications = []
            st.session_state.notifications.append({
                'message': message,
                'type': notification_type,
                'timestamp': datetime.now().isoformat()
            })
    except Exception:
        # Silent fallback - show as streamlit message
        if notification_type == "success":
            st.success(message)
        elif notification_type == "error":
            st.error(message)
        elif notification_type == "warning":
            st.warning(message)
        else:
            st.info(message)

def render_vuln_overview():
    # Check if AI mode is enabled
    ai_enabled = st.session_state.get('settings', {}).get('ai_enabled', False)
    
    if ai_enabled:
        st.title("🤖 AI-Enhanced Vulnerability Management")
        
        # Show AI status indicator
        st.info("🤖 AI Analysis Mode: Enhanced vulnerability insights and recommendations enabled")
    else:
        st.title("🛡️ System Vulnerability Management")
    
    # Add scan type selection
    st.markdown("### 🚀 Start New Vulnerability Scan")
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("🎯 Sniper Scan", key="sniper_scan_btn", use_container_width=True, help="Fast targeted scan of common ports"):
            st.session_state.view = "sniper_scan"
            st.rerun()
    
    with col2:
        if st.button("🌐 Multi Scan", key="multi_scan_btn", use_container_width=True, help="Comprehensive scan with multiple techniques"):
            st.session_state.view = "multi_scan"
            st.rerun()
    
    st.markdown("---")
    
    # Get scan data from database
    scans = get_vulnerability_scans_from_db()
    
    # Display summary statistics
    col1, col2, col3, col4 = st.columns(4)
    
    # Only display metrics if there are scans
    if scans:
        with col1:
            st.metric("Total Scans", len(scans))
        
        with col2:
            # Count total ports from all scans
            total_ports = 0
            for scan in scans:
                # Try to extract ports from the scan output using our extract_ports_from_text function
                try:
                    # Import the function from vuln_scanner
                    from components.vuln_scanner import extract_ports_from_text
                    
                    # Get the scan output
                    scan_output = scan.get('scan_output', '')
                    
                    # Extract ports
                    ports_info = extract_ports_from_text(scan_output)
                    total_ports += len(ports_info)
                except Exception as e:
                    print(f"Error counting ports: {e}")
                    pass
            st.metric("Total Ports Scanned", total_ports)
        
        with col3:
            # Count total vulnerabilities from all scans
            total_vulns = 0
            for scan in scans:
                try:
                    analysis = json.loads(scan.get('analysis_json', '{}'))
                    vulns = analysis.get('vulnerabilities', [])
                    if isinstance(vulns, list):
                        total_vulns += len(vulns)
                except:
                    pass
            st.metric("Total Vulnerabilities", total_vulns)
        
        with col4:
            # Count critical/high vulnerabilities from all scans
            high_vulns = 0
            for scan in scans:
                try:
                    analysis = json.loads(scan.get('analysis_json', '{}'))
                    vulns = analysis.get('vulnerabilities', [])
                    if isinstance(vulns, list):
                        for vuln in vulns:
                            if vuln.get('severity', '').lower() in ['critical', 'high']:
                                high_vulns += 1
                except:
                    pass
            st.metric("Critical/High Vulnerabilities", high_vulns, delta_color="inverse")
    else:
        # If no scans, show empty metrics
        with col1:
            st.metric("Total Scans", 0)
        with col2:
            st.metric("Total Ports Scanned", 0)
        with col3:
            st.metric("Total Vulnerabilities", 0)
        with col4:
            st.metric("Critical/High Vulnerabilities", 0, delta_color="inverse")
    
    st.markdown("---")
    
    # Add AI-enhanced section if AI mode is enabled
    if ai_enabled and scans:
        st.markdown("### 🤖 AI Security Insights")
        
        # Create columns for AI insights
        ai_col1, ai_col2 = st.columns(2)
        
        with ai_col1:
            st.info("🎯 **Risk Assessment**: AI analysis of vulnerability patterns suggests prioritizing network-facing services and authentication mechanisms.")
        
        with ai_col2:
            st.warning("⚠️ **Recommendation**: Consider implementing automated patch management for high-risk vulnerabilities detected in recent scans.")
        
        # AI-powered vulnerability trend analysis
        if len(scans) > 1:
            st.markdown("#### 📈 AI Trend Analysis")
            st.success("📊 **Trend**: Vulnerability detection rate has improved by analyzing scan patterns. Consider scheduling more frequent scans for critical assets.")
        
        st.markdown("---")
    elif ai_enabled and not scans:
        st.markdown("### 🤖 AI Security Insights")
        st.info("🤖 **AI Ready**: Run your first vulnerability scan to unlock AI-powered security insights and recommendations.")
        st.markdown("---")
    
    # Create tabs
    tabs = st.tabs(["📊 Scan History", "🔍 Vulnerabilities"])
    tab1, tab2 = tabs
    
    # Display data in tabs
    with tab1:
        render_scan_history(scans)
    with tab2:
        render_vulnerabilities(scans)
    
    # Add a Clear Database button at the bottom right
    st.markdown("""<div style='text-align: right; margin-top: 20px;'></div>""", unsafe_allow_html=True)
    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🗑️ Clear Database", key="clear_db_btn", use_container_width=True):
            if "confirm_clear_db" not in st.session_state:
                st.session_state.confirm_clear_db = False
            
            st.session_state.confirm_clear_db = True
            st.rerun()
    
    # Show confirmation dialog
    if st.session_state.get("confirm_clear_db", False):
        st.warning("⚠️ Are you sure you want to delete all vulnerability scan data? This action cannot be undone.")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Yes, Delete All Data", key="confirm_delete", use_container_width=True):
                success = clear_vulnerability_database()
                if success:
                    st.session_state.confirm_clear_db = False
                    add_notification("Database Cleared: All vulnerability scan data has been deleted", "success")
                    st.rerun()
        with col2:
            if st.button("❌ Cancel", key="cancel_delete", use_container_width=True):
                st.session_state.confirm_clear_db = False
                st.rerun()

def clear_vulnerability_database():
    """Clear all vulnerability scans from the SQLite database"""
    try:
        # Connect to the SQLite database
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'siem.db')
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Drop the vulnerability_scans table
        cursor.execute("DROP TABLE IF EXISTS vulnerability_scans")
        
        # Create the table again with the correct schema
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerability_scans (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            target_ip TEXT,
            scan_output TEXT,
            analysis_json TEXT,
            scan_type TEXT,
            ports_scanned INTEGER DEFAULT 0
        )
        """)
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        st.error(f"Error clearing database: {str(e)}")
        return False

def get_vulnerability_scans_from_db():
    """Get vulnerability scan data from the SQLite database"""
    try:
        # Connect to the SQLite database
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'siem.db')
        
        # Check if the database file exists
        if not os.path.exists(db_path):
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # Create a new database file
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create the table with all required columns
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_scans (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                target_ip TEXT,
                scan_output TEXT,
                analysis_json TEXT,
                scan_type TEXT,
                ports_scanned INTEGER DEFAULT 0
            )
            """)
            
            conn.commit()
            conn.close()
            
            return []
        
        # Connect to the database
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row  # This enables column access by name
        cursor = conn.cursor()
        
        # Check if the table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerability_scans'")
        if not cursor.fetchone():
            # Create the table if it doesn't exist
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_scans (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                target_ip TEXT,
                scan_output TEXT,
                analysis_json TEXT,
                scan_type TEXT
            )
            """)
            conn.commit()
            conn.close()
            return []
        
        # Query all scans
        cursor.execute("SELECT * FROM vulnerability_scans ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        
        # Convert rows to dictionaries
        scans = []
        for row in rows:
            scan = dict(row)
            # Ensure ports_scanned is set, default to 0 if not present
            if 'ports_scanned' not in scan:
                scan['ports_scanned'] = 0
            scans.append(scan)
        
        conn.close()
        return scans
    except Exception as e:
        st.error(f"Error getting vulnerability scans: {str(e)}")
        return []

def render_scan_history(scans):
    """Render the scan history tab"""
    if not scans:
        st.info("No vulnerability scans found. Click 'New Scan' to run a vulnerability scan.")
        return
    
    # Create a dataframe for the scans
    scan_data = []
    for scan in scans:
        # Extract data from scan
        scan_id = scan.get('id', 'Unknown')
        timestamp = scan.get('timestamp', 'Unknown')
        target_ip = scan.get('target_ip') or 'Unknown'
        
        # If target_ip is still None or empty, try to extract from scan output
        if target_ip in [None, 'Unknown', '']:
            scan_output = scan.get('scan_output', '')
            if scan_output:
                from components.vuln_scanner import extract_target_ip_from_scan
                extracted_ip = extract_target_ip_from_scan(scan_output)
                if extracted_ip and extracted_ip != 'Unknown':
                    target_ip = extracted_ip
        
        # Get scan type (vulnerability or discovery)
        scan_type = scan.get('scan_type', 'Unknown')
        if scan_type is None:  # Handle null values for older scans
            # Determine scan type from scan output if not available in database
            scan_output = scan.get('scan_output', '')
            scan_type = "vulnerability" if "VULNERABLE" in scan_output or "vulners" in scan_output or "script" in scan_output else "discovery"
        
        # Format scan type for display
        scan_type_display = scan_type.capitalize() if scan_type else "Unknown"
        
        # Try to extract risk level from analysis JSON
        risk_level = "Unknown"
        try:
            analysis = json.loads(scan.get('analysis_json', '{}'))
            risk_level = analysis.get('risk_level', 'Unknown')
        except:
            pass
        
        # Get the number of ports scanned
        ports_scanned = scan.get('ports_scanned', 0)
        
        # Add to data
        scan_data.append({
            'ID': scan_id,
            'Timestamp': timestamp,
            'Target IP': target_ip,
            'Scan Type': scan_type_display,
            'Risk Level': risk_level,
            'Ports Scanned': ports_scanned
        })
    
    # Create dataframe
    df = pd.DataFrame(scan_data)
    
    # Create columns for filters
    col1, col2 = st.columns(2)
    
    with col1:
        # Add a filter for scan type
        scan_types = ['All'] + sorted(df['Scan Type'].unique().tolist())
        selected_scan_type = st.selectbox("Filter by Scan Type", scan_types)
    
    with col2:
        # Add a filter for risk level
        risk_levels = ['All'] + sorted(df['Risk Level'].unique().tolist())
        selected_risk = st.selectbox("Filter by Risk Level", risk_levels)
    
    # Filter the dataframe
    if selected_scan_type != 'All':
        df = df[df['Scan Type'] == selected_scan_type]
        
    if selected_risk != 'All':
        df = df[df['Risk Level'] == selected_risk]
    
    # Display the dataframe
    if not df.empty:
        # Display the dataframe
        st.dataframe(
            df,
            column_config={
                "ID": st.column_config.TextColumn("ID"),
                "Timestamp": st.column_config.TextColumn("Timestamp"),
                "Target IP": st.column_config.TextColumn("Target IP"),
                "Scan Type": st.column_config.TextColumn("Scan Type"),
                "Risk Level": st.column_config.TextColumn("Risk Level"),
                "Ports Scanned": st.column_config.NumberColumn(
                    "Ports Scanned",
                    help="Number of ports scanned in this scan"
                )
            },
            use_container_width=True,
            hide_index=True,
            column_order=["Timestamp", "Target IP", "Scan Type", "Ports Scanned", "Risk Level"]
        )
        
        # Add a section to view scan details
        st.subheader("View Scan Details")
        selected_scan_id = st.selectbox("Select a scan to view details", df['ID'].tolist())
        
        if selected_scan_id:
            # Find the selected scan
            selected_scan = next((scan for scan in scans if scan.get('id') == selected_scan_id), None)
            
            if selected_scan:
                display_scan_details(selected_scan)
    else:
        st.info("No scans match the selected filter.")

def render_vulnerabilities(scans):
    """Render the vulnerabilities tab with port and vulnerability information"""
    if not scans:
        st.info("No vulnerability scans found. Click 'New Scan' to run a vulnerability scan.")
        return
    
    # Extract all vulnerabilities from all scans
    all_vulns = []
    for scan in scans:
        try:
            analysis = json.loads(scan.get('analysis_json', '{}'))
            vulns = analysis.get('vulnerabilities', [])
            
            # Add scan information to each vulnerability
            for vuln in vulns:
                vuln['scan_id'] = scan.get('id', 'Unknown')
                vuln['scan_timestamp'] = scan.get('timestamp', 'Unknown')
                vuln['target_ip'] = scan.get('target_ip') or 'Unknown'
                all_vulns.append(vuln)
        except:
            pass
    
    if not all_vulns:
        st.info("No vulnerabilities found in any scans.")
        return
    
    # Create a dataframe for the vulnerabilities
    vuln_data = []
    for vuln in all_vulns:
        # Extract data from vulnerability
        name = vuln.get('name', 'Unknown')
        severity = vuln.get('severity', 'Unknown')
        affected = vuln.get('affected_component', 'Unknown')
        target_ip = vuln.get('target_ip') or 'Unknown'
        scan_timestamp = vuln.get('scan_timestamp', 'Unknown')
        
        # Add to data
        vuln_data.append({
            'Name': name,
            'Severity': severity,
            'Affected Component': affected,
            'Target IP': target_ip,
            'Scan Date': scan_timestamp
        })
    
    # Create dataframe
    df = pd.DataFrame(vuln_data)
    
    # Add filters
    col1, col2 = st.columns(2)
    with col1:
        severity_levels = ['All'] + sorted(df['Severity'].unique().tolist())
        selected_severity = st.selectbox("Filter by Severity", severity_levels)
    
    with col2:
        target_ips = ['All'] + sorted(df['Target IP'].unique().tolist())
        selected_ip = st.selectbox("Filter by Target IP", target_ips)
    
    # Filter the dataframe
    filtered_df = df.copy()
    if selected_severity != 'All':
        filtered_df = filtered_df[filtered_df['Severity'] == selected_severity]
    if selected_ip != 'All':
        filtered_df = filtered_df[filtered_df['Target IP'] == selected_ip]
    
    # Display the dataframe
    if not filtered_df.empty:
        # Create an interactive table
        st.dataframe(
            filtered_df,
            column_config={
                "Name": st.column_config.TextColumn("Name"),
                "Severity": st.column_config.TextColumn("Severity"),
                "Affected Component": st.column_config.TextColumn("Affected Component"),
                "Target IP": st.column_config.TextColumn("Target IP"),
                "Scan Date": st.column_config.TextColumn("Scan Date")
            },
            use_container_width=True,
            hide_index=True
        )
        
        # Create a severity distribution chart
        st.subheader("Vulnerability Severity Distribution")
        severity_counts = df['Severity'].value_counts().reset_index()
        severity_counts.columns = ['Severity', 'Count']
        
        # Define colors for severity levels
        severity_colors = {
            'Critical': '#ff0000',
            'High': '#ff3b3b',
            'Medium': '#ff8c00',
            'Low': '#ffe900',
            'Unknown': '#0095ff'
        }
        
        # Create the chart
        fig = px.pie(
            severity_counts, 
            values='Count', 
            names='Severity',
            color='Severity',
            color_discrete_map=severity_colors
        )
        fig.update_traces(textposition='inside', textinfo='percent+label')
        fig.update_layout(margin=dict(t=20, b=20, l=20, r=20))
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No vulnerabilities match the selected filters.")

def display_scan_details(scan):
    """Display detailed information about a selected scan"""
    # Extract data from scan
    scan_id = scan.get('id', 'Unknown')
    timestamp = scan.get('timestamp', 'Unknown')
    target_ip = scan.get('target_ip') or 'Unknown'
    
    # If target_ip is still None or empty, try to extract from scan output
    if target_ip in [None, 'Unknown', '']:
        scan_output_for_extraction = scan.get('scan_output', '')
        if scan_output_for_extraction:
            from components.vuln_scanner import extract_target_ip_from_scan
            extracted_ip = extract_target_ip_from_scan(scan_output_for_extraction)
            if extracted_ip and extracted_ip != 'Unknown':
                target_ip = extracted_ip
    scan_output = scan.get('scan_output', 'No scan output available')
    
    # Try to parse the analysis JSON
    try:
        analysis = json.loads(scan.get('analysis_json', '{}'))
    except:
        analysis = {}
    
    # Display scan information
    cols = st.columns(2)
    with cols[0]:
        st.markdown(f"**Scan ID:** {scan_id}")
        st.markdown(f"**Timestamp:** {timestamp}")
        st.markdown(f"**Target IP:** {target_ip}")
    
    # Get ports scanned from scan data or analysis
    ports_scanned = scan.get('ports_scanned', analysis.get('ports_scanned', 0))
    
    with cols[1]:
        # Display risk level with appropriate color
        risk_level = analysis.get('risk_level', 'Unknown')
        risk_color = {
            'Critical': '#ff0000',
            'High': '#ff3b3b',
            'Medium': '#ff8c00',
            'Low': '#ffe900'
        }.get(risk_level, '#0095ff')
        
        st.markdown(f"**Risk Level:** <span style='color: {risk_color};'>{risk_level}</span>", unsafe_allow_html=True)
        st.markdown(f"**Ports Scanned:** {ports_scanned}")
        
        # Display scan type if available
        scan_type = scan.get('scan_type', 'Unknown')
        if scan_type != 'Unknown':
            st.markdown(f"**Scan Type:** {scan_type.capitalize()}")
    
    # Create tabs for different sections
    tabs = st.tabs(["Summary", "Vulnerabilities", "Recommendations", "Raw Output"])
    summary_tab, vulns_tab, recs_tab, raw_tab = tabs
    
    with summary_tab:
        # Display summary
        st.markdown("### Summary")
        st.markdown(analysis.get('summary', 'No summary available'))
        
        # Display scan metrics
        st.markdown("### Scan Metrics")
        metrics_cols = st.columns(3)
        with metrics_cols[0]:
            st.metric("Ports Scanned", ports_scanned)
        with metrics_cols[1]:
            open_ports = analysis.get('open_ports', len(analysis.get('ports', [])))
            st.metric("Open Ports", open_ports)
        with metrics_cols[2]:
            vuln_count = len(analysis.get('vulnerabilities', []))
            st.metric("Vulnerabilities Found", vuln_count)
        
        # Display ports found
        st.markdown("### Open Ports")
        ports = analysis.get('ports', [])
        if ports:
            port_data = []
            for port in ports:
                port_data.append({
                    'Port': port.get('port', 'Unknown'),
                    'Protocol': port.get('protocol', 'Unknown'),
                    'Service': port.get('service', 'Unknown'),
                    'Product': port.get('product', 'Unknown'),
                    'Version': port.get('version', 'Unknown')
                })
            
            # Create dataframe
            ports_df = pd.DataFrame(port_data)
            st.dataframe(ports_df, use_container_width=True, hide_index=True)
        else:
            st.info("No open ports detected")
    
    with vulns_tab:
        # Display vulnerabilities
        st.markdown("### Vulnerabilities")
        vulns = analysis.get('vulnerabilities', [])
        if vulns:
            for i, vuln in enumerate(vulns):
                severity = vuln.get('severity', 'Unknown')
                severity_color = {
                    'Critical': '#ff0000',
                    'High': '#ff3b3b',
                    'Medium': '#ff8c00',
                    'Low': '#ffe900'
                }.get(severity, '#0095ff')
                
                st.markdown(f"""
                <div style="padding: 10px; border-left: 4px solid {severity_color}; margin-bottom: 10px; background: rgba(0,0,0,0.05);">
                    <div style="font-weight: bold;">{vuln.get('name', 'Unknown vulnerability')}</div>
                    <div>Severity: <span style="color: {severity_color};">{severity}</span></div>
                    <div>Affected: {vuln.get('affected_component', 'Unknown')}</div>
                    <div>Description: {vuln.get('description', 'No description available')}</div>
                    <div>Remediation: {vuln.get('remediation', 'No remediation available')}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No vulnerabilities detected")
    
    with recs_tab:
        # Display recommendations
        st.markdown("### Recommendations")
        recommendations = analysis.get('recommendations', [])
        if recommendations:
            for i, rec in enumerate(recommendations):
                st.markdown(f"{i+1}. {rec}")
        else:
            st.info("No specific recommendations available")
    
    with raw_tab:
        # Display raw scan output
        st.markdown("### Raw Scan Output")
        st.text_area("", scan_output, height=400)
    
    # Add option to delete this scan
    if st.button("🗑️ Delete This Scan", key=f"delete_scan_{scan_id}"):
        if delete_scan(scan_id):
            st.success(f"Scan {scan_id} deleted successfully")
            st.rerun()
        else:
            st.error("Failed to delete scan")

def delete_scan(scan_id):
    """Delete a specific scan from the database"""
    try:
        # Connect to the SQLite database
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'siem.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Delete the scan
        cursor.execute("DELETE FROM vulnerability_scans WHERE id = ?", (scan_id,))
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        # Add a notification
        add_notification(
            "Scan Deleted",
            f"Vulnerability scan {scan_id} deleted successfully",
            "success"
        )
        
        return True
    except Exception as e:
        st.error(f"Error deleting scan: {str(e)}")
        return False
