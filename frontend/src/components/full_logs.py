import streamlit as st
import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
import re

# Import components
from components.ai_assistant import ai_assistant
from utils.gemini_api import analyze_logs_with_gemini

# Define log categories and their patterns
LOG_CATEGORIES = {
    'Authentication': [
        r'login', r'auth', r'authentication', r'failed log', r'successful log', 
        r'password', r'credential', r'session', r'SSO', r'OAuth', r'2FA', r'MFA'
    ],
    'Network': [
        r'connection', r'port', r'ip', r'network', r'firewall', r'blocked', 
        r'traffic', r'packet', r'bandwidth', r'latency', r'timeout', r'dns'
    ],
    'System': [
        r'system', r'server', r'cpu', r'memory', r'disk', r'load', r'usage', 
        r'reboot', r'shutdown', r'startup', r'service', r'daemon'
    ],
    'Security': [
        r'attack', r'intrusion', r'breach', r'malware', r'virus', r'threat', 
        r'exploit', r'vulnerability', r'CVE-', r'XSS', r'SQLi', r'DDoS'
    ],
    'Application': [
        r'error', r'warning', r'failed', r'crash', r'exception', r'bug', 
        r'application', r'app', r'database', r'query', r'transaction'
    ]
}

# Define severity levels and their colors
SEVERITY_LEVELS = {
    'critical': {'color': '#8B0000', 'icon': '🛑'},
    'high': {'color': '#FF4500', 'icon': '🔴'},
    'medium': {'color': '#FFA500', 'icon': '🟠'},
    'low': {'color': '#1E90FF', 'icon': '🔵'},
    'info': {'color': '#2E8B57', 'icon': 'ℹ️'}
}

def categorize_log_message(message):
    """Categorize log message into predefined categories"""
    if not isinstance(message, str):
        return 'Other'
        
    message = message.lower()
    for category, patterns in LOG_CATEGORIES.items():
        for pattern in patterns:
            if re.search(pattern, message, re.IGNORECASE):
                return category
    return 'Other'

def determine_severity(log):
    """Determine log severity based on message content"""
    message = str(log.get('message', '')).lower()
    
    # Check for critical indicators
    if any(term in message for term in ['critical', 'fatal', 'emergency', 'panic']):
        return 'critical'
    # Check for high severity indicators
    elif any(term in message for term in ['error', 'failed', 'denied', 'blocked', 'attack']):
        return 'high'
    # Check for medium severity indicators
    elif any(term in message for term in ['warning', 'caution', 'suspicious', 'unusual']):
        return 'medium'
    # Check for low severity indicators
    elif any(term in message for term in ['notice', 'info', 'information']):
        return 'low'
    # Default to info
    return 'info'

def load_logs_from_file_fallback():
    """Load logs directly from JSON file as fallback with change detection"""
    import json
    import os
    from pathlib import Path
    import streamlit as st
    
    # Try multiple possible paths for the logs file
    possible_paths = [
        Path("../server/data/dummy_logs.json"),
        Path("./server/data/dummy_logs.json"),
        Path("../data/dummy_logs.json"),
        Path("./data/dummy_logs.json"),
        Path("../../server/data/dummy_logs.json"),
    ]
    
    for log_path in possible_paths:
        try:
            if log_path.exists():
                # Get file modification time to detect changes
                file_mtime = os.path.getmtime(log_path)
                
                # Store file modification time in session state for change detection
                if 'logs_file_mtime' not in st.session_state:
                    st.session_state.logs_file_mtime = 0
                
                # Only reload if file has been modified
                if file_mtime > st.session_state.logs_file_mtime:
                    st.session_state.logs_file_mtime = file_mtime
                    with open(log_path, 'r') as f:
                        logs = json.load(f)
                    
                    # Store logs in session state to avoid constant file reading
                    st.session_state.cached_logs_fallback = logs
                    return logs, str(log_path)
                elif 'cached_logs_fallback' in st.session_state:
                    # Return cached logs if file hasn't changed
                    return st.session_state.cached_logs_fallback, str(log_path)
                else:
                    # First time load
                    with open(log_path, 'r') as f:
                        logs = json.load(f)
                    st.session_state.cached_logs_fallback = logs
                    return logs, str(log_path)
        except Exception as e:
            continue
    
    return [], None

def render_full_logs(session, backend_url, on_alert_click):

    # =====[ AI Summary for Full Logs — button -> PDF ]=====
    st.markdown("### 🤖 AI Log Analysis")
    st.caption("The AI agent inspects the recent logs and returns a downloadable PDF summary.")
    if st.button("Analyze Logs with AI → Summary (PDF)",
                 use_container_width=True,
                 type="primary",
                 key="ai_full_logs_summary_btn"):
        with st.spinner("AI agent is analyzing the recent logs and building your PDF report..."):
            try:
                ai_body = {"hours": 24, "include_summary": True, "format": "pdf"}
                ai_r = session.post(
                    f"{backend_url}/api/v1/reports/generate",
                    json=ai_body,
                    headers={"X-API-Key": "admin"},
                    timeout=90,
                )
                if ai_r.status_code == 200 and ai_r.headers.get("content-type", "").startswith("application/pdf"):
                    st.download_button(
                        "Download AI Summary (PDF)",
                        data=ai_r.content,
                        file_name="ai_summary_full_logs.pdf",
                        mime="application/pdf",
                        key="ai_summary_pdf_dl",
                        use_container_width=True,
                    )
                else:
                    st.warning(f"AI summary service answered HTTP {ai_r.status_code} — showing raw logs below.")
            except Exception as ai_e:
                st.warning(f"AI summary unavailable ({ai_e}); showing the raw logs below.")
        st.markdown("---")

    # Use session from session state if not provided
    if session is None:
        session = st.session_state.session
    if backend_url is None:
        backend_url = st.session_state.backend_url
        
    # Initialize AI assistant if not already done
    if 'ai_assistant' not in st.session_state:
        from components.ai_assistant import AIAssistant
        st.session_state.ai_assistant = AIAssistant()

    # Logs header - no manual refresh, handled by external script
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("📜 Security Logs Overview")
    with col2:
        # Show data source status and current time
        data_source = st.session_state.get('logs_data_source', 'API')
        import time
        current_time = time.strftime("%H:%M:%S")
        
        if data_source == 'FILE':
            st.caption(f"📄 Live • {current_time}")
        else:
            st.caption(f"🌐 Live • {current_time}")
    
    # Static logs view - user manually refreshes to see new logs
    
    # Add AI Analysis button at the top (only when AI mode is enabled)
    if st.session_state.get('ai_mode', False):
        if st.button("🤖 Analyze Logs with AI", use_container_width=True, type="primary"):
            # Note: This will analyze logs after they are filtered below
            pass
    
    # Add visual separator
    st.markdown("---")
    
    # Add custom CSS for log cards
    st.markdown("""
    <style>
    .log-card {
        border-left: 4px solid #4a90e2;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0.25rem;
        background-color: #1e1e2e;
        transition: all 0.2s;
    }
    .log-card:hover {
        background-color: #2a2a3a;
        cursor: pointer;
        transform: translateX(4px);
    }
    .log-card.critical { border-left-color: #ff4d4d; }
    .log-card.high { border-left-color: #ff6b6b; }
    .log-card.medium { border-left-color: #ffa500; }
    .log-card.low { border-left-color: #4dabf7; }
    .log-card.info { border-left-color: #51cf66; }
    .log-time { color: #adb5bd; font-size: 0.8rem; }
    .log-source { font-weight: bold; color: #74c0fc; }
    .log-category { 
        display: inline-block;
        padding: 0.1rem 0.5rem;
        border-radius: 1rem;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 0.5rem;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Custom alert click handler
    def handle_alert_click(threat):
        st.session_state.view = 'detail'  # Set view to detail
        st.query_params["view"] = "detail"
        on_alert_click(threat)  # Call original handler
    
    # If we're supposed to show details, let the main app handle it by returning early
    # The main app.py will call render_detail_view when view == 'detail'
    if st.session_state.get('view') == 'detail':
        return  # Let the main app handle the detail view
    
    # Fetch all logs - try API first, then file fallback
    try:
        with st.spinner("Loading logs..."):
            threats = []
            data_source = "API"
            
            try:
                # Try API first
                response = session.get(
                    f"{backend_url}/threats",
                    params={"limit": 100000},
                    verify=False,
                    timeout=30
                )
                response.raise_for_status()
                threats = response.json()
                st.success("✅ Connected to API backend")
            except Exception as api_error:
                # API failed, try file fallback
                st.info("📄 API unavailable, loading from file...")
                threats, file_path = load_logs_from_file_fallback()
                data_source = "FILE"
                
                if threats:
                    st.success(f"✅ Loaded {len(threats)} logs from: {file_path}")
                    st.session_state.logs_data_source = "FILE"
                else:
                    st.error("❌ No logs found in API or file system")
                    return
            
            # Store data source for status display
            st.session_state.logs_data_source = data_source
            
            # Convert to DataFrame for easier handling
            df = pd.DataFrame(threats)
            
            # Process data according to dummy_logs.json structure
            if not df.empty:
                # Ensure timestamp is datetime
                df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed', dayfirst=False)
                df['date'] = df['timestamp'].dt.date
                df['time'] = df['timestamp'].dt.strftime('%H:%M:%S')
                
                # Use source and message as-is from the data
                # Ensure severity is properly formatted
                df['severity'] = df['severity'].str.lower()
                
                # Ensure severity is one of the defined levels
                df['severity'] = df['severity'].apply(
                    lambda x: x if x in SEVERITY_LEVELS else 'medium'
                )
                
                # Sort by timestamp (newest first)
                df = df.sort_values('timestamp', ascending=False)
            
        # Simple search interface
        with st.expander("🔍 Search Logs", expanded=True):
            # Log search functionality
            search_query = st.text_input(
                "Search logs by message, source, or any field...", 
                placeholder="e.g., 'firewall', 'high severity', 'SQL injection', etc."
            )
            
        # Apply search filter
        if not df.empty:
            df_filtered = df.copy()
            
            # Apply search query across all relevant columns
            if search_query:
                search_terms = search_query.lower().split()
                # Search across message, source, severity, and details
                mask = (
                    df_filtered['message'].str.lower().apply(
                        lambda x: all(term in str(x) for term in search_terms)
                    ) |
                    df_filtered['source'].str.lower().apply(
                        lambda x: all(term in str(x) for term in search_terms)
                    ) |
                    df_filtered['severity'].astype(str).str.lower().apply(
                        lambda x: all(term in str(x) for term in search_terms)
                    )
                )
                df_filtered = df_filtered[mask]
                
            # Show summary stats
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Logs", len(df_filtered))
            with col2:
                st.metric("Unique Sources", df_filtered['source'].nunique())
            with col3:
                st.metric("Critical/High", 
                        len(df_filtered[df_filtered['severity'].isin(['critical', 'high'])]))
            
            # Show AI analysis section if AI is enabled
            if st.session_state.get('ai_enabled', False):
                with st.expander("🤖 AI-Powered Log Analysis", expanded=False):
                    if st.button("Analyze Log Patterns"):
                        with st.spinner("AI is analyzing log patterns..."):
                            # Get top log messages for analysis
                            top_logs = df_filtered.head(100).to_dict('records')
                            analysis = analyze_logs_with_gemini(top_logs, "patterns")
                            st.markdown("### Log Analysis Insights")
                            st.markdown(analysis)
            
            # Guard: nothing left to show after filtering
            if df_filtered is None or df_filtered.empty:
                st.info("No logs match the current filters in this window.")
                return

            # Pagination setup (without controls)
            items_per_page = 25
            total_pages = max(1, (len(df_filtered) + items_per_page - 1) // items_per_page)
            
            # Get current page from session state or default to 1
            if 'current_page' not in st.session_state:
                st.session_state.current_page = 1
            page = st.session_state.current_page
            
            # Ensure page is within bounds
            st.session_state.current_page = max(1, min(st.session_state.current_page, total_pages))
            page = st.session_state.current_page
            
            start_idx = (page - 1) * items_per_page
            end_idx = min(start_idx + items_per_page, len(df_filtered))
            
            # Display logs with enhanced UI
            st.markdown(f"### Showing {start_idx + 1}-{end_idx} of {len(df_filtered)} logs")
            
            # Display logs with clickable cards
            for idx in range(start_idx, end_idx):
                if idx >= len(df_filtered):
                    break
                    
                threat = df_filtered.iloc[idx]
                severity = threat['severity'].lower()
                severity_icon = SEVERITY_LEVELS.get(severity, {}).get('icon', 'ℹ️')
                severity_color = SEVERITY_LEVELS.get(severity, {}).get('color', '#6c757d')
                
                # Create a clickable card for each log entry
                with st.container():
                    # Create columns for actions
                    col1, col2, col3 = st.columns([0.8, 0.1, 0.1])
                    
                    with col1:
                        # Display log card with custom styling
                        st.markdown(f"""
                        <div style="
                            border: 1px solid {severity_color};
                            border-left: 4px solid {severity_color};
                            padding: 12px;
                            margin: 8px 0;
                            border-radius: 6px;
                            background: rgba(255,255,255,0.02);
                        ">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                                <span style="font-weight: bold; color: {severity_color};">
                                    {severity_icon} {threat['source'].upper()}
                                </span>
                                <span style="color: {severity_color}; font-size: 0.9rem;">
                                    {severity.upper()}
                                </span>
                            </div>
                            <div style="margin-bottom: 8px; color: #888; font-size: 0.85rem;">
                                📅 {threat['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
                            </div>
                            <div style="font-size: 0.95rem; line-height: 1.4;">
                                {threat['message'][:200]}{'...' if len(str(threat['message'])) > 200 else ''}
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    with col2:
                        # View Details button - this will trigger the detailed view
                        if st.button("👁️", 
                                   key=f"view_log_{threat.get('id', idx)}",
                                   help="View detailed information",
                                   use_container_width=True):
                            # Create a serializable version of the threat for detailed view
                            threat_dict = {
                                'id': str(threat.get('id', idx)),
                                'timestamp': threat['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                                'source': str(threat['source']),
                                'message': str(threat['message']),
                                'severity': str(threat['severity']),
                                'details': threat.get('details', {}),
                                'type': threat.get('type', 'Unknown')
                            }
                            # Set the selected alert and view for detailed view
                            st.session_state.selected_alert = threat_dict
                            st.session_state.view = 'detail'
                            st.query_params["view"] = "detail"
                            st.session_state.show_details = True
                            st.rerun()
                    
                    # Add AI analysis button for each log entry (only when AI mode is enabled)
                    with col3:
                        if st.session_state.get('ai_mode', False):
                            if st.button("🤖", 
                                       key=f"ai_analyze_{threat.get('id', idx)}",
                                       help="Analyze this log entry with AI",
                                       use_container_width=True):
                                # Create a serializable version of the threat for AI analysis
                                threat_dict = {
                                    'id': str(threat.get('id', idx)),
                                    'timestamp': threat['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                                    'source': str(threat['source']),
                                    'message': str(threat['message']),
                                    'severity': str(threat['severity']),
                                    'details': threat.get('details', {}),
                                    'type': threat.get('type', 'Unknown')
                                }
                                # Use the direct Gemini API for immediate analysis
                                from utils.gemini_api import analyze_alert_with_gemini
                                analysis = analyze_alert_with_gemini(threat_dict)
                                st.markdown("### AI Analysis")
                                st.markdown(analysis)
        
        # Enhanced pagination controls at bottom
        st.markdown("---")
        col1, col2, col3, col4, col5 = st.columns([1, 1, 2, 1, 1])
        
        with col1:
            if st.button("⏮️ First", disabled=(page == 1)):
                st.session_state.current_page = 1
                st.rerun()
        
        with col2:
            if st.button("◀️ Previous", disabled=(page == 1)):
                st.session_state.current_page = page - 1
                st.rerun()
        
        with col3:
            st.markdown(f"<div style='text-align: center; padding: 8px;'><strong>Page {page} of {total_pages}</strong></div>", unsafe_allow_html=True)
            # Page input for direct navigation
            new_page = st.number_input("Go to page:", min_value=1, max_value=total_pages, value=page, key="page_input")
            if new_page != page:
                st.session_state.current_page = new_page
                st.rerun()
        
        with col4:
            if st.button("▶️ Next", disabled=(page == total_pages)):
                st.session_state.current_page = page + 1
                st.rerun()
        
        with col5:
            if st.button("⏭️ Last", disabled=(page == total_pages)):
                st.session_state.current_page = total_pages
                st.rerun()
        
        # Show page info
        st.caption(f"Showing {start_idx + 1}-{end_idx} of {len(df_filtered)} logs total")
        
    except Exception as e:
        st.error(f"Failed to fetch logs: {e}")



def on_alert_click(alert):
    # Make sure we're only passing the ID or a properly formatted alert object
    if isinstance(alert, dict) and 'id' in alert:
        # Convert timestamp to string if it's a pandas Timestamp
        timestamp = alert.get('timestamp', '')
        if hasattr(timestamp, 'strftime'):
            timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        elif not isinstance(timestamp, str):
            timestamp = str(timestamp)
            
        # Just pass the alert ID or a cleaned version of the alert
        clean_alert = {
            'id': alert['id'],
            'timestamp': timestamp,
            'source': alert.get('source', ''),
            'message': alert.get('message', ''),
            'severity': alert.get('severity', ''),
            'details': alert.get('details', {}),
            'type': alert.get('type', '')
        }
        st.session_state.view = "detail"
        st.query_params["view"] = "detail"
        st.session_state.selected_alert = clean_alert
        st.session_state.came_from = "logs"  # Track that we came from logs page
        st.rerun()
    else:
        st.error("Invalid alert format")