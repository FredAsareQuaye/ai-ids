import json
from config import BACKEND, BACKEND_BASE
import os
import sys
import time
import warnings
from datetime import datetime  # type: ignore

# Suppress all warnings and import errors
warnings.filterwarnings("ignore")
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=ImportWarning)
warnings.filterwarnings("ignore", message=".*stub.*")


import pandas as pd
import plotly.express as px
import requests  # type: ignore
import streamlit as st

# Set page configuration - MUST be the first Streamlit command
st.set_page_config(
    page_title="AI-IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Import components
from components.ai_assistant import ai_assistant, render_ai_components
from components.ai_logs_overview import render_ai_logs_overview
from components.ai_vuln_test import AIVulnerabilityTester
from components.detail_view import render_detail_view
from components.full_logs import render_full_logs
from components.login import logout, render_login
from components.scan_analyzer import ScanAnalyzer
from components.sidebar import render_sidebar
from components.vuln_overview import render_vuln_overview
from components.vuln_scanner import VulnerabilityScanner

# Enhanced authentication integrated into login.py
from _pages.detailed_scan import render_detailed_scan
from _pages.sniper_scan import render_page as render_sniper_scan
from _pages.multi_scan import render_page as render_multi_scan
from _pages.scan_results import render_scan_results
from _pages.settings import render_settings
from utils.api import create_session

# Backend configuration
BACKEND_URL = BACKEND
VERIFY_SSL = False  # For development with self-signed certificates

def load_logs_from_file():
    """Load logs directly from JSON file as fallback"""
    import json
    import os
    from pathlib import Path
    import hashlib
    
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
                    st.session_state.cached_logs = logs
                    return logs
                elif 'cached_logs' in st.session_state:
                    # Return cached logs if file hasn't changed
                    return st.session_state.cached_logs
                else:
                    # First time load
                    with open(log_path, 'r') as f:
                        logs = json.load(f)
                    st.session_state.cached_logs = logs
                    return logs
        except Exception as e:
            continue
    
    return []

def get_recent_logs_stats(logs, hours=24):
    """Calculate statistics from recent logs"""
    from datetime import datetime, timedelta
    import json
    
    if not logs:
        return {"total_alerts": 0, "high_severity": 0, "medium_severity": 0, "low_severity": 0, "critical_severity": 0}
    
    # Filter logs from last 24 hours
    cutoff_time = datetime.now() - timedelta(hours=hours)
    recent_logs = []
    
    for log in logs:
        try:
            log_time = datetime.fromisoformat(log.get('timestamp', '').replace('Z', ''))
            if log_time >= cutoff_time:
                recent_logs.append(log)
        except:
            # Include logs with invalid timestamps
            recent_logs.append(log)
    
    # Count by severity
    stats = {"total_alerts": len(recent_logs), "high_severity": 0, "medium_severity": 0, "low_severity": 0, "critical_severity": 0}
    
    for log in recent_logs:
        severity = log.get('severity', 'low').lower()
        if severity in ['critical']:
            stats['critical_severity'] += 1
        elif severity in ['high', 'error']:
            stats['high_severity'] += 1
        elif severity in ['medium', 'warning', 'warn']:
            stats['medium_severity'] += 1
        else:
            stats['low_severity'] += 1
    
    return stats

def get_recent_threats(logs, limit=10):
    """Get recent threats from logs"""
    from datetime import datetime
    
    if not logs:
        return []
    
    # Sort logs by timestamp (most recent first)
    try:
        sorted_logs = sorted(logs, 
                           key=lambda x: datetime.fromisoformat(x.get('timestamp', '').replace('Z', '')), 
                           reverse=True)
    except:
        sorted_logs = logs  # Use original order if sorting fails
    
    # Convert to threat format
    threats = []
    for i, log in enumerate(sorted_logs[:limit]):
        threat = {
            'id': i + 1,
            'timestamp': log.get('timestamp', ''),
            'severity': log.get('severity', 'low'),
            'source': log.get('source', 'unknown'),
            'message': log.get('message', 'No message'),
            'details': log.get('details', {})
        }
        threats.append(threat)
    
    return threats

def render_main_dashboard():
    """Render the main dashboard with alerts and statistics"""
    # Create a session for API calls
    session = create_session()
    
    # Initialize real-time refresh state
    if 'dashboard_last_refresh' not in st.session_state:
        st.session_state.dashboard_last_refresh = 0
    if 'dashboard_refresh_container' not in st.session_state:
        st.session_state.dashboard_refresh_container = None
    
    # Check if AI mode is enabled for enhanced features
    ai_enabled = st.session_state.get('settings', {}).get('ai_enabled', False)
    
    # Add dashboard title with AI indicator - clean header without controls
    header_col1, header_col2 = st.columns([4, 1])
    
    with header_col1:
        if ai_enabled:
            st.title("🤖 AI-Enhanced IDS Security Dashboard")
            st.success("🤖 AI Analysis Mode: Enhanced threat detection and insights enabled")
        else:
            st.title("🛡️ AI-IDS Security Dashboard")
    
    with header_col2:
        if ai_enabled:
            if st.button("🧠 AI Insights", key="ai_insights_btn", help="AI Insights"):
                st.session_state.view = "logs_overview"
                st.query_params["view"] = "logs_overview"
                st.rerun()
        
        # Show current time 
        import time
        time_str = time.strftime("%H:%M:%S")
        st.caption(f"🟢 Live • {time_str}")
    
    # Static dashboard - no automatic refresh, user controls updates manually
    
    try:
        # Try to fetch from API first
        threats = []
        stats = {"total_alerts": 0, "high_severity": 0, "medium_severity": 0, "low_severity": 0, "critical_severity": 0}
        api_working = False
        
        try:
            # Fetch threats for the dashboard
            response_threats = session.get(f"{BACKEND_URL}/threats", timeout=5)
            response_stats = session.get(f"{BACKEND_URL}/stats", timeout=5)
            
            if response_threats.status_code == 200 and response_stats.status_code == 200:
                threats = response_threats.json()
                stats = response_stats.json()
                api_working = True
        except Exception as api_error:
            # API is not working, fall back to file reading
            pass
        
        # If API failed, load from files
        if not api_working:
            st.info("📄 Loading logs from file (API unavailable)")
            logs = load_logs_from_file()
            if logs:
                stats = get_recent_logs_stats(logs)
                threats = get_recent_threats(logs)
                st.success(f"✅ Loaded {len(logs)} logs from file")
            else:
                st.warning("⚠️ No logs found in file system")
        else:
            st.success("✅ Connected to API backend")
        
        # Use much wider spacing between columns
        col1, col2 = st.columns([0.65, 0.35], gap="large")
        
        with col1:
            # Create threat feed container
            with st.container():
                st.markdown("""
                    <div class="box-3d" style="min-height: 80px; padding: 20px; margin-bottom: 30px;">
                        <h2 style="margin-top: 0; color: white; font-size: 1.5rem; margin-bottom: 20px;">Latest Threat Alerts</h2>
                """, unsafe_allow_html=True)
                
                # Display threats
                if not threats:
                    st.info("No security threats to display")
                else:
                    # Sort threats by timestamp (newest first)
                    sorted_threats = sorted(
                        threats,
                        key=lambda x: x.get('timestamp', '1970-01-01T00:00:00Z'),
                        reverse=True
                    )
                    
                    # Show the 5 most recent threats
                    for threat in sorted_threats[:5]:
                        severity = threat.get('severity', 'unknown').lower()
                        severity_class = f"severity-{severity}" if severity in ['high', 'medium', 'low'] else "severity-info"
                        
                        col_a, col_b = st.columns([0.95, 0.05])
                        
                        with col_a:
                            message = threat.get('message', 'No message')
                            # Truncate message for title if too long
                            title_message = message[:50] + '...' if len(message) > 50 else message
                            st.markdown(f"""
                            <div class="alert-box {severity_class}">
                                <h4>{title_message} | {severity.upper()}</h4>
                                <p>{threat.get('message', 'No message')}</p>
                                <small>{threat.get('timestamp', 'Unknown time')}</small>
                            </div>
                            """, unsafe_allow_html=True)
                        
                        with col_b:
                            if st.button("📝", key=f"view_{threat.get('id', hash(json.dumps(threat)))}"):
                                st.session_state.view = "detail"
                                st.query_params["view"] = "detail"
                                st.session_state.selected_alert = threat
                                st.rerun()
                
                # Close the box-3d div
                st.markdown("</div>", unsafe_allow_html=True)
        
        with col2:
            # Create a container with the box-3d class
            with st.container():
                # IMPORTANT: Using custom HTML to guarantee title is inside the box
                st.markdown("""
                    <div class="box-3d" style="min-height: 0px; padding: 20px; margin-bottom: 30px;">
                        <h2 style="margin-top: 0; color: white; font-size: 1.5rem; margin-bottom: 20px;">Quick Stats</h2>
                    """, unsafe_allow_html=True)
                
                # Use stats API response instead of calculated values
                # Use stats.get() with default values to prevent KeyError
                total_alerts = stats.get('total', 0)
                high_severity = stats.get('high', 0)
                medium_severity = stats.get('medium', 0)
                low_severity = stats.get('low', 0)
                
                # Display metrics using custom HTML for consistent styling
                st.markdown("""
                    <style>
                    .stat-container {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 1.5rem;
                        padding: 8px 0;
                        border-bottom: 1px solid rgba(255,255,255,0.1);
                    }
                    .stat-label {
                        color: #ffffff;
                        opacity: 0.85;
                        font-size: 1rem;
                    }
                    .stat-value {
                        color: #ffffff;
                        font-size: 1.6rem;
                        font-weight: 600;
                    }
                    .high-value { color: #ff3b3b; }
                    .medium-value { color: #ff8c00; }
                    .low-value { color: #ffe900; }
                    </style>
                """, unsafe_allow_html=True)
                
                # Render stats with custom styling
                st.markdown(f"""
                    <div class="stat-container">
                        <span class="stat-label">Total Alerts</span>
                        <span class="stat-value">{total_alerts}</span>
                    </div>
                    <div class="stat-container">
                        <span class="stat-label">High Severity</span>
                        <span class="stat-value high-value">{high_severity}</span>
                    </div>
                    <div class="stat-container">
                        <span class="stat-label">Medium Severity</span>
                        <span class="stat-value medium-value">{medium_severity}</span>
                    </div>
                    <div class="stat-container">
                        <span class="stat-label">Low Severity</span>
                        <span class="stat-value low-value">{low_severity}</span>
                    </div>
                """, unsafe_allow_html=True)
                
                # Close the box-3d div
                st.markdown("</div>", unsafe_allow_html=True)
        
        # Second row: Charts for visualizations
        st.markdown("### 📊 Threat Analytics")
        
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            # Create a container with the box-3d class
            with st.container():
                st.markdown("""
                    <div class="box-3d" style="min-height: 0px; padding: 20px; margin-bottom: 30px;">
                        <h3 style="margin-top: 0; color: white; font-size: 1.3rem; margin-bottom: 20px;">Severity Distribution</h3>
                    """, unsafe_allow_html=True)
                
                # Create data for pie chart from stats API
                severity_data = {
                    'Category': ['High', 'Medium', 'Low', 'Info'],
                    'Count': [
                        high_severity,
                        medium_severity,
                        low_severity,
                        total_alerts - (high_severity + medium_severity + low_severity)
                    ]
                }
                
                # Check if there's at least some data
                if sum(severity_data['Count']) > 0:
                    df_severity = pd.DataFrame(severity_data)
                    
                    # Create pie chart
                    fig = px.pie(
                        df_severity,
                        values='Count',
                        names='Category',
                        color='Category',
                        color_discrete_map={
                            'High': '#ff3b3b',
                            'Medium': '#ff8c00',
                            'Low': '#ffe900',
                            'Info': '#0095ff'
                        }
                    )
                    fig.update_traces(textposition='inside', textinfo='percent+label')
                    fig.update_layout(showlegend=True, height=300)
                    
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No severity data available")
                    
                # Close the box-3d div
                st.markdown("</div>", unsafe_allow_html=True)
        
        with chart_col2:
            # Create a container with the box-3d class for alert sources
            with st.container():
                st.markdown("""
                    <div class="box-3d" style="min-height: 0px; padding: 20px; margin-bottom: 30px;">
                        <h3 style="margin-top: 0; color: white; font-size: 1.3rem; margin-bottom: 20px;">Alert Sources</h3>
                    """, unsafe_allow_html=True)
                
                # Get source distribution from threats data
                try:
                    if threats and len(threats) > 0:
                        # Count sources from threats
                        source_counts = {}
                        for threat in threats:
                            source = threat.get('source', 'Unknown')
                            source_counts[source] = source_counts.get(source, 0) + 1
                        
                        # Create bar chart for top sources
                        if source_counts:
                            sources = list(source_counts.keys())[:10]  # Top 10 sources
                            counts = [source_counts[s] for s in sources]
                            
                            fig_sources = px.bar(
                                x=counts,
                                y=sources,
                                orientation='h',
                                color=counts,
                                color_continuous_scale='viridis'
                            )
                            fig_sources.update_layout(
                                yaxis={'categoryorder': 'total ascending'},
                                height=300,
                                showlegend=False,
                                coloraxis_showscale=False
                            )
                            
                            st.plotly_chart(fig_sources, use_container_width=True)
                        else:
                            st.info("No source data available")
                    else:
                        st.info("No alert sources available")
                        
                except Exception as e:
                    st.warning(f"Error creating source chart: {str(e)}")
                    
                # Close the box-3d div
                st.markdown("</div>", unsafe_allow_html=True)
        
        # Add real-time logs section (placeholder)
        st.markdown("---")
        try:
            from components.real_time_logs import render_real_time_logs, render_log_notifications
            # Update notifications with new log alerts
            render_log_notifications()
            # Render real-time logs
            render_real_time_logs()
        except ImportError:
            # Fallback - show simple log monitoring info
            st.subheader("📊 Real-time Log Monitoring")
            st.info("Real-time log monitoring will be available in the next update.")
            
    except Exception as e:
        st.error(f"Error loading dashboard: {str(e)}")

def render_logs_overview():
    """Render logs overview page - uses full logs by default, AI logs if enabled"""
    # Create a back button at the top
    if st.button("◀️ Back to Dashboard", key="logs_overview_back"):
        st.session_state.view = st.session_state.previous_view if "previous_view" in st.session_state else "main"
        st.rerun()
    
    # Create a session for API calls
    session = create_session()
    
    # Define alert click handler
    def on_alert_click(alert):
        st.session_state.selected_alert = alert
        st.session_state.view = 'detail'
        st.query_params["view"] = "detail"
        st.rerun()
    
    # Get AI mode from settings
    ai_enabled = st.session_state.get('settings', {}).get('ai_enabled', False)
    
    # Show AI logs if enabled, otherwise show full logs
    if ai_enabled:
        try:
            from components.ai_logs_overview import render_ai_logs_overview
            render_ai_logs_overview()
        except Exception as e:
            st.error(f"Error loading AI logs: {str(e)}")
            st.error("Falling back to standard logs view")
            render_full_logs(session, BACKEND_URL, on_alert_click)
    else:
        # Show standard full logs view
        render_full_logs(session, BACKEND_URL, on_alert_click)


def create_top_menu():
    """Create a unified top menu with dropdown for user options"""
    # Generate unique IDs for menu elements
    timestamp = int(time.time() * 1000)
    menu_id = f'menu_{timestamp}'
    gear_icon_id = f'gear_icon_{timestamp}'
    
    # Get the AI mode state
    ai_mode = st.session_state.get("ai_mode", False)
    
    # Initialize menu state if it doesn't exist
    if "menu_expanded" not in st.session_state:
        st.session_state.menu_expanded = False
    
    # Add custom CSS for the menu
    st.markdown("""
    <style>
    .menu-container {
        position: fixed;
        top: 10px;
        right: 10px;
        z-index: 1000;
    }
    .menu-button {
        background: none;
        border: none;
        font-size: 1.8em;
        cursor: pointer;
        padding: 8px;
        color: #f0f0f0;
        transition: transform 0.2s;
    }
    .menu-button:hover {
        transform: rotate(45deg);
    }
    .menu-dropdown {
        display: none;
        position: absolute;
        right: 0;
        top: 100%;
        background-color: #1e1e2d;
        min-width: 200px;
        box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
        z-index: 1001;
        border-radius: 4px;
        padding: 10px;
    }
    .menu-dropdown.visible {
        display: flex;
        flex-direction: row;
        gap: 5px;
    }
    .menu-dropdown button {
        background: #2d2d42;
        color: white;
        border: none;
        padding: 8px 12px;
        border-radius: 4px;
        cursor: pointer;
        white-space: nowrap;
        font-size: 0.9em;
        transition: background 0.2s;
    }
    .menu-dropdown button:hover {
        background: #3d3d5a;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Create the menu HTML structure
    menu_html = f"""
    <div class="menu-container">
        <button class="menu-button" id="gear-icon">⚙️</button>
        <div class="menu-dropdown" id="menu-dropdown">
            <button id="ai-toggle">🤖 AI: {'ON' if ai_mode else 'OFF'}</button>
            <button id="view-logs">📋 Logs</button>
            <button id="logout-btn">🚪 Logout</button>
        </div>
    </div>
    <script>
    document.addEventListener('DOMContentLoaded', function() {{
        const gearIcon = document.getElementById('gear-icon');
        const menuDropdown = document.getElementById('menu-dropdown');
        
        // Toggle menu visibility
        gearIcon.addEventListener('click', function(e) {{
            e.stopPropagation();
            menuDropdown.classList.toggle('visible');
        }});
        
        // Close menu when clicking outside
        document.addEventListener('click', function(e) {{
            if (!menuDropdown.contains(e.target) && e.target !== gearIcon) {{
                menuDropdown.classList.remove('visible');
            }}
        }});
        
        // Handle menu item clicks
        document.getElementById('ai-toggle').addEventListener('click', function() {{
            const event = new CustomEvent('toggle-ai-mode');
            document.dispatchEvent(event);
            menuDropdown.classList.remove('visible');
        }});
        
        document.getElementById('view-logs').addEventListener('click', function() {{
            const event = new CustomEvent('show-overview');
            document.dispatchEvent(event);
            menuDropdown.classList.remove('visible');
        }});
        
        document.getElementById('logout-btn').addEventListener('click', function() {{
            const event = new CustomEvent('trigger-logout');
            document.dispatchEvent(event);
            menuDropdown.classList.remove('visible');
        }});
    }});
    </script>
    """
    
    # Add the menu to the page
    st.components.v1.html(menu_html, height=0)
    
    # Handle menu events
    if 'menu_events' not in st.session_state:
        st.session_state.menu_events = False
    
    if not st.session_state.menu_events:
        st.session_state.menu_events = True
        
        # Listen for custom events
        st.components.v1.html("""
        <script>
        document.addEventListener('toggle-ai-mode', function() {
            window.parent.postMessage({type: 'streamlit:setComponentValue', value: 'AI_TOGGLE'}, '*');
        });
        document.addEventListener('show-overview', function() {
            window.parent.postMessage({type: 'streamlit:setComponentValue', value: 'SHOW_OVERVIEW'}, '*');
        });
        document.addEventListener('trigger-logout', function() {
            window.parent.postMessage({type: 'streamlit:setComponentValue', value: 'LOGOUT'}, '*');
        });
        </script>
        """, height=0)
        
        # Handle the events in Python
        if st.session_state.get('_component_value') == 'AI_TOGGLE':
            st.session_state.ai_mode = not st.session_state.get('ai_mode', False)
            st.session_state._component_value = None
            st.rerun()
        elif st.session_state.get('_component_value') == 'SHOW_OVERVIEW':
            st.session_state.page = "vuln_overview"
            st.session_state._component_value = None
            st.rerun()
        elif st.session_state.get('_component_value') == 'LOGOUT':
            st.session_state.authenticated = False
            st.session_state.page = "login"
            st.session_state._component_value = None
            st.rerun()

    # Add click outside behavior - this is now handled by the new menu implementation
    # Keeping this as a fallback
    st.markdown("""
    <script>
    document.addEventListener('click', function(event) {
        // If click is outside the menu container, hide the menu
        const menu = document.querySelector('.menu-container');
        const isClickInside = menu && menu.contains(event.target);
        const isMenuButton = event.target.closest('.menu-button');
        
        if (!isClickInside && !isMenuButton) {
            const menuDropdown = document.querySelector('.menu-dropdown');
            if (menuDropdown) {
                menuDropdown.classList.remove('visible');
            }
        }
    });
    </script>
    """, unsafe_allow_html=True)
        
        # Show dropdown menu if expanded
    if st.session_state.menu_expanded:
            # Add custom CSS for the dropdown menu
            st.markdown("""
            <style>
            /* Style for the dropdown menu container */
            .menu-dropdown {
                position: fixed;
                top: 60px;
                right: -200px;  /* Start off-screen to the right */
                background-color: rgba(30, 30, 50, 0.98);
                border-radius: 8px 0 0 8px;
                box-shadow: -4px 4px 15px rgba(0,0,0,0.3);
                border: 1px solid rgba(255,255,255,0.1);
                width: 200px;
                z-index: 1000;
                padding: 10px 0;
                transition: right 0.3s ease-in-out;
                backdrop-filter: blur(10px);
                border-right: none;
            }
            
            .menu-dropdown.visible {
                right: 0;  /* Slide in from right */
            }
            
            /* Style for menu buttons */
            .menu-dropdown button {
                width: 100%;
                height: 40px;  /* Fixed height for all buttons */
                text-align: center;
                padding: 8px 12px;
                margin: 4px 0;
                border-radius: 4px;
                background-color: rgba(255, 255, 255, 0.1);
                color: white;
                border: none;
                cursor: pointer;
                font-size: 13px;
                transition: all 0.2s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                white-space: nowrap;
                box-sizing: border-box;  /* Include padding in width/height */
            }
            
            .menu-dropdown button:hover {
                background-color: rgba(255, 255, 255, 0.2);
            }
            
            /* Divider style */
            .menu-divider {
                height: 1px;
                background-color: rgba(255, 255, 255, 0.1);
                margin: 6px 0;
            }
            </style>
            """, unsafe_allow_html=True)
            
            # Create the dropdown menu with HTML for better styling control
            ai_status = "ON" if ai_mode else "OFF"
            ai_toggle_id = f"ai_toggle_{hash(str(time.time()))}"
            logout_id = f"logout_btn_{hash(str(time.time()))}"
            overview_btn_id = f"overview_btn_{hash(str(time.time()))}"
            
            # Determine which overview button to show based on AI mode
            overview_text = '🤖 AI Overview' if ai_mode else '📋 Logs Overview'
            
            st.markdown(f"""
            <div class="menu-dropdown">
                <button id="{overview_btn_id}" class="menu-item">
                    {overview_text}
                </button>
                <div class="menu-divider"></div>
                <button id="{ai_toggle_id}" class="menu-item">
                    🤖 AI: {ai_status}
                </button>
                <div class="menu-divider"></div>
                <button id="{logout_id}" class="menu-item">
                    🚪 Logout
                </button>
            </div>
            
            <style>
                .menu-item {{
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 12px;
                    width: 100%;
                    background: transparent;
                    border: none;
                    color: #fff;
                    cursor: pointer;
                    font-size: 14px;
                    border-radius: 4px;
                }}
                
                .menu-item:hover {{
                    background: rgba(255, 255, 255, 0.1);
                }}
            </style>
            
            <script>
            // Initialize dropdown state
            document.addEventListener('DOMContentLoaded', function() {{
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) {{
                    dropdown.classList.remove('visible');
                }}
            }});

            // Close dropdown when clicking outside
            document.addEventListener('click', function(event) {{
                const dropdown = document.getElementById('{menu_id}');
                const gearIcon = document.getElementById('{gear_icon_id}');
                
                // Close dropdown if click is outside both dropdown and gear icon
                if (dropdown && gearIcon && !dropdown.contains(event.target) && event.target !== gearIcon && !gearIcon.contains(event.target)) {{
                    dropdown.classList.remove('visible');
                }}
            }});
            
            // Toggle dropdown visibility when clicking the gear icon
            document.getElementById('{gear_icon_id}').addEventListener('click', function(e) {{
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) {{
                    dropdown.classList.toggle('visible');
                }}
            }});
            
            // Handle menu item clicks
            document.getElementById('{ai_toggle_id}').addEventListener('click', function(e) {{
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) dropdown.classList.remove('visible');
                
                // Toggle AI mode
                const event = new CustomEvent('toggle-ai-mode');
                document.dispatchEvent(event);
            }});
            
            document.getElementById('{overview_btn_id}').addEventListener('click', function(e) {{
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) dropdown.classList.remove('visible');
                
                // Show overview
                const event = new CustomEvent('show-overview');
                document.dispatchEvent(event);
            }});
            
            document.getElementById('{logout_id}').addEventListener('click', function(e) {{
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) dropdown.classList.remove('visible');
                
                // Trigger logout
                const event = new CustomEvent('trigger-logout');
                document.dispatchEvent(event);
            }});
            
            // Handle AI toggle
            document.getElementById('ai_toggle_btn').addEventListener('click', function(e) {{
                e.preventDefault();
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) dropdown.style.display = 'none';
                
                // Toggle AI mode
                fetch('/_stcore/script-runner/script-run-event', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        'type': 'script_runner:script_run',
                        'data': {{ 'script_name': 'toggle_ai' }}
                    }})
                }});
            }});
            
            // Handle overview
            document.getElementById('overview_btn').addEventListener('click', function(e) {{
                e.preventDefault();
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) dropdown.style.display = 'none';
                
                // Trigger overview action
                fetch('/_stcore/script-runner/script-run-event', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        'type': 'script_runner:script_run',
                        'data': {{ 'script_name': 'show_overview' }}
                    }})
                }});
            }});
            
            // Handle logout
            document.getElementById('logout_btn').addEventListener('click', function(e) {{
                e.preventDefault();
                e.stopPropagation();
                const dropdown = document.getElementById('{menu_id}');
                if (dropdown) dropdown.style.display = 'none';
                
                // Trigger logout action
                fetch('/_stcore/script-runner/script-run-event', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        'type': 'script_runner:script_run',
                        'data': {{ 'script_name': 'logout' }}
                    }})
                }});
            }});
            </script>
            """, unsafe_allow_html=True)
            
            # Add event listeners for the custom events
            st.markdown("""
            <script>
            // Handle script runner events
            document.addEventListener('script_runner:script_run', function(e) {{
                const scriptName = e.detail.script_name;
                
                if (scriptName === 'toggle_ai') {{
                    // Toggle AI mode
                    window.parent.postMessage({{type: 'streamlit:setComponentValue', value: {{script_name: 'toggle_ai'}}}}, '*');
                }} else if (scriptName === 'show_overview') {{
                    // Show overview
                    window.parent.postMessage({{type: 'streamlit:setComponentValue', value: {{script_name: 'show_overview'}}}}, '*');
                }} else if (scriptName === 'logout') {{
                    // Handle logout
                    window.parent.postMessage({{type: 'streamlit:setComponentValue', value: {{script_name: 'logout'}}}}, '*');
                }}
            }});
            
            // Logout
            document.addEventListener('logout-action', function() {{
                fetch('/_stcore/script-runner/script-run-event', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        'type': 'script_runner:script_run',
                        'data': {{ 'script_name': 'logout' }}
                    }})
                }});
            }});
            </script>
            """, unsafe_allow_html=True)
            
            # Handle actions from JavaScript
            if 'last_action' in st.session_state:
                action = st.session_state.last_action
                del st.session_state.last_action
                
                if action == 'toggle_ai':
                    st.session_state.ai_mode = not st.session_state.get('ai_mode', False)
                    st.session_state.menu_expanded = False
                    st.rerun()
                    
                elif action == 'show_overview':
                    try:
                        if st.session_state.get("ai_mode", False):
                            # AI Overview logic
                            session = create_session()
                            response = session.get(f"{BACKEND_URL}/threats")
                            
                            if response.status_code != 200:
                                st.error(f"Failed to fetch threats: {response.status_code}")
                            else:
                                data = response.json()
                                st.session_state.overview_logs_data = data
                                
                                if data and len(data) > 0:
                                    st.session_state.gemini_analysis_data = data[0]
                                else:
                                    st.session_state.gemini_analysis_data = {}
                                
                                if "gemini_api_key" not in st.session_state:
                                    st.session_state.gemini_api_key = os.getenv("GOOGLE_GEMINI_API_KEY", "")
                                
                                st.session_state.previous_view = st.session_state.get("view", "main")
                                st.session_state.view = "ai_analysis"
                                st.query_params["view"] = "ai_analysis"
                        else:
                            # Regular Logs Overview logic
                            session = create_session()
                            response = session.get(f"{BACKEND_URL}/threats")
                            
                            if response.status_code != 200:
                                st.error(f"Failed to fetch threats: {response.status_code}")
                            else:
                                st.session_state.overview_logs_data = response.json()
                                st.session_state.view = "logs_overview"
                                st.query_params["view"] = "logs_overview"
                        
                        st.session_state.menu_expanded = False
                        st.rerun()
                            
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
                        st.session_state.menu_expanded = False
                        st.rerun()
                        
                elif action == 'logout':
                    st.session_state.menu_expanded = False
                    logout()
                    st.rerun()

def main():
    # Initialize persistent session state variables
    if 'session_initialized' not in st.session_state:
        # First time initialization
        st.session_state.session_initialized = True
        st.session_state.view = 'main'  # Will be overridden if not authenticated
        st.query_params["view"] = "main"
        # Auto-refresh is now seamless and always enabled
        st.session_state.sidebar_selection = "Dashboard"
        st.session_state.selected_alert = None
        st.session_state.previous_view = None
        
        # Initialize enhanced authentication database
        try:
            from components.login import init_enhanced_database
            init_enhanced_database()
        except:
            pass
        
        # Do NOT initialize authentication state here - let login.py handle it
        # This ensures proper login flow on first visit
    
    # Preserve current view on refresh
    if 'view' not in st.session_state:
        st.session_state.view = 'main'
        st.query_params["view"] = "main"
    
    # Always load settings to ensure they're up to date
    from _pages.settings import load_settings
    settings = load_settings()
    st.session_state.settings = settings
    
    # Synchronize AI mode from settings
    ai_enabled_from_settings = settings.get('ai_enabled', False)
    st.session_state.ai_enabled = ai_enabled_from_settings
    st.session_state.ai_mode = ai_enabled_from_settings
    
    if "ai_config" not in st.session_state:
        st.session_state.ai_config = {"configured": False}
    
    # Check if user is authenticated
    is_authenticated = render_login()
    
    # Only show the main app if authenticated
    if not is_authenticated:
        return
        
    # Get the current view
    current_view = st.session_state.get('view', 'main')
    
    # Create the top menu with dropdown for all pages except scan pages
    if current_view not in ['vuln_scanner', 'ai_vuln_test', 'sniper_scan', 'multi_scan', 'scan_results']:
        create_top_menu()
    
    # Add custom CSS
    st.markdown("""
    <style>
        /* Hide any unwanted sidebar navigation */
        [data-testid="stSidebarNav"] {display: none !important;}
        
        /* Alert box styling */
        .alert-box {
            padding: 1rem;
            margin: 0.5rem 0;
            border-radius: 8px;
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
        }
        .alert-box:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .severity-high {
            background: rgba(255, 59, 59, 0.1);
            border-left: 4px solid #ff3b3b;
        }
        .severity-medium {
            background: rgba(255, 140, 0, 0.1);
            border-left: 4px solid #ff8c00;
        }
        .severity-low {
            background: rgba(255, 233, 0, 0.1);
            border-left: 4px solid #ffe900;
        }
        .severity-info {
            background: rgba(0, 149, 255, 0.1);
            border-left: 4px solid #0095ff;
        }
        
        /* Detail card styling */
        .detail-card {
            background: rgba(255, 255, 255, 0.05);
            padding: 1.5rem;
            border-radius: 10px;
            margin: 1rem 0;
        }
        .back-button {
            padding: 0.5rem 1rem;
            border-radius: 5px;
            background: #2c2c42;
            color: white;
            text-decoration: none;
            margin-bottom: 1rem;
            display: inline-block;
        }
        
        /* 3D box styling */
        .box-3d {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 20px;
            margin: 10px 0;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
            backdrop-filter: blur(4px);
            border: 1px solid rgba(255, 255, 255, 0.18);
            transition: transform 0.3s ease;
        }
        
        .box-3d:hover {
            transform: translateY(-5px);
        }
        
        /* Generic page layout */
        .detail-page {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        /* Notification styling */
        .notification {
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            background: rgba(255,255,255,0.1);
            border-left: 4px solid;
        }
        
        .notification.success {
            border-color: #00ff95;
            background: rgba(0,255,149,0.1);
        }
        
        .notification.info {
            border-color: #0095ff;
            background: rgba(0,149,255,0.1);
        }
        
        .notification.warning {
            border-color: #ffb300;
            background: rgba(255,179,0,0.1);
        }
        
        .notification small {
            display: block;
            opacity: 0.7;
            margin-top: 5px;
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Add a small spacer to push content down below the top menu
    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
    
    # Render sidebar
    render_sidebar()
    
    # Seamless auto-refresh is now handled directly in individual components
    
    # Main content area - handle different views
    view = st.session_state.get('view', 'main')  # Default to 'main' if view is None
    
    if view == 'main':
        render_main_dashboard()
    elif view == 'logs_overview':
        render_logs_overview()
    elif view == 'vuln_overview':
        render_vuln_overview()
    elif view == 'detail':
        render_detail_view(st.session_state.get('selected_alert'))
    elif view == 'ai_vuln_test':
        AIVulnerabilityTester().render()
    elif view == 'sniper_scan':
        render_sniper_scan()
    elif view == 'multi_scan':
        render_multi_scan()
    elif view == 'scan_results':
        render_scan_results()
    elif view == 'detailed_scan':
        # Get the selected scan ID from session state
        selected_scan_id = st.session_state.get("selected_scan_id")
        render_detailed_scan(selected_scan_id)
    elif view == 'settings':
        render_settings()

    else:
        st.error(f"Invalid view selected: {view}")

if __name__ == "__main__":
    main()