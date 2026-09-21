import streamlit as st
import plotly.graph_objects as go
import json
from datetime import datetime, timedelta
from utils.api import get_alert_details, create_session

# Import the AI assistant
from components.ai_assistant import ai_assistant, initialize_session_state
from utils.gemini_api import analyze_alert_with_gemini

def render_detail_view(alert_id):
    # Make sure session state is initialized
    initialize_session_state()
    
    # Create a session first
    session = create_session()
    
    # Extract just the ID if we received the full alert object
    if isinstance(alert_id, dict) and 'id' in alert_id:
        alert_id = alert_id['id']
    
    # Fetch alert details with the session
    try:
        alert_data = get_alert_details(session, alert_id)
    except Exception as e:
        st.error(f"Error loading alert: {str(e)}")
        return
    
    if not alert_data:
        st.error("Alert not found or could not be loaded")
        return
    
    # Add back navigation button only when coming from logs
    came_from = st.session_state.get('came_from', 'dashboard')
    if came_from == 'logs':
        if st.button("← Back to Logs", type="secondary"):
            st.session_state.view = 'logs_overview'
            if 'selected_alert' in st.session_state:
                del st.session_state.selected_alert
            if 'came_from' in st.session_state:
                del st.session_state.came_from
            st.rerun()
    
    st.markdown("---")
    
    # Display alert details
    st.header(f"Alert Details: {alert_data.get('title', 'Unknown Alert')}")
    
    # Add buttons at the top
    cols = st.columns([1, 1, 1, 1])
    
    # Add AI Summary button in the top row (move it to first column since we removed the back button)
    with cols[3]:
        if st.session_state.get("ai_mode", False):
            if st.button("🤖 AI Summary", key="top_ai_summary", use_container_width=True):
                # Call the AI assistant to analyze this alert
                ai_assistant.analyze_alert(alert_data)
    
    # Display the alert details
    render_alert_summary(alert_data)
    render_timeline(alert_data)
    
    # Quick action buttons row
    st.subheader("Quick Actions")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("Mark as Resolved", key="mark_resolved"):
            try:
                # Update alert status to resolved
                alert_data['status'] = 'resolved'
                # Here you would typically make an API call to update the alert
                # For now, we'll just show a success message
                st.success(f"✅ Alert {alert_id} marked as resolved")
                # Refresh the alert data
                st.session_state.force_refresh = True
            except Exception as e:
                st.error(f"Failed to mark alert as resolved: {str(e)}")
    
    with col2:
        if st.button("Assign to Me", key="assign_to_me"):
            try:
                # Get current user (in a real app, this would come from authentication)
                current_user = st.session_state.get('current_user', 'admin')
                # Update alert assignment
                alert_data['assigned_to'] = current_user
                # Here you would typically make an API call to update the assignment
                st.success(f"👤 Alert {alert_id} assigned to {current_user}")
                # Refresh the alert data
                st.session_state.force_refresh = True
            except Exception as e:
                st.error(f"Failed to assign alert: {str(e)}")
    
    with col3:
        if st.button("Export Details", key="export_details"):
            try:
                # Create a JSON file with alert details
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"alert_{alert_id}_{timestamp}.json"
                
                # Prepare data for export
                export_data = {
                    'alert_id': alert_id,
                    'title': alert_data.get('title', 'No Title'),
                    'timestamp': alert_data.get('timestamp', ''),
                    'severity': alert_data.get('severity', 'Unknown'),
                    'status': alert_data.get('status', 'open'),
                    'details': alert_data.get('details', {})
                }
                
                # Create a download button for the file
                st.download_button(
                    label="Download Alert Details",
                    data=json.dumps(export_data, indent=2),
                    file_name=filename,
                    mime="application/json"
                )
                st.info(f"📥 Ready to download: {filename}")
            except Exception as e:
                st.error(f"Failed to export alert details: {str(e)}")
            
    with col4:
        # Add the AI Summary button in the quick actions
        if st.session_state.get("ai_mode", False):
            if st.button("AI Summary", key="quick_ai_summary"):
                # Call the AI assistant to analyze this alert
                ai_assistant.analyze_alert(alert_data)
        else:
            # Show disabled button with tooltip when AI mode is off
            st.markdown(
                """
                <div title="Enable AI Mode to use this feature" style="opacity:0.5">
                <button disabled>AI Summary</button>
                </div>
                """, 
                unsafe_allow_html=True
            )
    
    # Render technical details
    render_technical_details(alert_data)
    
    # Additional buttons/actions can go here
    render_quick_actions(alert_data)

import re

def extract_ip_from_alert(alert):
    """Extract IP address from various parts of the alert"""
    # First check the details field
    ip = alert.get('details', {}).get('ip')
    if ip:
        return ip
    
    # Check other common IP fields in details
    details = alert.get('details', {})
    for field in ['source_ip', 'src_ip', 'client_ip', 'remote_ip']:
        ip = details.get(field)
        if ip:
            return ip
    
    # Extract IP from message using regex
    message = alert.get('message', '')
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ip_matches = re.findall(ip_pattern, message)
    if ip_matches:
        return ip_matches[0]  # Return the first IP found
    
    return None

def render_quick_actions(alert):
    """Render quick action buttons"""
    st.subheader("Additional Actions")
    
    # Extract IP to determine if we should show the block IP button
    source_ip = extract_ip_from_alert(alert)
    
    # Dynamically create columns based on available actions
    if source_ip:
        col1, col2, col3 = st.columns(3)
    else:
        col1, col2 = st.columns(2)
    
    # Block IP button (only if IP is present)
    if source_ip:
        with col1:
            if st.button("🚫 Block Source IP", key="block_ip"):
                try:
                    # In a real implementation, this would call an API to block the IP
                    st.success(f"🔒 IP {source_ip} has been blocked in the firewall")
                    
                    # Add to blocked IPs in session state (temporary storage)
                    if 'blocked_ips' not in st.session_state:
                        st.session_state.blocked_ips = set()
                    st.session_state.blocked_ips.add(source_ip)
                    
                except Exception as e:
                    st.error(f"Failed to block IP: {str(e)}")
        
        col_gen_report = col2
        col_alert_team = col3
    else:
        col_gen_report = col1
        col_alert_team = col2
    
    # Generate Report button
    with col_gen_report:
        if st.button("� Generate Report", key="gen_report"):
            st.info("Generating detailed incident report...")
    
    # Alert Team button
    with col_alert_team:
        if st.button("📧 Alert Team", key="alert_team"):
            st.success("Security team notified")

def render_alert_summary(alert):
    """Render the alert summary section"""
    st.markdown(f'''
    <div class="box-3d severity-{alert.get('severity', 'unknown')}">
        <h3>Incident Summary</h3>
        <p><strong>Message:</strong> {alert.get('message', 'No message')}</p>
        <p><strong>Severity:</strong> {alert.get('severity', 'unknown').upper()}</p>
        <p><strong>Timestamp:</strong> {alert.get('timestamp', 'Unknown time')}</p>
        <p><strong>Source:</strong> {alert.get('source', 'Unknown source')}</p>
    </div>
    ''', unsafe_allow_html=True)

def render_timeline(alert):
    """Render the timeline visualization"""
    st.subheader("Event Timeline")
    
    # Safely get timestamp with fallback
    timestamp = alert.get('timestamp')
    if not timestamp:
        st.warning("No timestamp data available for timeline")
        return
        
    try:
        current_time = datetime.fromisoformat(timestamp)
        times = [current_time - timedelta(minutes=i) for i in range(5, -1, -1)]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=times,
            y=[1] * len(times),
            mode='markers+text',
            name='Events',
            text=['Previous Activity', 'System Warning', 'Failed Login', 
                'Alert Triggered', 'Detection', 'Current'],
            marker=dict(size=12, symbol='diamond'),
            textposition='top center'
        ))

        fig.update_layout(
            showlegend=False,
            height=250,
            margin=dict(l=0, r=0, t=30, b=0),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            yaxis=dict(showticklabels=False, showgrid=False),
            xaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)')
        )
        
        st.plotly_chart(fig, use_container_width=True)
    except (ValueError, TypeError) as e:
        st.error(f"Error generating timeline: {str(e)}")

def render_technical_details(alert):
    """Render technical details section"""
    with st.expander("Technical Details", expanded=True):
        st.json(alert.get('details', {}))
    
    # Only show AI analysis if AI mode is enabled
    if st.session_state.get('ai_mode', False):
        with st.expander("🤖 AI Analysis", expanded=True):
            if st.button("Generate AI Analysis", key="generate_ai_analysis"):
                with st.spinner("🤖 AI is analyzing this log entry..."):
                    try:
                        # Generate AI analysis for the current log using Gemini
                        analysis = analyze_alert_with_gemini(alert)
                        
                        if analysis and not analysis.startswith("Error") and not analysis.startswith("Network error"):
                            st.markdown("### AI-Generated Analysis")
                            st.markdown(analysis)
                            
                            # Store the analysis in session state for this alert
                            if 'ai_analyses' not in st.session_state:
                                st.session_state.ai_analyses = {}
                            st.session_state.ai_analyses[alert.get('id')] = analysis
                        else:
                            st.error(analysis)
                    except Exception as e:
                        st.error(f"Error generating AI analysis: {str(e)}")
            
            # Show previously generated analysis if available
            if hasattr(st.session_state, 'ai_analyses') and alert.get('id') in st.session_state.ai_analyses:
                st.markdown("### Previous AI Analysis")
                st.markdown(st.session_state.ai_analyses[alert.get('id')])