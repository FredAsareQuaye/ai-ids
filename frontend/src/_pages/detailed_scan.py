import streamlit as st
import requests  # type: ignore
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os
from utils.api import create_session
from config import BACKEND, BACKEND_BASE

def render_detailed_scan(scan_id=None):
    """Render a detailed view of a vulnerability scan"""
    st.title("Detailed Vulnerability Scan")
    
    # Create a session for API calls
    session = create_session()
    
    # If no scan_id is provided, check if it's in the session state
    if scan_id is None:
        scan_id = st.session_state.get("selected_scan_id")
    
    if not scan_id:
        st.error("No scan selected. Please select a scan from the vulnerability overview page.")
        if st.button("← Back to Overview"):
            st.session_state.view = "vuln_overview"
            st.query_params["view"] = "vuln_overview"
            st.rerun()
        return
    
    # Fetch scan data from API
    try:
        # Try multiple endpoint patterns
        endpoints = [
            f"{BACKEND_BASE}/api/v1/vulnerability/scan/{scan_id}",
            f"{BACKEND_BASE}/vulnerability/scan/{scan_id}"
        ]
        
        response = None
        for endpoint in endpoints:
            try:
                response = session.get(endpoint, timeout=5)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                continue
                
        if not response or response.status_code != 200:
            st.error(f"Error fetching scan data: {response.text if response else 'No response from any endpoint'}")
            return
        
        scan_data = response.json()
        summary = scan_data.get("summary", {})
        details = scan_data.get("details", {})
        
        # Display scan summary in a modern card
        st.markdown("""
        <style>
        .scan-card {
            background-color: #1E1E1E;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #00A0FF;
        }
        .scan-header {
            color: #FFFFFF;
            font-size: 1.5rem;
            margin-bottom: 10px;
        }
        .scan-meta {
            color: #B0B0B0;
            font-size: 0.9rem;
            margin-bottom: 15px;
        }
        .scan-stats {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
        .stat-item {
            background-color: #2D2D2D;
            border-radius: 5px;
            padding: 10px;
            flex: 1;
            min-width: 120px;
            text-align: center;
        }
        .stat-value {
            font-size: 1.8rem;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 0.8rem;
            color: #B0B0B0;
        }
        .critical { color: #FF4444; }
        .high { color: #FFA500; }
        .medium { color: #FFFF00; }
        .low { color: #00BFFF; }
        </style>
        """, unsafe_allow_html=True)
        
        # Create the summary card
        st.markdown(f"""
        <div class="scan-card">
            <div class="scan-header">{scan_name}</div>
            <div class="scan-meta">Target: {target} • Type: {scan_type} • Date: {formatted_date}</div>
            <div class="scan-stats">
                <div class="stat-item">
                    <div class="stat-value">{total_ports}</div>
                    <div class="stat-label">OPEN PORTS</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{summary.get("total_vulnerabilities", 0)}</div>
                    <div class="stat-label">VULNERABILITIES</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value critical">{summary.get("critical_vulns", 0)}</div>
                    <div class="stat-label">CRITICAL</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value high">{summary.get("high_vulns", 0)}</div>
                    <div class="stat-label">HIGH</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value medium">{summary.get("medium_vulns", 0)}</div>
                    <div class="stat-label">MEDIUM</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value low">{summary.get("low_vulns", 0)}</div>
                    <div class="stat-label">LOW</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Create tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🔓 Vulnerabilities", "🖥️ Open Ports", "📝 Raw Output"])
        
        with tab1:
            # Create a vulnerability severity distribution chart
            st.subheader("Vulnerability Severity Distribution")
            
            severity_data = {
                "Severity": ["Critical", "High", "Medium", "Low"],
                "Count": [
                    summary.get("critical_vulns", 0),
                    summary.get("high_vulns", 0),
                    summary.get("medium_vulns", 0),
                    summary.get("low_vulns", 0)
                ]
            }
            
            severity_df = pd.DataFrame(severity_data)
            
            # Only create the chart if there are vulnerabilities
            if sum(severity_data["Count"]) > 0:
                fig = px.bar(
                    severity_df, 
                    x="Severity", 
                    y="Count",
                    color="Severity",
                    color_discrete_map={
                        "Critical": "#FF4444",
                        "High": "#FFA500",
                        "Medium": "#FFFF00",
                        "Low": "#00BFFF"
                    },
                    height=400
                )
                fig.update_layout(
                    plot_bgcolor="rgba(0,0,0,0)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#FFFFFF"),
                    xaxis=dict(showgrid=False),
                    yaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.1)")
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No vulnerabilities found in this scan.")
            
            # Display scan information
            st.subheader("Scan Information")
            
            # Create two columns
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Target Information**")
                st.markdown(f"**Target:** {summary.get('target', 'Unknown')}")
                st.markdown(f"**Scan Name:** {summary.get('scan_name', 'Unknown')}")
                st.markdown(f"**Scan Type:** {summary.get('scan_type', 'Unknown')}")
                
            with col2:
                st.markdown("**Scan Details**")
                st.markdown(f"**Scan Date:** {formatted_date}")
                st.markdown(f"**Total Open Ports:** {summary.get('total_ports', 0)}")
                st.markdown(f"**Duration:** {summary.get('duration', 'Unknown')}")
            
            # Enhanced Timeline Chart
            st.subheader("📈 Scan Timeline Analysis")
            
            # Create mock timeline data for demonstration (simulating scan progress)
            timeline_data = []
            base_time = datetime.strptime(summary.get('scan_date', '2025-09-15T14:00:00'), '%Y-%m-%dT%H:%M:%S')
            
            # Simulate scan phases
            phases = [
                {"phase": "Initialization", "time_offset": 0, "discoveries": 0, "color": "#00BFFF"},
                {"phase": "Port Discovery", "time_offset": 2, "discoveries": summary.get('total_ports', 0) // 3, "color": "#32CD32"},
                {"phase": "Service Detection", "time_offset": 5, "discoveries": summary.get('total_ports', 0) // 2, "color": "#FFD700"},
                {"phase": "Vulnerability Scanning", "time_offset": 10, "discoveries": summary.get('total_ports', 0), "color": "#FFA500"},
                {"phase": "Analysis Complete", "time_offset": 15, "discoveries": summary.get("total_vulnerabilities", 0), "color": "#FF6B6B"}
            ]
            
            if phases:
                times = []
                discoveries = []
                phase_names = []
                colors = []
                
                for phase in phases:
                    phase_time = base_time.replace(
                        minute=base_time.minute + phase["time_offset"]
                    )
                    times.append(phase_time.strftime('%H:%M'))
                    discoveries.append(phase["discoveries"])
                    phase_names.append(phase["phase"])
                    colors.append(phase["color"])
                
                # Create enhanced timeline chart
                fig_timeline = go.Figure()
                
                # Add line chart
                fig_timeline.add_trace(go.Scatter(
                    x=times,
                    y=discoveries,
                    mode='lines+markers+text',
                    line=dict(color='#FF6B6B', width=4, shape='spline'),
                    marker=dict(
                        size=12, 
                        color=colors,
                        line=dict(width=2, color='white')
                    ),
                    text=phase_names,
                    textposition="top center",
                    textfont=dict(size=10, color='white'),
                    hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Discoveries: %{y}<extra></extra>',
                    name='Scan Progress'
                ))
                
                # Add area fill under the line
                fig_timeline.add_trace(go.Scatter(
                    x=times,
                    y=discoveries,
                    fill='tonexty',
                    mode='none',
                    fillcolor='rgba(255, 107, 107, 0.2)',
                    showlegend=False
                ))
                
                fig_timeline.update_layout(
                    height=400,
                    title="Scan Progress Timeline",
                    xaxis_title="Time",
                    yaxis_title="Items Discovered",
                    plot_bgcolor="rgba(0,0,0,0.1)",
                    paper_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#FFFFFF", size=12),
                    title_font=dict(size=16, color="#FFFFFF"),
                    xaxis=dict(
                        showgrid=True, 
                        gridcolor="rgba(255,255,255,0.1)",
                        linecolor="rgba(255,255,255,0.3)"
                    ),
                    yaxis=dict(
                        showgrid=True, 
                        gridcolor="rgba(255,255,255,0.1)",
                        linecolor="rgba(255,255,255,0.3)"
                    ),
                    showlegend=False
                )
                
                st.plotly_chart(fig_timeline, use_container_width=True)
            else:
                st.info("Timeline data not available for this scan.")
                st.markdown(f"**Total Vulnerabilities:** {summary.get('total_vulnerabilities', 0)}")
        
        with tab2:
            st.subheader("Detected Vulnerabilities")
            
            # Get vulnerabilities from details
            vulnerabilities = details.get("vulnerabilities", [])
            
            if vulnerabilities:
                # Create a dataframe for the vulnerabilities
                vuln_data = []
                for vuln in vulnerabilities:
                    vuln_data.append({
                        "Name": vuln.get("name", "Unknown"),
                        "Severity": vuln.get("severity", "Unknown"),
                        "Port": vuln.get("port", "N/A"),
                        "Service": vuln.get("service", "N/A"),
                        "Details": vuln.get("details", "")
                    })
                
                vuln_df = pd.DataFrame(vuln_data)
                
                # Create a color-coded dataframe
                def highlight_severity(val):
                    if val == "Critical":
                        return "background-color: #FF444455; color: #FF4444"
                    elif val == "High":
                        return "background-color: #FFA50055; color: #FFA500"
                    elif val == "Medium":
                        return "background-color: #FFFF0055; color: #FFFF00"
                    elif val == "Low":
                        return "background-color: #00BFFF55; color: #00BFFF"
                    return ""
                
                # Display the dataframe with styling
                st.dataframe(
                    vuln_df.style.applymap(highlight_severity, subset=["Severity"]),
                    use_container_width=True,
                    height=400
                )
                
                # Create an expandable section for each vulnerability with details
                st.subheader("Vulnerability Details")
                for i, vuln in enumerate(vulnerabilities):
                    severity = vuln.get("severity", "Unknown")
                    severity_color = {
                        "Critical": "🔴",
                        "High": "🟠",
                        "Medium": "🟡",
                        "Low": "🔵"
                    }.get(severity, "⚪")
                    
                    with st.expander(f"{severity_color} {vuln.get('name', 'Unknown')} - Port {vuln.get('port', 'N/A')} ({vuln.get('service', 'N/A')})"):
                        st.markdown(f"**Severity:** {severity}")
                        st.markdown(f"**Port:** {vuln.get('port', 'N/A')}")
                        st.markdown(f"**Service:** {vuln.get('service', 'N/A')}")
                        st.markdown("**Details:**")
                        st.code(vuln.get("details", "No details available"), language="text")
            else:
                st.info("No vulnerabilities were detected in this scan.")
        
        with tab3:
            st.subheader("Open Ports")
            
            # Get ports from details
            ports = details.get("ports", [])
            port_details = details.get("port_details", {})
            
            if ports:
                # Create a dataframe for the ports
                port_data = []
                for port in ports:
                    # Find the port details
                    port_info = None
                    for key, value in port_details.items():
                        if key.startswith(f"{port}/"):
                            port_info = value
                            break
                    
                    if port_info:
                        port_data.append({
                            "Port": port,
                            "Protocol": port_info.get("protocol", "N/A"),
                            "State": port_info.get("state", "open"),
                            "Service": port_info.get("service", "N/A"),
                            "Details": ", ".join(port_info.get("details", []))[:50] + "..." if len(port_info.get("details", [])) > 0 else "No details"
                        })
                    else:
                        port_data.append({
                            "Port": port,
                            "Protocol": "N/A",
                            "State": "open",
                            "Service": "N/A",
                            "Details": "No details"
                        })
                
                port_df = pd.DataFrame(port_data)
                
                # Display the dataframe
                st.dataframe(port_df, use_container_width=True)
                
                # Create an expandable section for each port with details
                st.subheader("Port Details")
                for key, value in port_details.items():
                    port = value.get("port", "Unknown")
                    protocol = value.get("protocol", "Unknown")
                    service = value.get("service", "Unknown")
                    
                    with st.expander(f"Port {port}/{protocol} - {service}"):
                        st.markdown(f"**Port:** {port}")
                        st.markdown(f"**Protocol:** {protocol}")
                        st.markdown(f"**Service:** {service}")
                        
                        # Display details if available
                        details = value.get("details", [])
                        if details:
                            st.markdown("**Details:**")
                            for detail in details:
                                st.code(detail, language="text")
                        else:
                            st.info("No additional details available for this port.")
            else:
                st.info("No open ports were detected in this scan.")
        
        with tab4:
            # Show raw scan output
            st.subheader("Raw Scan Output")
            
            # Show command used
            st.markdown(f"**Command Used:** `{nmap_cmd}`")
            
            # Get raw output
            if not raw_output:
                raw_output = details.get("raw_output", "No raw output available")
            
            # Display in code block with syntax highlighting for nmap output
            st.code(raw_output, language="text")
            
            # Add download options
            col1, col2 = st.columns(2)
            with col1:
                # Download as text
                st.download_button(
                    label="Download as Text",
                    data=raw_output,
                    file_name=f"scan_{scan_id}_raw_output.txt",
                    mime="text/plain"
                )
            
            with col2:
                # Download as JSON
                try:
                    # Create a JSON representation of the scan
                    json_data = json.dumps({
                        "summary": summary,
                        "details": details,
                        "raw_output": raw_output
                    }, indent=2)
                    
                    st.download_button(
                        label="Download as JSON",
                        data=json_data,
                        file_name=f"scan_{scan_id}_data.json",
                        mime="application/json"
                    )
                except Exception as e:
                    st.error(f"Could not create JSON download: {str(e)}")
            
            # Add option to re-run scan with same parameters
            if st.button("Re-run this scan", key="rerun_scan_btn"):
                # Store the scan parameters in session state
                st.session_state.scan_target = target
                st.session_state.scan_name = f"Re-scan of {scan_name}"
                st.session_state.scan_type = "sniper"  # Default to sniper scan
                st.session_state.view = "vuln_overview"
                st.query_params["view"] = "vuln_overview"
                st.rerun()
        
        # Add a back button at the bottom
        if st.button("← Back to Overview", key="back_button_bottom"):
            st.session_state.view = "vuln_overview"
            st.query_params["view"] = "vuln_overview"
            st.rerun()
            
    except Exception as e:
        st.error(f"Error rendering detailed scan view: {str(e)}")
        if st.button("← Back to Overview", key="error_back_button"):
            st.session_state.view = "vuln_overview"
            st.query_params["view"] = "vuln_overview"
            st.rerun()

if __name__ == "__main__":
    render_detailed_scan()
