import streamlit as st
from config import BACKEND, BACKEND_BASE
import pandas as pd
import plotly.express as px
import requests  # type: ignore
from datetime import datetime
from typing import List, Dict, Any

def render_ai_logs_overview():
    """Render the AI logs overview page if AI mode is enabled, otherwise redirect to full logs"""
    try:
        # Load settings from the settings system
        from _pages.settings import load_settings
        settings = load_settings()
        
        # Check if AI mode is enabled in settings
        ai_enabled = settings.get('ai_enabled', False)
        
        # Update session state with settings
        st.session_state.settings = settings
        st.session_state.ai_mode = ai_enabled
        st.session_state.ai_enabled = ai_enabled
        
        if not ai_enabled:
            # Redirect to full logs view if AI mode is disabled
            from components.full_logs import render_full_logs
            from utils.api import create_session
            
            def on_alert_click(alert):
                st.session_state.selected_alert = alert
                st.session_state.view = 'detail'
                st.query_params["view"] = "detail"
                st.session_state.came_from = "logs"  # Track that we came from logs page
                st.rerun()
            
            session = create_session()
            backend_url = BACKEND
            render_full_logs(session, backend_url, on_alert_click)
            return
            
        # AI mode is enabled - render AI-powered logs overview
        from components.page_style import inject_page_css, page_header
        inject_page_css()
        col1, col2 = st.columns([3, 1])
        with col1:
            page_header("Log Analysis", "AI-powered real-time security log analysis", badge="DeepSeek AI")
        with col2:
            st.markdown("<div style='margin-top:32px'></div>", unsafe_allow_html=True)
            auto_refresh = st.checkbox("Auto-refresh", value=True, key="ai_logs_auto_refresh")
        
        # Initialize session state for AI analysis
        if 'ai_analysis_result' not in st.session_state:
            st.session_state.ai_analysis_result = None
        if 'analysis_in_progress' not in st.session_state:
            st.session_state.analysis_in_progress = False
        if 'ai_analysis_auto_triggered' not in st.session_state:
            st.session_state.ai_analysis_auto_triggered = False
        
        # Import DeepSeek AI
        try:
            from utils.gemini_api import analyze_logs_with_gemini
            deepseek_available = True
        except ImportError:
            deepseek_available = False
            st.warning("DeepSeek AI integration is not available. Please check the configuration.")
        
        if not deepseek_available:
            st.info("Showing basic logs overview instead.")
            _render_basic_overview()
            return
        
        # Auto-trigger analysis on first visit
        if not st.session_state.ai_analysis_auto_triggered and not st.session_state.analysis_in_progress:
            st.session_state.analysis_in_progress = True
            st.session_state.ai_analysis_auto_triggered = True
            st.rerun()
        
        # Show basic metrics and charts first (full width)
        st.markdown("---")
        _render_basic_overview()
        
        # AI Analysis section (full width below charts)
        st.markdown("<hr style='border-color:#1a2235;margin:1.5rem 0'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:12px'>DeepSeek AI Analysis Report</div>", unsafe_allow_html=True)

        if st.session_state.ai_analysis_result:
            st.markdown(
                f'<div style="background:#0f1623;border:1px solid #1a2235;border-left:3px solid #1ec8ff;'
                f'border-radius:8px;padding:24px;color:#c8d4e8;font-size:13px;line-height:1.7;">'
                f'{st.session_state.ai_analysis_result}</div>',
                unsafe_allow_html=True,
            )
            st.markdown(f"<div style='font-size:11px;color:#334155;margin-top:8px'>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>", unsafe_allow_html=True)
        else:
            if st.session_state.analysis_in_progress:
                st.info("Analyzing security logs with DeepSeek AI... This may take a moment.")
                st.progress(0.5)
            elif not st.session_state.ai_analysis_auto_triggered:
                st.info("AI analysis will start automatically...")
            else:
                st.info("Analysis complete. Use 'Refresh Analysis' to update with latest data.")
        
        # Perform AI analysis if requested
        if st.session_state.analysis_in_progress:
            with st.spinner('Analyzing logs with DeepSeek AI...'):
                try:
                    # Check if API key is configured in the correct location
                    import os
                    from pathlib import Path
                    
                    # Check for API key in server/.env file (where settings saves it)
                    import os
                    env_path = Path(os.path.join(os.path.dirname(__file__), "../../../server/.env"))
                    api_key = None
                    
                    if env_path.exists():
                        try:
                            env_content = env_path.read_text()
                            for line in env_content.split('\n'):
                                if line.startswith('OPENROUTER_API_KEY='):
                                    api_key = line.split('=', 1)[1].strip()
                                    break
                        except Exception:
                            pass
                    
                    # Also check environment variables as fallback
                    if not api_key:
                        api_key = os.getenv("OPENROUTER_API_KEY")
                    
                    if not api_key:
                        st.session_state.ai_analysis_result = "❌ OpenRouter API key not configured. Please configure it in Settings → AI Settings."
                        st.session_state.analysis_in_progress = False
                        st.rerun()
                        return
                    
                    # Temporarily set the environment variable for the API call
                    os.environ["OPENROUTER_API_KEY"] = api_key
                    
                    # Fetch recent logs (limit to 100 for AI analysis performance)
                    logs = _fetch_recent_logs(limit=100)
                    if logs:
                        # Use DeepSeek AI to analyze logs
                        analysis_result = analyze_logs_with_gemini(logs, "comprehensive")
                        st.session_state.ai_analysis_result = analysis_result
                    else:
                        st.warning("No logs found to analyze. Please ensure the backend service is running.")
                        
                except Exception as e:
                    st.error(f"Error during AI analysis: {str(e)}")
                finally:
                    st.session_state.analysis_in_progress = False
                    st.rerun()
        
        # Auto-refresh functionality
        if auto_refresh:
            import time
            time.sleep(15)  # Refresh every 15 seconds for AI analysis
            st.rerun()
                    
    except Exception as e:
        st.error(f"Error in AI logs overview: {str(e)}")
        st.info("Falling back to basic logs view")
        _render_basic_overview()


def _fetch_recent_logs(limit = None) -> List[Dict[str, Any]]:
    """Fetch recent logs from the backend using same method as full_logs"""
    try:
        from utils.api import create_session
        session = create_session()
        backend_url = BACKEND
        
        # Use same API call as full_logs component
        response = session.get(f"{backend_url}/threats", params={"limit": 100000}, verify=False, timeout=30)
        response.raise_for_status()
        logs = response.json()
        
        # Validate and clean the logs data
        if logs and isinstance(logs, list):
            cleaned_logs = []
            for log in logs:
                if isinstance(log, dict):
                    # Clean and validate each log entry
                    cleaned_log = {}
                    for key, value in log.items():
                        # Convert all values to strings to prevent dataframe issues
                        if value is not None:
                            cleaned_log[key] = str(value) if not isinstance(value, (dict, list)) else value
                        else:
                            cleaned_log[key] = 'Unknown'
                    cleaned_logs.append(cleaned_log)
            
            # Return all logs or limited logs based on limit parameter
            if limit is not None:
                return cleaned_logs[:limit] if cleaned_logs else []
            return cleaned_logs if cleaned_logs else []
        
        return []
        
    except ImportError as e:
        st.error(f"Error importing API utilities: {str(e)}")
        return []
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend server. Please ensure the backend is running.")
        return []
    except requests.exceptions.Timeout:
        st.error("Backend request timed out. The server may be overloaded.")
        return []
    except Exception as e:
        st.error(f"Error fetching logs: {str(e)}")
        return []


def _render_basic_overview():
    """Render enhanced log overview with comprehensive metrics and visuals"""
    try:
        logs = _fetch_recent_logs()
        
        if not logs:
            st.info("No logs available at the moment.")
            return
        
        # Enhanced metrics dashboard
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:12px'>Security Dashboard</div>", unsafe_allow_html=True)
        
        # Main metrics row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        # Count by severity and calculate real statistics
        high_count = len([l for l in logs if l.get('severity', '').lower() == 'high'])
        medium_count = len([l for l in logs if l.get('severity', '').lower() == 'medium'])
        low_count = len([l for l in logs if l.get('severity', '').lower() == 'low'])
        critical_count = len([l for l in logs if l.get('severity', '').lower() == 'critical'])
        
        # Calculate recent activity (last hour approximation)
        from datetime import datetime, timedelta
        try:
            recent_logs = []
            cutoff_time = datetime.now() - timedelta(hours=1)
            for log in logs:
                timestamp_str = log.get('timestamp', '')
                try:
                    log_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if log_time > cutoff_time:
                        recent_logs.append(log)
                except:
                    continue
            recent_count = len(recent_logs)
        except:
            recent_count = len(logs) // 10  # Fallback estimation
        
        # Calculate severity deltas based on comparison to total average
        total_count = len(logs)
        avg_per_severity = total_count // 4 if total_count > 0 else 0
        
        with col1:
            st.metric("Total Threats", total_count, delta=f"+{recent_count} recent")
        with col2:
            delta_critical = critical_count - avg_per_severity
            st.metric("Critical", critical_count, delta=f"{delta_critical:+d} vs avg")
        with col3:
            delta_high = high_count - avg_per_severity
            st.metric("High Severity", high_count, delta=f"{delta_high:+d} vs avg")
        with col4:
            delta_medium = medium_count - avg_per_severity
            st.metric("Medium Severity", medium_count, delta=f"{delta_medium:+d} vs avg")
        with col5:
            delta_low = low_count - avg_per_severity
            st.metric("Low Severity", low_count, delta=f"{delta_low:+d} vs avg")
        
        # Create two columns for side-by-side charts
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:8px'>Severity Distribution</div>", unsafe_allow_html=True)
            severity_data = {
                'Critical': critical_count,
                'High': high_count,
                'Medium': medium_count,
                'Low': low_count
            }
            # Remove zero values
            severity_data = {k: v for k, v in severity_data.items() if v > 0}
            
            if severity_data:
                fig_pie = px.pie(
                    values=list(severity_data.values()),
                    names=list(severity_data.keys()),
                    color_discrete_map={
                        'Critical': '#ef4444',
                        'High':     '#f97316',
                        'Medium':   '#eab308',
                        'Low':      '#22c55e',
                    }
                )
                fig_pie.update_layout(
                    height=300,
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font_color='#a8b4d4',
                    margin=dict(l=10, r=10, t=20, b=10),
                )
                st.plotly_chart(fig_pie, use_container_width=True)
        
        with chart_col2:
            st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:8px'>Threat Timeline</div>", unsafe_allow_html=True)
            try:
                # Parse timestamps and create hourly counts
                from datetime import datetime, timedelta
                import plotly.graph_objects as go
                
                hourly_counts = {}
                for log in logs:
                    timestamp = log.get('timestamp', '')
                    try:
                        # Try parsing different timestamp formats
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        hour_key = dt.strftime('%H:00')
                        hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
                    except:
                        continue
                
                if hourly_counts:
                    hours = sorted(hourly_counts.keys())
                    counts = [hourly_counts[h] for h in hours]
                    
                    fig_timeline = go.Figure(data=go.Scatter(
                        x=hours,
                        y=counts,
                        mode='lines+markers',
                        line=dict(color='#1ec8ff', width=2),
                        marker=dict(size=6, color='#1ec8ff'),
                        fill='tozeroy',
                        fillcolor='rgba(30,200,255,0.06)',
                    ))
                    fig_timeline.update_layout(
                        height=300,
                        xaxis_title="Hour",
                        yaxis_title="Events",
                        showlegend=False,
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#a8b4d4',
                        margin=dict(l=10, r=10, t=20, b=10),
                        xaxis=dict(gridcolor='#1a2235'),
                        yaxis=dict(gridcolor='#1a2235'),
                    )
                    st.plotly_chart(fig_timeline, use_container_width=True)
                else:
                    st.info("Timeline data not available")
            except Exception as e:
                st.warning(f"Timeline chart unavailable: {str(e)}")
        
        st.markdown("<hr style='border-color:#1a2235;margin:1.5rem 0'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:12px'>Threat Sources</div>", unsafe_allow_html=True)
        source_chart_col1, source_chart_col2 = st.columns(2)
        
        with source_chart_col1:
            if logs:
                source_counts = {}
                for log in logs:
                    source = log.get('source', 'Unknown')
                    source_counts[source] = source_counts.get(source, 0) + 1
                
                if source_counts:
                    # Create horizontal bar chart
                    sources = list(source_counts.keys())[:8]  # Top 8
                    counts = [source_counts[s] for s in sources]
                    
                    fig_sources = px.bar(
                        x=counts,
                        y=sources,
                        orientation='h',
                        color=counts,
                        color_continuous_scale=[[0,'#1e2d3d'],[1,'#1ec8ff']],
                    )
                    fig_sources.update_layout(
                        yaxis=dict(categoryorder='total ascending', gridcolor='#1a2235'),
                        xaxis=dict(gridcolor='#1a2235'),
                        height=350,
                        showlegend=False,
                        coloraxis_showscale=False,
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#a8b4d4',
                        margin=dict(l=10, r=10, t=10, b=10),
                    )
                    st.plotly_chart(fig_sources, use_container_width=True)
        
        with source_chart_col2:
            st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:8px'>Geographic Distribution</div>", unsafe_allow_html=True)
            
            # Extract locations for geographic distribution  
            location_counts = {}
            if logs:
                for log in logs:
                    # Extract location from details field if it exists
                    location = 'Unknown'
                    if 'details' in log:
                        details = log['details']
                        if isinstance(details, str):
                            try:
                                import json
                                details_dict = json.loads(details)
                                location = details_dict.get('location', 'Unknown')
                            except:
                                location = 'Unknown'
                        elif isinstance(details, dict):
                            location = details.get('location', 'Unknown')
                    
                    location_counts[location] = location_counts.get(location, 0) + 1
            
            # Use the actual location counts for display
            if location_counts:
                # Remove 'Unknown' if there are real locations
                display_locations = location_counts.copy()
                if len(display_locations) > 1 and 'Unknown' in display_locations:
                    del display_locations['Unknown']
                
                # Take top 10 locations for cleaner display
                sorted_locations = sorted(display_locations.items(), key=lambda x: x[1], reverse=True)[:10]
                
                if sorted_locations:
                    locations = [item[0] for item in sorted_locations]
                    counts = [item[1] for item in sorted_locations]
                    
                    fig_geo = px.bar(
                        x=locations,
                        y=counts,
                        color=counts,
                        color_continuous_scale=[[0,'#1e2d3d'],[1,'#9b6dff']],
                    )
                    fig_geo.update_layout(
                        height=350,
                        showlegend=False,
                        coloraxis_showscale=False,
                        xaxis=dict(title="Location", tickangle=45, gridcolor='#1a2235'),
                        yaxis=dict(title="Events", gridcolor='#1a2235'),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#a8b4d4',
                        margin=dict(l=10, r=10, t=10, b=10),
                    )
                    st.plotly_chart(fig_geo, use_container_width=True)
                else:
                    st.info("Location data not available")
            else:
                st.info("Location data not available")
        
        st.markdown("<hr style='border-color:#1a2235;margin:1.5rem 0'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin-bottom:12px'>Latest Security Events</div>", unsafe_allow_html=True)
        
        try:
            if logs and len(logs) > 0:
                # Process logs similar to dashboard but simpler
                processed_logs = []
                
                for i, log in enumerate(logs[:15]):  # Show top 15
                    try:
                        # Safe data extraction
                        log_entry = {
                            'id': log.get('id', i),
                            'timestamp': log.get('timestamp', 'Unknown'),
                            'source': str(log.get('source', 'Unknown')),
                            'message': str(log.get('message', 'No message')),
                            'severity': str(log.get('severity', 'medium')).lower(),
                            'details': log.get('details', {})
                        }
                        
                        # Ensure severity is valid
                        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
                        if log_entry['severity'] not in valid_severities:
                            log_entry['severity'] = 'medium'
                        
                        # Format timestamp safely
                        try:
                            if log_entry['timestamp'] != 'Unknown':
                                # Try to parse and format timestamp
                                from datetime import datetime
                                if isinstance(log_entry['timestamp'], str):
                                    # Handle different timestamp formats
                                    timestamp_str = log_entry['timestamp'].replace('Z', '+00:00')
                                    dt = datetime.fromisoformat(timestamp_str)
                                    log_entry['formatted_time'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                                else:
                                    log_entry['formatted_time'] = str(log_entry['timestamp'])[:19]
                            else:
                                log_entry['formatted_time'] = 'Unknown'
                        except:
                            log_entry['formatted_time'] = 'Unknown'
                        
                        processed_logs.append(log_entry)
                    except Exception as e:
                        # Skip problematic entries
                        st.warning(f"Skipping malformed log entry: {str(e)}")
                        continue
                
                # Display logs as cards (like dashboard)
                if processed_logs:
                    severity_colors = {
                        'critical': '#ef4444',
                        'high':     '#f97316',
                        'medium':   '#eab308',
                        'low':      '#22c55e',
                        'info':     '#1ec8ff',
                    }

                    for i, log_entry in enumerate(processed_logs):
                        severity = log_entry['severity']
                        color = severity_colors.get(severity, '#64748b')
                        message = log_entry['message']
                        display_message = message[:200] + ('...' if len(message) > 200 else '')

                        col1, col2 = st.columns([0.92, 0.08])
                        with col1:
                            st.markdown(
                                f'<div style="background:#0f1623;border:1px solid #1a2235;border-left:3px solid {color};'
                                f'padding:10px 14px;margin:4px 0;border-radius:6px;">'
                                f'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
                                f'<span style="font-size:12px;font-weight:700;color:{color}">{log_entry["source"].upper()}</span>'
                                f'<span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;'
                                f'color:{color};background:{color}18;padding:2px 8px;border-radius:4px">{severity}</span>'
                                f'</div>'
                                f'<div style="font-size:11px;color:#334155;margin-bottom:6px">{log_entry["timestamp"]}</div>'
                                f'<div style="font-size:13px;color:#c8d4e8;line-height:1.5">{display_message}</div>'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                        with col2:
                            if st.button("View", key=f"ai_view_log_{log_entry.get('id', i)}", use_container_width=True):
                                st.session_state.selected_alert = log_entry
                                st.session_state.show_details = True
                                st.rerun()
                else:
                    st.info("No valid log entries to display")
            else:
                st.info("No logs available at the moment")
                
        except Exception as e:
            st.error(f"Error processing security events: {str(e)}")
            st.info("Please check the backend connection and try refreshing the page")
        
        # Action buttons at bottom right
        if st.session_state.ai_analysis_result:
            st.markdown("---")  # Add a separator line
            
            # Create columns to push buttons to the right
            button_col1, button_col2, button_col3 = st.columns([3, 1, 1])
            
            with button_col2:
                if st.button("Refresh Analysis", key="refresh_ai_analysis_bottom", disabled=st.session_state.analysis_in_progress, use_container_width=True):
                    st.session_state.analysis_in_progress = True
                    st.rerun()

            with button_col3:
                analysis_text = (
                    f"AI-IDS Log Analysis Report\n{'='*40}\n\n"
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Engine: DeepSeek AI\n\n"
                    f"{st.session_state.ai_analysis_result}"
                )
                st.download_button(
                    label="Download Report",
                    data=analysis_text,
                    file_name=f"ai_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    key="download_ai_analysis_bottom",
                    use_container_width=True,
                )
        
    except Exception as e:
        st.error(f"Error rendering enhanced overview: {str(e)}")