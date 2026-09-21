import streamlit as st

def render_sidebar():
    with st.sidebar:
        # Initialize view if not set
        if 'view' not in st.session_state:
            st.session_state.view = 'main'
            
        # Define view groups
        main_views = ['main', 'logs_overview', 'ai_overview', 'vuln_overview', 'gemini_analysis', 'ai_vuln_test', 'sniper_scan', 'multi_scan', 'scan_results']
        
        # Only show main navigation if in a main view or scan view
        if st.session_state.view in main_views:
            # Check if AI mode is enabled
            ai_enabled = st.session_state.get('settings', {}).get('ai_enabled', False)
            
            # Show AI mode status indicator
            if ai_enabled:
                st.success("🤖 AI Mode: Enabled")
            else:
                st.info("🛡️ Standard Mode: Active")
            
            st.markdown("---")
            
            # Dynamic navigation buttons based on AI mode
            if ai_enabled:
                nav_buttons = [
                    ("🤖 AI Dashboard", "main", "AI Dashboard"),
                    ("🤖 AI Logs Analysis", "logs_overview", "AI Logs Analysis"),
                    ("🤖 AI Vulnerability Test", "ai_vuln_test", "AI Vulnerability Test"),
                    ("🛡️ System Vulnerability Test", "vuln_overview", "System Vulnerability Test")
                ]
            else:
                nav_buttons = [
                    ("📊 Dashboard", "main", "Dashboard"),
                    ("📜 Full Logs", "logs_overview", "Full Logs"),
                    ("🤖 AI Vulnerability Test", "ai_vuln_test", "AI Vulnerability Test"),
                    ("🎯 System Vulnerability Test", "vuln_overview", "System Vulnerability Test")
                ]
            
            for btn_text, view_name, selection in nav_buttons:
                if st.button(btn_text, 
                           key=f"nav_{view_name}",
                           use_container_width=True):
                    st.session_state.sidebar_selection = selection
                    st.session_state.view = view_name
                    st.rerun()
            
            # Add Settings and User Management buttons at the bottom
            st.markdown("---")
            if st.button("⚙️ Settings",
                       key="nav_settings",
                       use_container_width=True):
                st.session_state.sidebar_selection = "Settings"
                st.session_state.previous_view = st.session_state.view
                st.session_state.view = 'settings'
                st.rerun()
                

                
        # Show back button in detail view
        elif st.session_state.view == 'detail':
            if st.button("← Back to Dashboard",
                       key="back_to_dash",
                       use_container_width=True):
                # Get the previous view, default to 'main' if not set
                previous_view = st.session_state.get('previous_view', 'main')
                
                # Ensure we have a valid view to return to
                if previous_view is None or previous_view not in ['main', 'logs_overview', 'ai_overview', 'vuln_overview']:
                    previous_view = 'main'
                
                # Set the view and update sidebar selection
                st.session_state.view = previous_view
                st.session_state.sidebar_selection = {
                    'main': 'Dashboard',
                    'logs_overview': 'Full Logs',
                    'ai_vuln_test': 'AI Vulnerability Test',
                    'vuln_overview': 'System Vulnerability Test'
                }.get(st.session_state.view, 'Dashboard')
                st.session_state.selected_alert = None
                st.session_state.auto_refresh = True
                st.rerun()
                
        # Show back button in settings
        elif st.session_state.view == 'settings':
            if st.button("← Back",
                       key="back_from_settings",
                       use_container_width=True):
                previous_view = st.session_state.get("previous_view", "main")
                st.session_state.view = previous_view
                st.session_state.sidebar_selection = {
                    "main": "Dashboard",
                    "logs_overview": "Full Logs",
                    "ai_vuln_test": "AI Vulnerability Test",
                    "vuln_overview": "System Vulnerability Test",
                    "gemini_analysis": "Gemini Analysis",
                    "ai_vuln_test": "AI Vulnerability Test"
                }.get(previous_view, "Dashboard")
                st.rerun()
                
