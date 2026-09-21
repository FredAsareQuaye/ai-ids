import streamlit as st
import json
import os
import requests  # type: ignore
from pathlib import Path
import time

def initialize_session_state():
    """Initialize all required session state variables"""
    if "ai_mode" not in st.session_state:
        st.session_state.ai_mode = False
        
    if "ai_config" not in st.session_state:
        st.session_state.ai_config = {
            'api_key': '',
            'configured': False
        }
        
    if "show_ai_config" not in st.session_state:
        st.session_state.show_ai_config = False
        
    if "ai_analysis_data" not in st.session_state:
        st.session_state.ai_analysis_data = None
        
    if "ai_analysis_complete" not in st.session_state:
        st.session_state.ai_analysis_complete = False
        
    if "ai_analysis_text" not in st.session_state:
        st.session_state.ai_analysis_text = ""
        
    if "previous_page" not in st.session_state:
        st.session_state.previous_page = "home"

# Initialize session state variables first
initialize_session_state()

class AIAssistant:
    def __init__(self):
        self.config_file = Path(".ai_keys")
        self.load_config()
        
        # Ensure the config file is not readable by others
        if self.config_file.exists():
            try:
                os.chmod(self.config_file, 0o600)  # Only owner can read/write
            except Exception:
                pass
    
    def load_config(self):
        """Load AI configuration from file"""
        # Load from file if exists
        if self.config_file.exists():
            try:
                config = json.loads(self.config_file.read_text())
                st.session_state.ai_config = config
                return True
            except Exception as e:
                return False
        return False
    
    def save_config(self):
        """Save AI configuration to file"""
        try:
            self.config_file.write_text(json.dumps(st.session_state.ai_config))
            # Ensure the config file is not readable by others
            os.chmod(self.config_file, 0o600)  # Only owner can read/write
            return True
        except Exception as e:
            return False
    
    def render_ai_toggle(self):
        """Handle AI mode state (UI is now in the top menu dropdown)"""
        # Make sure session state is initialized
        initialize_session_state()
        
        # This method is kept for backward compatibility but doesn't render anything
        # The actual UI toggle is now in the top menu dropdown
        pass
    
    def render_config_modal(self):
        """Render the AI configuration modal dialog"""
        # Make sure session state is initialized
        initialize_session_state()
        
        if st.session_state.get("show_ai_config", False):
            # Create form for configuration
            with st.form("ai_config_form"):
                st.subheader("Configure DeepSeek AI Assistant")
                st.markdown("Enter your DeepSeek API key to enable AI-powered log analysis")
                
                api_key = st.text_input(
                    "DeepSeek API Key", 
                    value=st.session_state.ai_config.get('api_key', ''),
                    type="password",
                    help="Get your API key from https://makersuite.google.com/app/apikey"
                )
                
                # Only have form submit buttons in the form
                submitted = st.form_submit_button("Save Configuration")
                cancel_submit = st.form_submit_button("Cancel")
                
                if submitted:
                    if not api_key:
                        st.error("API key is required to enable AI features")
                        return
                        
                    st.session_state.ai_config = {
                        'api_key': api_key,
                        'configured': True
                    }
                    success = self.save_config()
                    if success:
                        st.session_state.show_ai_config = False
                        st.rerun()
                    
                if cancel_submit:
                    st.session_state.show_ai_config = False
                    if not st.session_state.ai_config.get('configured', False):
                        st.session_state.ai_mode = False
                    st.rerun()
    
    def analyze_alert(self, alert_data):
        """Analyze a single alert using DeepSeek AI and return results directly"""
        # Make sure session state is initialized
        initialize_session_state()
        
        if not st.session_state.get("ai_mode", False):
            st.warning("AI features are currently disabled. Enable AI mode in settings to use this feature.")
            return None
                
        # Use the centralized DeepSeek function
        try:
            from utils.gemini_api import analyze_alert_with_gemini
            return analyze_alert_with_gemini(alert_data)
        except ImportError:
            st.error("DeepSeek API integration is not available.")
            return None

    def analyze_log_patterns(self, logs_data):
        """Analyze log patterns using DeepSeek AI and return results directly"""
        # Make sure session state is initialized
        initialize_session_state()
        
        if not st.session_state.get("ai_mode", False):
            st.warning("AI features are currently disabled. Enable AI mode in settings to use this feature.")
            return None
                
        # Use the centralized DeepSeek function
        try:
            from utils.gemini_api import analyze_logs_with_gemini
            return analyze_logs_with_gemini(logs_data, "patterns")
        except ImportError:
            st.error("DeepSeek API integration is not available.")
            return None
        
    def analyze_logs(self, logs_data):
        """Analyze multiple logs using DeepSeek AI and return results directly"""
        # Make sure session state is initialized
        initialize_session_state()
        
        if not st.session_state.get("ai_mode", False):
            st.warning("AI features are currently disabled. Enable AI mode in settings to use this feature.")
            return None
                
        if not logs_data or len(logs_data) == 0:
            st.warning("No log data to analyze")
            return None
        
        # Use the centralized DeepSeek function
        try:
            from utils.gemini_api import analyze_logs_with_gemini
            return analyze_logs_with_gemini(logs_data, "comprehensive")
        except ImportError:
            st.error("DeepSeek API integration is not available.")
            return None

    def render_analysis_page(self):
        """Render the AI analysis page"""
        # Make sure we have alert data to analyze
        if not st.session_state.ai_analysis_data:
            st.error("No alert data to analyze. Please select an alert first.")
            if st.button("Return to Dashboard"):
                st.session_state.page = "home"
                st.rerun()
            return

# Initialize the assistant
ai_assistant = AIAssistant()

def render_ai_components():
    """Render AI configuration modal only (toggle is now in the top menu)"""
    # Make sure session state is initialized
    initialize_session_state()
    
    # Render the configuration modal if needed
    ai_assistant.render_config_modal()
