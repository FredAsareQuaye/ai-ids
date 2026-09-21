import os
import json
import requests  # type: ignore
import streamlit as st
from pathlib import Path

class AIHelper:
    """Utility class for interacting with AI APIs"""
    
    def __init__(self):
        """Initialize the AI helper"""
        self.config_file = Path(".ai_keys")
        self.load_config()
    
    def load_config(self):
        """Load AI configuration from file"""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    self.config = json.load(f)
            except:
                self.config = {}
        else:
            self.config = {}
    
    def save_config(self):
        """Save AI configuration to file"""
        with open(self.config_file, "w") as f:
            json.dump(self.config, f)
    
    def is_configured(self):
        """Check if AI is configured"""
        return 'api_key' in self.config and 'endpoint' in self.config
    
    def configure_ai(self):
        """Configure AI settings through UI"""
        st.markdown("### Configure AI Integration")
        st.write("Please provide your AI API credentials")
        
        with st.form("ai_config_form"):
            api_key = st.text_input("API Key", type="password")
            endpoint = st.text_input("API Endpoint URL")
            sample_request = st.text_area(
                "Sample POST Request Format (JSON)",
                value='{\n  "model": "gpt-4",\n  "messages": [\n    {"role": "user", "content": "{{message}}"}\n  ]\n}',
                help="Use {{message}} as placeholder for the actual message content"
            )
            
            submitted = st.form_submit_button("Save Configuration")
            
            if submitted:
                if not api_key or not endpoint:
                    st.error("Please provide both API key and endpoint")
                    return False
                
                self.config = {
                    "api_key": api_key,
                    "endpoint": endpoint,
                    "request_template": sample_request
                }
                self.save_config()
                st.success("AI configuration saved successfully!")
                return True
        
        return False
    
    def get_ai_analysis(self, log_data):
        """Send log data to AI API for analysis and stream response"""
        if not self.is_configured():
            st.error("AI is not configured. Please configure AI first.")
            return None
        
        # Prepare message including log data
        message = (
            f"Kindly explain this log alert into details, and In 4 or 5 sentences, "
            f"tell me about the services and if there are past vulnerabilities and "
            f"possibly how to remediate them.\n\nLog data: {json.dumps(log_data)}"
        )
        
        try:
            # Get request template and insert message
            request_body = self.config['request_template'].replace('{{message}}', message)
            request_json = json.loads(request_body)
            
            headers = {
                "Authorization": f"Bearer {self.config['api_key']}",
                "Content-Type": "application/json"
            }
            
            # Make request to AI API
            response = requests.post(
                self.config['endpoint'],
                headers=headers,
                json=request_json,
                stream=True
            )
            
            if response.status_code != 200:
                st.error(f"API request failed with status code {response.status_code}")
                return f"Error: {response.text}"
            
            # Process streaming response
            full_response = ""
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    try:
                        # Handle different API response formats
                        chunk_text = chunk.decode('utf-8')
                        # Extract text from chunk (simplified - adjust based on actual API response format)
                        if '"content":' in chunk_text:
                            content_start = chunk_text.find('"content":') + 11
                            content_end = chunk_text.find('"', content_start)
                            if content_end > content_start:
                                chunk_text = chunk_text[content_start:content_end]
                        
                        full_response += chunk_text
                        yield chunk_text
                    except Exception as e:
                        st.error(f"Error processing response chunk: {str(e)}")
            
            return full_response
        except Exception as e:
            st.error(f"Error communicating with AI API: {str(e)}")
            return f"Error: {str(e)}"