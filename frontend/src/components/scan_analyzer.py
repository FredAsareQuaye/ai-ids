import streamlit as st
import json
import requests  # type: ignore
import time
import os
import sqlite3
from datetime import datetime
import pandas as pd
from utils.gemini_api import analyze_scan_with_gemini

class ScanAnalyzer:
    """Component for analyzing scan results with Gemini AI"""
    
    def __init__(self):
        """Initialize the scan analyzer"""
        # Initialize session state variables if they don't exist
        if "analyzer_scan_id" not in st.session_state:
            st.session_state.analyzer_scan_id = None
        if "analyzer_is_loading" not in st.session_state:
            st.session_state.analyzer_is_loading = False
        if "analyzer_error" not in st.session_state:
            st.session_state.analyzer_error = None
        if "analyzer_response" not in st.session_state:
            st.session_state.analyzer_response = None
            
    def _get_scan_by_id(self, scan_id):
        """Get a scan from the database by ID"""
        try:
            # Connect to the database
            db_path = os.path.join(os.path.expanduser("~/.siem_data"), "siem.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get the scan by ID
            cursor.execute("SELECT results FROM vulnerability_scans WHERE id = ?", (scan_id,))
            result = cursor.fetchone()
            
            # Close the connection
            conn.close()
            
            if result:
                # Parse the JSON results
                scan_data = json.loads(result[0])
                return scan_data
            else:
                return None
        except Exception as e:
            st.error(f"Error retrieving scan: {str(e)}")
            return None
    
    def _update_scan_with_analysis(self, scan_id, gemini_insights):
        """Update a scan in the database with Gemini AI analysis"""
        try:
            # Connect to the database
            db_path = os.path.join(os.path.expanduser("~/.siem_data"), "siem.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # First get the current scan data
            cursor.execute("SELECT results FROM vulnerability_scans WHERE id = ?", (scan_id,))
            result = cursor.fetchone()
            
            if not result:
                st.error(f"Scan with ID {scan_id} not found")
                return False
                
            # Parse the JSON results
            scan_data = json.loads(result[0])
            
            # Update the scan data with Gemini insights
            scan_data["gemini_insights"] = gemini_insights
            scan_data["ai_analyzed"] = True
            scan_data["ai_analysis_time"] = datetime.now().isoformat()
            
            # Update summary with AI-generated summary
            if "summary" not in scan_data:
                scan_data["summary"] = {}
                
            if "summary" in gemini_insights:
                scan_data["summary"]["ai_summary"] = gemini_insights["summary"]
            
            # Add risk level if available
            if "risk_level" in gemini_insights:
                scan_data["summary"]["risk_level"] = gemini_insights["risk_level"]
                
            # Add recommendations if available
            if "recommendations" in gemini_insights:
                scan_data["summary"]["recommendations"] = gemini_insights["recommendations"]
            
            # Check if Gemini found any vulnerabilities
            has_vulnerabilities = False
            if "vulnerabilities" in gemini_insights and gemini_insights["vulnerabilities"]:
                # If Gemini found vulnerabilities, update them
                scan_data["vulnerabilities"] = gemini_insights["vulnerabilities"]
                has_vulnerabilities = True
                
                # Count vulnerabilities by severity
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = 0
                
                for vuln in scan_data["vulnerabilities"]:
                    severity = vuln.get("severity", "").lower()
                    if "critical" in severity:
                        critical_count += 1
                    elif "high" in severity:
                        high_count += 1
                    elif "medium" in severity:
                        medium_count += 1
                    elif "low" in severity:
                        low_count += 1
                
                scan_data["summary"]["critical_vulns"] = critical_count
                scan_data["summary"]["high_vulns"] = high_count
                scan_data["summary"]["medium_vulns"] = medium_count
                scan_data["summary"]["low_vulns"] = low_count
                
                # Update total vulnerabilities count
                if "total_vulnerabilities" in gemini_insights:
                    scan_data["summary"]["total_vulnerabilities"] = gemini_insights["total_vulnerabilities"]
                else:
                    scan_data["summary"]["total_vulnerabilities"] = len(scan_data["vulnerabilities"])
            
            # Determine if this is a vulnerability scan based on whether vulnerabilities were found
            if has_vulnerabilities:
                scan_data["scan_category"] = "Vulnerability"
                scan_data["vulnerability_scan"] = True
            
            # Update the scan in the database
            cursor.execute("""
            UPDATE vulnerability_scans SET 
                results = ?,
                ai_analyzed = 1,
                ai_summary = ?,
                vulnerability_scan = ?,
                risk_level = ?,
                raw_response = ?
            WHERE id = ?
            """, (
                json.dumps(scan_data),
                scan_data["summary"].get("ai_summary", ""),
                1 if scan_data.get("vulnerability_scan", False) else 0,
                scan_data["summary"].get("risk_level", ""),
                gemini_insights.get("raw_response", ""),
                scan_id
            ))
            
            # Commit the changes
            conn.commit()
            
            # Close the connection
            conn.close()
            
            return True
        except Exception as e:
            st.error(f"Error updating scan with analysis: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return False
    
    def analyze_scan(self, scan_id):
        """Analyze a scan with Gemini AI"""
        # Get the scan data
        scan_data = self._get_scan_by_id(scan_id)
        
        if not scan_data:
            st.error(f"Scan with ID {scan_id} not found")
            return
        
        # Get the scan output
        scan_output = scan_data.get("raw_output", "")
        
        if not scan_output:
            st.error("No scan output found to analyze")
            return
        
        # Set loading state
        st.session_state.analyzer_is_loading = True
        st.session_state.analyzer_error = None
        st.session_state.analyzer_response = None
        st.session_state.analyzer_scan_id = scan_id
        
        # Display loading animation
        st.markdown("""
        <style>
        .loading-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 2rem 0;
        }
        .loading-text {
            font-size: 1.2rem;
            margin-bottom: 1rem;
            color: #4285F4;
        }
        .loading-animation {
            display: flex;
            justify-content: center;
        }
        .loader {
            border: 0.5rem solid #f3f3f3;
            border-radius: 50%;
            border-top: 0.5rem solid #4285F4;
            width: 3rem;
            height: 3rem;
            animation: spin 2s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        </style>
        <div class="loading-container">
            <div class="loading-text">Analyzing scan with Gemini AI...</div>
            <div class="loading-animation">
                <div class="loader"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Make the API call in the background
        try:
            # Get API key from environment variable
            api_key = os.getenv("GOOGLE_GEMINI_API_KEY")
            
            if not api_key:
                st.session_state.analyzer_error = "Google Gemini API key not found in .env file"
                st.session_state.analyzer_is_loading = False
                return
            
            # Create the message for the AI - exactly like in gemini_analysis.py
            prompt = (
                "Analyze this nmap scan output and identify vulnerabilities, open ports, and security risks. "
                "Provide detailed information about each vulnerability including severity, affected port, and remediation steps. "
                "For any CVEs detected, include the CVE ID and a brief description. "
                "\n\n"
                f"Scan Output: {scan_output}\n\n"
                "Provide your analysis in JSON format with the following structure:\n"
                "{"
                "\n  \"total_vulnerabilities\": number,"
                "\n  \"vulnerabilities\": ["
                "\n    {"
                "\n      \"name\": \"vulnerability name or CVE ID\","
                "\n      \"severity\": \"Critical/High/Medium/Low\","
                "\n      \"port\": \"port number\","
                "\n      \"service\": \"service name\","
                "\n      \"description\": \"brief description of the vulnerability\""
                "\n    }"
                "\n  ],"
                "\n  \"open_ports\": ["
                "\n    {"
                "\n      \"port\": \"port number\","
                "\n      \"service\": \"service name\","
                "\n      \"details\": \"additional details\""
                "\n    }"
                "\n  ],"
                "\n  \"summary\": \"comprehensive summary of findings\","
                "\n  \"risk_level\": \"Critical/High/Medium/Low\","
                "\n  \"recommendations\": ["
                "\n    \"specific recommendation 1\","
                "\n    \"specific recommendation 2\""
                "\n  ]"
                "\n}"
            )
            
            # Make request to Gemini API - exactly like in gemini_analysis.py
            endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
            
            request_data = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }]
            }
            
            response = requests.post(
                endpoint,
                json=request_data,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            if response.status_code != 200:
                error_text = f"API error: {response.status_code} - {response.text}"
                st.session_state.analyzer_error = error_text
                st.session_state.analyzer_response = None
            else:
                data = response.json()
                response_text = data.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No response received from Gemini AI.')
                
                # Try to extract JSON from the response
                try:
                    # Try to find JSON in the response
                    json_start = response_text.find("{")
                    json_end = response_text.rfind("}") + 1
                    
                    if json_start >= 0 and json_end > json_start:
                        json_str = response_text[json_start:json_end]
                        gemini_insights = json.loads(json_str)
                    else:
                        # If no JSON found, try to parse the whole response
                        gemini_insights = json.loads(response_text)
                    
                    # Add the raw response to the insights
                    gemini_insights["raw_response"] = response_text
                    
                    # Update the scan with the analysis
                    success = self._update_scan_with_analysis(scan_id, gemini_insights)
                    
                    if success:
                        st.session_state.analyzer_response = gemini_insights
                    else:
                        st.session_state.analyzer_error = "Failed to update scan with analysis"
                except json.JSONDecodeError:
                    st.session_state.analyzer_error = "Failed to parse Gemini response as JSON"
                    st.session_state.analyzer_response = None
                
        except Exception as e:
            st.session_state.analyzer_error = str(e)
            st.session_state.analyzer_response = None
        
        # Mark as done loading
        st.session_state.analyzer_is_loading = False
        st.rerun()
    
    def render(self):
        """Render the scan analyzer component"""
        st.header("🧠 Gemini AI Scan Analysis")
        
        # Check if we have a scan ID in session state from the vulnerability scanner
        if "analyzer_scan_id" in st.session_state and st.session_state.analyzer_scan_id is not None:
            scan_id = st.session_state.analyzer_scan_id
            
            # Check if we're already analyzing this scan
            if not st.session_state.analyzer_is_loading and st.session_state.analyzer_response is None and st.session_state.analyzer_error is None:
                # Start analyzing the scan automatically
                self.analyze_scan(scan_id)
                return  # Return early while analysis is in progress
        else:
            # If no scan ID in session state, show the scan selection interface
            try:
                db_path = os.path.join(os.path.expanduser("~/.siem_data"), "siem.db")
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Get all scans
                cursor.execute("SELECT id, scan_name, target, scan_date, ai_analyzed FROM vulnerability_scans ORDER BY id DESC")
                scans = cursor.fetchall()
                
                # Close the connection
                conn.close()
                
                if not scans:
                    st.info("No scans found. Run a scan first to analyze it.")
                    return
                
                # Create a dataframe for easier display
                scan_data = []
                for scan in scans:
                    scan_id, scan_name, target, scan_date, ai_analyzed = scan
                    scan_data.append({
                        "ID": scan_id,
                        "Name": scan_name,
                        "Target": target,
                        "Date": scan_date.split("T")[0] if "T" in scan_date else scan_date,
                        "Analyzed": "✅" if ai_analyzed else "❌"
                    })
                
                df = pd.DataFrame(scan_data)
                
                # Display scans as a table
                st.write("Select a scan to analyze:")
                st.dataframe(df, hide_index=True)
                
                # Select a scan to analyze
                scan_options = [f"ID {scan[0]}: {scan[1]} ({scan[2]})" for scan in scans]
                selected_scan = st.selectbox("Select a scan:", scan_options)
                
                if selected_scan:
                    # Extract the scan ID from the selected option
                    scan_id = int(selected_scan.split(":")[0].replace("ID ", ""))
                    
                    # Check if the scan has already been analyzed
                    is_analyzed = next((scan[4] for scan in scans if scan[0] == scan_id), False)
                    
                    if is_analyzed:
                        st.info("This scan has already been analyzed. You can view the results in the Vulnerability Overview.")
                        if st.button("Analyze Again"):
                            self.analyze_scan(scan_id)
                    else:
                        if st.button("Analyze with Gemini AI"):
                            self.analyze_scan(scan_id)
                
            except Exception as e:
                st.error(f"Error loading scans: {str(e)}")
                return
        
        # Show loading state or results
        if st.session_state.analyzer_is_loading:
            st.info("Analyzing scan with Gemini AI... Please wait.")
        elif st.session_state.analyzer_error:
            st.error(f"Error: {st.session_state.analyzer_error}")
            if st.button("Try Again"):
                if st.session_state.analyzer_scan_id:
                    self.analyze_scan(st.session_state.analyzer_scan_id)
        elif st.session_state.analyzer_response:
            st.success("Analysis completed successfully!")
            
            # Display the analysis results
            insights = st.session_state.analyzer_response
            
            # Display summary
            if "summary" in insights:
                st.subheader("Summary")
                st.write(insights["summary"])
            
            # Display risk level
            if "risk_level" in insights:
                risk_level = insights["risk_level"]
                risk_color = {
                    "Critical": "red",
                    "High": "orange",
                    "Medium": "yellow",
                    "Low": "green"
                }.get(risk_level, "blue")
                
                st.subheader("Risk Level")
                st.markdown(f"<span style='color:{risk_color};font-weight:bold;'>{risk_level}</span>", unsafe_allow_html=True)
            
            # Display recommendations
            if "recommendations" in insights and insights["recommendations"]:
                st.subheader("Recommendations")
                for i, rec in enumerate(insights["recommendations"], 1):
                    st.write(f"{i}. {rec}")
            
            # Display vulnerabilities
            if "vulnerabilities" in insights and insights["vulnerabilities"]:
                st.subheader("Vulnerabilities")
                
                # Create a dataframe of vulnerabilities
                vuln_data = [{
                    "Name": v.get("name", "Unknown"),
                    "Severity": v.get("severity", "Unknown"),
                    "Port": v.get("port", "N/A"),
                    "Service": v.get("service", "N/A"),
                    "Description": v.get("description", "")
                } for v in insights["vulnerabilities"]]
                
                df_vulns = pd.DataFrame(vuln_data)
                
                # Define severity order for sorting
                severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
                if "Severity" in df_vulns.columns:
                    df_vulns["SeverityRank"] = df_vulns["Severity"].map(lambda x: severity_order.get(x, 5))
                    df_vulns = df_vulns.sort_values("SeverityRank").drop("SeverityRank", axis=1)
                
                st.dataframe(df_vulns, hide_index=True)
            
            # Display open ports
            if "open_ports" in insights and insights["open_ports"]:
                st.subheader("Open Ports")
                
                # Create a dataframe of open ports
                port_data = [{
                    "Port": p.get("port", "Unknown"),
                    "Service": p.get("service", "Unknown"),
                    "Details": p.get("details", "")
                } for p in insights["open_ports"]]
                
                df_ports = pd.DataFrame(port_data)
                st.dataframe(df_ports, hide_index=True)
            
            # Add buttons for saving analysis and viewing in vulnerability overview
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("💾 Save Analysis", use_container_width=True):
                    # Save the analysis to the database
                    success = self._update_scan_with_analysis(st.session_state.analyzer_scan_id, st.session_state.analyzer_response)
                    if success:
                        st.success("Analysis saved successfully!")
                        # Clear the analyzer scan ID so we don't automatically analyze again
                        st.session_state.analyzer_scan_id = None
                        # Redirect to vulnerability overview
                        st.session_state.view = "vuln_overview"
                        st.rerun()
                    else:
                        st.error("Failed to save analysis.")
            
            with col2:
                if st.button("🔍 View in Vulnerability Overview", use_container_width=True):
                    # Clear the analyzer scan ID so we don't automatically analyze again
                    st.session_state.analyzer_scan_id = None
                    st.session_state.view = "vuln_overview"
                    st.rerun()
