import streamlit as st
# Notification handled by streamlit messages
def add_notification(message, notification_type="info"):
    """Simple notification fallback"""
    if notification_type == "success":
        st.success(message)
    elif notification_type == "error":
        st.error(message)
    elif notification_type == "warning":
        st.warning(message)
    else:
        st.info(message)
from datetime import datetime
import subprocess
import os
import re
import threading
import time
import json
import sqlite3
import uuid
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Check if Gemini API is available
GEMINI_API_KEY = os.getenv("GOOGLE_GEMINI_API_KEY")
GEMINI_AVAILABLE = False

# Try to import Gemini API if available
try:
    import google.generativeai as genai
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        GEMINI_AVAILABLE = True
except ImportError:
    # Gemini API not available
    pass

# Path to the nmap bash script - using absolute path
NMAP_SCRIPT_PATH = "/home/sawbvnny/projectsandpayloads/aisiem/siem-system/nmap.sh"

def extract_ports_from_text(scan_output):
    """Extract port information from Nmap text output
    
    Args:
        scan_output: Raw text output from Nmap scan
        
    Returns:
        List of dictionaries containing port information
    """
    ports_info = []
    try:
        # Handle None or empty scan output
        if not scan_output or scan_output is None:
            return ports_info
            
        # Look for port entries in the text output using regex
        # This pattern matches lines like: "80/tcp open  http    Apache httpd 2.4.41"
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?'
        port_matches = re.findall(port_pattern, str(scan_output))
        
        for match in port_matches:
            port, protocol, state, service, version_info = match
            
            # Parse product and version from version_info if available
            product = "Unknown"
            version = "Unknown"
            if version_info:
                # Try to extract product and version
                product_match = re.search(r'^([^\d]+)', version_info)
                if product_match:
                    product = product_match.group(1).strip()
                
                version_match = re.search(r'\d+\.\d+(?:\.\d+)?', version_info)
                if version_match:
                    version = version_match.group(0)
            
            if state.lower() == "open":
                port_info = {
                    'port': port,
                    'protocol': protocol,
                    'state': state,
                    'service': service,
                    'product': product,
                    'version': version
                }
                ports_info.append(port_info)
    except Exception as e:
        st.warning(f"Error extracting port information: {e}")
    
    return ports_info

def extract_target_ip_from_scan(scan_output):
    """Extract target IP from scan output"""
    if not scan_output:
        return "Unknown"
    
    try:
        # Look for IP patterns in the scan output (in order of preference)
        ip_patterns = [
            r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',  # Most reliable
            r'Starting Nmap.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
            r'Host: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
            r'Scanning ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
            r'Target: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
            r'Address: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
            r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+(?:is up|appears to be up)',
            r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*(?:\/|\s)',  # IP followed by space or slash
            r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'  # Any IP pattern as last resort
        ]
        
        scan_text = str(scan_output).strip()
        
        for pattern in ip_patterns:
            matches = re.findall(pattern, scan_text, re.IGNORECASE)
            if matches:
                # Return the first valid IP found
                for ip in matches:
                    # Basic validation - avoid IPs like 0.0.0.0, 127.0.0.1 in certain contexts
                    if ip and ip not in ['0.0.0.0', '255.255.255.255']:
                        return ip
                
        return "Unknown"
    except Exception:
        return "Unknown"

def calculate_severity_from_keywords(scan_output):
    """Calculate severity based on keywords found in scan output"""
    if not scan_output:
        return "Low", 0
    
    # Define severity keywords and their weights
    critical_keywords = [
        'critical', 'backdoor', 'rce', 'remote code execution', 'buffer overflow',
        'sql injection', 'command injection', 'privilege escalation', 'root access',
        'administrator access', 'authentication bypass', 'default credentials'
    ]
    
    high_keywords = [
        'high', 'vulnerable', 'exploit', 'security', 'weakness', 'flaw',
        'unauthorized', 'disclosure', 'bypass', 'elevation', 'compromise',
        'malicious', 'unsafe', 'unpatched', 'outdated'
    ]
    
    medium_keywords = [
        'medium', 'information disclosure', 'directory traversal', 'cross-site',
        'xss', 'csrf', 'weak', 'insecure', 'misconfiguration', 'exposure',
        'fingerprint', 'enumeration', 'brute force'
    ]
    
    low_keywords = [
        'low', 'informational', 'banner', 'version', 'service', 'open port',
        'accessible', 'detected', 'identified'
    ]
    
    scan_text = str(scan_output).lower()
    
    # Count keyword occurrences
    critical_count = sum(1 for keyword in critical_keywords if keyword in scan_text)
    high_count = sum(1 for keyword in high_keywords if keyword in scan_text)
    medium_count = sum(1 for keyword in medium_keywords if keyword in scan_text)
    low_count = sum(1 for keyword in low_keywords if keyword in scan_text)
    
    # Calculate total vulnerability score
    total_score = (critical_count * 10) + (high_count * 7) + (medium_count * 4) + (low_count * 1)
    
    # Determine severity based on score
    if critical_count > 0 or total_score >= 50:
        return "Critical", total_score
    elif high_count > 2 or total_score >= 30:
        return "High", total_score  
    elif medium_count > 3 or total_score >= 15:
        return "Medium", total_score
    else:
        return "Low", total_score

def analyze_scan_with_gemini(scan_output, target_ip):
    """Analyze scan results with Gemini to extract vulnerabilities and severity ratings
    
    Args:
        scan_output: Raw text output from the nmap scan
        target_ip: The IP address that was scanned
        
    Returns:
        Dictionary containing analysis results with vulnerabilities and severity ratings
    """
    # Check if Gemini is available
    if not GEMINI_AVAILABLE:
        # Create a basic analysis without Gemini
        return create_basic_analysis(scan_output, target_ip)
        
    # Extract the number of ports scanned from the scan output
    ports_scanned = 0
    ports_scan_match = re.search(r'Scanned (\d+) ports? in', scan_output)
    if ports_scan_match:
        ports_scanned = int(ports_scan_match.group(1))
    st.session_state.scan_port_count = ports_scanned  # Update session state with actual ports scanned
    
    try:
        if not GEMINI_API_KEY:
            return create_basic_analysis(scan_output, target_ip)
        
        # Extract ports from text data
        ports_info = extract_ports_from_text(scan_output)
        
        # Determine if this was a vulnerability scan or just a discovery scan
        is_vuln_scan = "VULNERABLE" in scan_output or "vulners" in scan_output or "script" in scan_output
        
        # Create a prompt for Gemini that focuses on detailed analysis without default messages
        prompt = f"""You are a cybersecurity expert analyzing the results of an Nmap scan.
        Provide a detailed analysis of ALL discovered ports, services, and vulnerabilities found in this scan.
        DO NOT include any generic or default messages - only analyze what is actually present in the scan results.
        
        Target IP: {target_ip}
        Scan Type: {'Vulnerability Scan' if is_vuln_scan else 'Discovery Scan'}
        
        Here are the open ports and services detected:
        """
        
        # Add port information to the prompt
        if ports_info:
            for port in ports_info:
                prompt += f"\nPort {port['port']}/{port['protocol']} - {port['service']} - {port['product']} {port['version']}"
        else:
            prompt += "\nNo open ports detected in the scan results."
        
        # Add raw scan data for additional context - include more data for better analysis
        prompt += f"\n\nRaw scan data:\n{scan_output[:8000]}"
        
        # Adjust prompt based on scan type
        if is_vuln_scan:
            prompt += "\n\nThis was a vulnerability scan with scripts enabled. Analyze ALL vulnerabilities found in the scan results."
            prompt += "\nBe specific about each vulnerability, its severity, and how it was detected in the scan."
            prompt += "\nDO NOT include generic vulnerabilities that aren't specifically indicated in the scan output."
        else:
            prompt += "\n\nThis was a discovery scan without vulnerability scripts. Analyze all open ports and services for potential security concerns."
            prompt += "\nBe specific about each port, service, and potential security implications based on what was actually detected."
        
        prompt += "\n\nBased on this information, provide a detailed security analysis in JSON format with the following structure:"
        prompt += """
        {
            "vulnerabilities": [
                {
                    "name": "Specific vulnerability name or security concern found in scan",
                    "description": "Detailed description of the vulnerability based on scan evidence",
                    "severity": "Critical/High/Medium/Low",
                    "affected_component": "Specific service/port affected",
                    "remediation": "Specific remediation steps for this vulnerability"
                }
            ],
            "summary": "Detailed summary of all findings from this specific scan",
            "risk_level": "Overall risk level (Critical, High, Medium, Low) based on actual findings",
            "recommendations": ["Specific security recommendations based on the actual scan results"]
        }
        
        IMPORTANT: Only include vulnerabilities and concerns that are actually indicated in the scan results.
        If no vulnerabilities are found, the vulnerabilities array should be empty, but still provide a summary of open ports and services.
        Your analysis should be specific to this scan and not include generic security advice unless relevant to the findings.
        """
        
        # Generate the analysis with Gemini
        model = genai.GenerativeModel('gemini-2.0-flash')
        response = model.generate_content(prompt)
        
        # Parse the response
        try:
            # Extract JSON from the response
            response_text = response.text
            json_match = re.search(r'```json\s*(.+?)\s*```', response_text, re.DOTALL)
            
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find JSON without code block markers
                json_match = re.search(r'(\{\s*"vulnerabilities":.+\})', response_text, re.DOTALL)
                if json_match:
                    json_str = json_match.group(1)
                else:
                    # Just use the whole response and hope it's valid JSON
                    json_str = response_text
            
            analysis = json.loads(json_str)
            
            # Ensure the analysis has the expected structure
            if 'vulnerabilities' not in analysis:
                analysis['vulnerabilities'] = []
            if 'summary' not in analysis:
                analysis['summary'] = "No summary provided by the AI."
            if 'risk_level' not in analysis:
                analysis['risk_level'] = "Low"
            if 'recommendations' not in analysis:
                analysis['recommendations'] = ["No specific recommendations provided by the AI."]
                
            return analysis
            
        except Exception as e:
            pass  # Error parsing response
            return create_basic_analysis(scan_output, target_ip)
            
    except Exception as e:
        pass  # Error analyzing scan
        return create_basic_analysis(scan_output, target_ip)
def create_basic_analysis(scan_output, target_ip):
    """Create a basic analysis of scan results without using Gemini
    
    Args:
        scan_output: Raw text output from the nmap scan
        target_ip: The IP address that was scanned
        
    Returns:
        Dictionary containing basic analysis results based only on actual scan findings
    """
    # Initialize empty analysis structure
    analysis = {
        "vulnerabilities": [],
        "summary": "",
        "risk_level": "Unknown",
        "recommendations": []
    }
    
    # Extract the number of ports scanned from the scan output
    ports_scan_match = re.search(r'Scanned (\d+) ports? in', scan_output)
    if ports_scan_match:
        ports_scanned = int(ports_scan_match.group(1))
        st.session_state.scan_port_count = ports_scanned  # Update session state with actual ports scanned
        analysis["ports_scanned"] = ports_scanned
    
    try:
        # Extract ports from text data
        ports_info = extract_ports_from_text(scan_output)
        
        # Check if the host appears to be down
        host_down = "host down" in scan_output.lower() or "0 hosts up" in scan_output.lower()
        
        if host_down:
            analysis["summary"] = f"Host {target_ip} appears to be down or unreachable based on scan results."
            return analysis
        
        # Check for explicit vulnerabilities in the scan output
        vulnerabilities_found = False
        if "VULNERABLE" in scan_output:
            vulnerabilities_found = True
            # Extract vulnerability information from the scan output
            vuln_lines = [line for line in scan_output.split('\n') if 'VULNERABLE' in line]
            
            for line in vuln_lines:
                # Extract the vulnerability details
                parts = line.split('|')
                if len(parts) >= 2:
                    vuln_name = parts[0].strip()
                    vuln_desc = parts[1].strip() if len(parts) > 1 else "No description available"
                    
                    # Create a vulnerability entry based on actual scan findings
                    vuln = {
                        "name": vuln_name,
                        "description": vuln_desc,
                        "severity": "High", # Default to High for explicitly identified vulnerabilities
                        "affected_component": "Identified in scan",
                        "remediation": "Address the specific vulnerability identified in the scan"
                    }
                    analysis["vulnerabilities"].append(vuln)
        
        # Define risk levels for specific ports
        high_risk_ports = {
            '21': {'name': 'FTP', 'severity': 'High'},
            '23': {'name': 'Telnet', 'severity': 'Critical'},  # Telnet is critical risk
            '445': {'name': 'SMB', 'severity': 'High'},
            '3389': {'name': 'RDP', 'severity': 'High'}
        }
        
        medium_risk_ports = {
            '22': 'SSH',
            '25': 'SMTP',
            '80': 'HTTP',
            '443': 'HTTPS',
            '8080': 'HTTP Alternate',
            '8443': 'HTTPS Alternate'
        }
        
        high_risk_count = 0
        medium_risk_count = 0
        port_details = []
        
        # Check for Telnet service specifically
        telnet_ports = [port for port in ports_info 
                       if (port.get('port') == '23' and port.get('protocol', 'tcp') == 'tcp') or 
                          port.get('service', '').lower() == 'telnet']
        
        # Add Telnet vulnerability if found
        for telnet_port in telnet_ports:
            port_number = telnet_port.get('port')
            service = telnet_port.get('service', 'telnet')
            protocol = telnet_port.get('protocol', 'tcp')
            product = telnet_port.get('product', '')
            version = telnet_port.get('version', '')
            
            telnet_vuln = {
                "name": "Telnet Service Detected",
                "description": f"Telnet service detected on port {port_number}/{protocol}. "
                               f"Telnet transmits all data, including credentials, in plaintext.",
                "severity": "Critical",
                "affected_component": f"Port {port_number}/{protocol}",
                "remediation": "1. Disable Telnet if not required\n"
                              "2. Use SSH instead of Telnet for secure remote access\n"
                              "3. If Telnet must be used, ensure it's restricted to internal networks only\n"
                              "4. Implement network segmentation to limit access to the Telnet service"
            }
            analysis["vulnerabilities"].append(telnet_vuln)
        
        # Analyze other open ports
        for port in ports_info:
            port_number = port.get('port')
            service = port.get('service', 'unknown').lower()
            protocol = port.get('protocol', 'tcp')
            product = port.get('product', '')
            version = port.get('version', '')
            
            port_details.append(f"{port_number}/{protocol} ({service}{' ' + product if product else ''}{' ' + version if version else ''})")
            
            # Skip if this is a Telnet port (already handled)
            if port_number == '23' and protocol == 'tcp' or 'telnet' in service:
                continue
                
            if port_number in high_risk_ports:
                high_risk_count += 1
                
                # Only add as vulnerability if not already identified in scan
                if not vulnerabilities_found:
                    vuln = {
                        "name": f"{high_risk_ports[port_number]['name']} service detected",
                        "description": f"Port {port_number} is running {service} {product} {version}",
                        "severity": high_risk_ports[port_number]['severity'],
                        "affected_component": f"Port {port_number}/{protocol}",
                        "remediation": f"Verify if {service} on port {port_number} is necessary and properly secured"
                    }
                    analysis["vulnerabilities"].append(vuln)
                
            elif port_number in medium_risk_ports:
                medium_risk_count += 1
        
        # Determine risk level based on actual findings
        if high_risk_count > 0 or vulnerabilities_found:
            risk_level = "High"
        elif medium_risk_count > 0:
            risk_level = "Medium"
        elif len(ports_info) > 0:
            risk_level = "Low"
        else:
            risk_level = "Unknown"
        
        # Update the analysis with the risk level
        analysis["risk_level"] = risk_level
        
        # Create a summary based only on the actual findings
        port_count = len(ports_info)
        if port_count == 0:
            analysis["summary"] = f"No open ports were detected on {target_ip} in this scan."
        else:
            analysis["summary"] = f"Scan of {target_ip} found {port_count} open ports: {', '.join(port_details[:5])}{' and others' if len(port_details) > 5 else ''}."
            if vulnerabilities_found:
                analysis["summary"] += f" {len(analysis['vulnerabilities'])} vulnerabilities were identified in the scan."
        
        # Add recommendations based on actual findings
        if len(analysis["vulnerabilities"]) > 0:
            analysis["recommendations"] = [f"Address the {len(analysis['vulnerabilities'])} identified vulnerabilities"]
        elif port_count > 0:
            analysis["recommendations"] = [f"Review the {port_count} open ports identified in the scan"]
        
        return analysis
        
    except Exception as e:
        pass  # Error creating basic analysis
        analysis["summary"] = f"Error analyzing scan results: {str(e)}"
        return analysis

class VulnerabilityScanner:
    def __init__(self):
        # Initialize scanner properties
        if "scan_type" not in st.session_state:
            st.session_state.scan_type = None
        
        # Initialize scan state variables
        if "scan_output" not in st.session_state:
            st.session_state.scan_output = ""
        if "scan_phase" not in st.session_state:
            st.session_state.scan_phase = "Ready"
        if "scan_progress" not in st.session_state:
            st.session_state.scan_progress = 0
        if "scan_error" not in st.session_state:
            st.session_state.scan_error = None
        if "scan_running" not in st.session_state:
            st.session_state.scan_running = False
        if "scan_found_ports" not in st.session_state:
            st.session_state.scan_found_ports = []
        if "scan_found_vulns" not in st.session_state:
            st.session_state.scan_found_vulns = []
        if "scan_ai_progress" not in st.session_state:
            st.session_state.scan_ai_progress = 0
        if "scan_start_timestamp" not in st.session_state:
            st.session_state.scan_start_timestamp = None
        if "scan_start_time" not in st.session_state:
            st.session_state.scan_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if "scan_result_file" not in st.session_state:
            st.session_state.scan_result_file = None
        if "scan_analysis" not in st.session_state:
            st.session_state.scan_analysis = None
        if "scan_target_ip" not in st.session_state:
            st.session_state.scan_target_ip = ""
        if "scan_port_count" not in st.session_state:
            st.session_state.scan_port_count = 1000
            
        # Check if nmap is installed
        self.nmap_available = self._check_nmap_installed()
        
    def _check_nmap_installed(self):
        """Check if nmap is available on the system"""
        try:
            result = subprocess.run(['which', 'nmap'], 
                                 capture_output=True, 
                                 text=True)
            return result.returncode == 0
        except Exception:
            return False
            
    def _run_scan(self, target_ip, scan_name=None, vuln_scan=False):
        """Run an Nmap scan using the bash script
        
        Args:
            target_ip: Target IP to scan
            scan_name: Optional name for the scan
            vuln_scan: Whether to include vulnerability scanning
            
        Returns:
            bool: Success or failure
        """
        try:
            # Update session state to indicate scan is running
            st.session_state.scan_running = True
            st.session_state.scan_phase = "Scanning"
            st.session_state.scan_progress = 10
            st.session_state.scan_output = "Starting nmap scan...\n"
            st.session_state.scan_target_ip = target_ip
            
            # Get port count from session state
            port_count = st.session_state.get("scan_port_count", 1000)
            
            # Generate output filename with absolute path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), f"nmap_scan_{timestamp}.txt")
            st.session_state.scan_result_file = output_file
            
            # Set the scan start time
            st.session_state.scan_start_timestamp = datetime.now()
            st.session_state.scan_start_time = st.session_state.scan_start_timestamp.strftime("%Y-%m-%d %H:%M:%S")
            
            # Debug information
            debug_info = f"Debug Info:\n"
            debug_info += f"NMAP_SCRIPT_PATH: {NMAP_SCRIPT_PATH}\n"
            debug_info += f"Script exists: {os.path.exists(NMAP_SCRIPT_PATH)}\n"
            debug_info += f"Script executable: {os.access(NMAP_SCRIPT_PATH, os.X_OK)}\n"
            debug_info += f"Output file: {output_file}\n"
            debug_info += f"Output directory exists: {os.path.exists(os.path.dirname(output_file))}\n"
            debug_info += f"Port count: {port_count}\n"
            
            st.session_state.scan_output += debug_info
            
            # Build command for the bash script
            cmd = [NMAP_SCRIPT_PATH]
            
            # Add vulnerability scanning if requested
            if vuln_scan:
                cmd.append("--vuln")
                
            # Add port count parameter
            cmd.append("--ports")
            cmd.append(str(port_count))
                
            # Add output file
            cmd.append("--output")
            cmd.append(output_file)
            
            # Add target IP as the last argument
            cmd.append(target_ip)
            
            # Store the command for display
            command_str = " ".join(cmd)
            st.session_state.scan_command = command_str
            st.session_state.scan_output += f"Command: {command_str}\n"
            
            # Run the scan directly using a simpler approach
            try:
                # Create a command string that will be executed directly with shell=True
                shell_cmd = f"bash {NMAP_SCRIPT_PATH} --ports {port_count} --output {output_file} {target_ip}"
                if vuln_scan:
                    shell_cmd = f"bash {NMAP_SCRIPT_PATH} --vuln --ports {port_count} --output {output_file} {target_ip}"
                
                st.session_state.scan_output += f"Executing shell command: {shell_cmd}\n"
                
                # Run the command with shell=True for more reliable execution
                process = subprocess.Popen(
                    shell_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Read output line by line
                output_lines = []
                for line in iter(process.stdout.readline, ''):
                    output_lines.append(line)
                    st.session_state.scan_output += line
                    
                    # Update progress based on output
                    if "Scanning" in line:
                        st.session_state.scan_progress = 30
                    elif "PORT" in line and "STATE" in line:
                        st.session_state.scan_progress = 50
                    elif "OS detection performed" in line:
                        st.session_state.scan_progress = 70
                    elif "Nmap done" in line:
                        st.session_state.scan_progress = 90
                
                # Wait for process to complete
                process.wait()
                
                # Check if the scan was successful
                if process.returncode == 0:
                    st.session_state.scan_phase = "Analyzing"
                    st.session_state.scan_progress = 95
                    
                    # Read the output file
                    try:
                        if os.path.exists(output_file):
                            with open(output_file, 'r') as f:
                                scan_output = f.read()
                                
                            # Check if AI mode is enabled before analyzing
                            if st.session_state.get("ai_mode", False):
                                # Analyze the scan results with AI
                                analysis = analyze_scan_with_gemini(scan_output, target_ip)
                                
                                # Store the analysis in session state
                                st.session_state.scan_analysis = analysis
                                
                                # Extract vulnerabilities from AI analysis
                                st.session_state.scan_found_vulns = analysis.get("vulnerabilities", [])
                            else:
                                # No AI analysis - create basic analysis structure
                                analysis = {
                                    "vulnerabilities": [],
                                    "summary": "AI analysis disabled - raw scan results available",
                                    "severity": "info"
                                }
                                st.session_state.scan_analysis = analysis
                                st.session_state.scan_found_vulns = []
                            
                            # Extract found ports (always extract ports regardless of AI mode)
                            st.session_state.scan_found_ports = extract_ports_from_text(scan_output)
                            
                            # Automatically save scan results to database
                            try:
                                success, scan_id = self._save_scan_to_db(target_ip, scan_output, analysis)
                                if success:
                                    st.session_state.scan_saved = True
                                    st.session_state.scan_id = scan_id
                                else:
                                    st.session_state.scan_save_error = f"Failed to save scan: {scan_id}"
                            except Exception as save_error:
                                st.session_state.scan_save_error = f"Error saving scan: {str(save_error)}"
                            
                            # Update scan phase
                            st.session_state.scan_phase = "Complete"
                            st.session_state.scan_progress = 100
                        else:
                            st.session_state.scan_error = f"Output file not found: {output_file}"
                            st.session_state.scan_phase = "Error"
                        
                    except Exception as analysis_error:
                        st.session_state.scan_error = f"Error analyzing scan results: {str(analysis_error)}"
                        st.session_state.scan_phase = "Error"
                else:
                    st.session_state.scan_error = f"Scan failed with return code {process.returncode}"
                    st.session_state.scan_phase = "Error"
            except Exception as process_error:
                st.session_state.scan_error = f"Error running scan process: {str(process_error)}"
                st.session_state.scan_phase = "Error"
            
            st.session_state.scan_running = False
            return True
            
        except Exception as e:
            import traceback
            error_traceback = traceback.format_exc()
            st.session_state.scan_error = f"Error in _run_scan: {str(e)}\n\nTraceback: {error_traceback}"
            st.session_state.scan_phase = "Error"
            st.session_state.scan_running = False
            return False
            
    # The _run_scan_thread method has been removed since we now run the scan directly in _run_scan
    def _save_scan_to_db(self, target_ip, scan_output, analysis):
        """Save scan results to the database"""
        try:
            import sqlite3
            import json
            import uuid
            
            # Create a database connection
            db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'siem.db')
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Check if the table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerability_scans'")
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                # Create the tables with all required columns
                cursor.execute("""
                CREATE TABLE vulnerability_scans (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    target_ip TEXT,
                    scan_output TEXT,
                    analysis_json TEXT,
                    scan_type TEXT,
                    ports_scanned INTEGER DEFAULT 0
                )
                """)
                
                # Create table for port information
                cursor.execute("""
                CREATE TABLE port_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    port_number INTEGER,
                    protocol TEXT,
                    state TEXT,
                    service TEXT,
                    product TEXT,
                    version TEXT,
                    FOREIGN KEY (scan_id) REFERENCES vulnerability_scans(id) ON DELETE CASCADE
                )
                """)
            else:
                # Check if scan_type column exists
                cursor.execute("PRAGMA table_info(vulnerability_scans)")
                columns = [column[1] for column in cursor.fetchall()]
                
                if 'scan_type' not in columns:
                    # Add scan_type column if it doesn't exist
                    try:
                        cursor.execute("ALTER TABLE vulnerability_scans ADD COLUMN scan_type TEXT")
                        conn.commit()
                    except sqlite3.OperationalError as e:
                        # If we can't add the column, we'll insert without it
                        pass  # Could not add scan_type column
            
            # Create a unique ID for this scan
            scan_id = str(uuid.uuid4())
            
            # Determine if this was a vulnerability scan or discovery scan
            is_vuln_scan = "VULNERABLE" in scan_output or "vulners" in scan_output or "script" in scan_output
            scan_type = "vulnerability" if is_vuln_scan else "discovery"
            
            # Check for additional columns after our schema updates
            cursor.execute("PRAGMA table_info(vulnerability_scans)")
            columns = {column[1]: column for column in cursor.fetchall()}
            
            # Get the number of ports scanned from the session state
            ports_scanned = st.session_state.get('scan_port_count', 0)
            
            # Prepare the base insert statement and values
            columns_list = ["id", "timestamp", "target_ip", "scan_output", "analysis_json", "ports_scanned"]
            placeholders = [":" + col for col in columns_list]
            values = {
                "id": scan_id,
                "ports_scanned": ports_scanned,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_ip": target_ip,
                "scan_output": scan_output,
                "analysis_json": json.dumps(analysis)
            }
            
            # Add scan_type if column exists
            if 'scan_type' in columns:
                columns_list.append("scan_type")
                placeholders.append(":scan_type")
                values["scan_type"] = scan_type
                
            # Add ports_scanned if column exists
            ports_scanned = st.session_state.get("scan_port_count", 1000)  # Default to 1000 if not set
            if 'ports_scanned' in columns:
                columns_list.append("ports_scanned")
                placeholders.append(":ports_scanned")
                values["ports_scanned"] = ports_scanned
            
            # Build and execute the insert query
            query = f"""
                INSERT INTO vulnerability_scans 
                ({', '.join(columns_list)})
                VALUES ({', '.join(placeholders)})
            """
            cursor.execute(query, values)
            
            # Save port information if available
            if 'scan_found_ports' in st.session_state and st.session_state.scan_found_ports:
                for port_info in st.session_state.scan_found_ports:
                    try:
                        # Extract port number and protocol (e.g., '80/tcp' -> 80, 'tcp')
                        port_parts = port_info.get('port', '').split('/')
                        if len(port_parts) == 2:
                            port_number = int(port_parts[0])
                            protocol = port_parts[1].lower()
                            
                            cursor.execute("""
                                INSERT INTO port_scan_results 
                                (scan_id, port_number, protocol, state, service, product, version)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (
                                scan_id,
                                port_number,
                                protocol,
                                port_info.get('state', ''),
                                port_info.get('service', ''),
                                port_info.get('product', ''),
                                port_info.get('version', '')
                            ))
                    except (ValueError, AttributeError) as e:
                        pass  # Error saving port info
                        continue
            
            conn.commit()
            conn.close()
            
            return True, scan_id
            
        except Exception as e:
            pass  # Error saving scan to database
            return False, str(e)
    
    def run_scan(self):
        """Run a vulnerability scan based on user input"""
        # Check if nmap is available
        if not self.nmap_available:
            st.error("Nmap is not installed or not available in the system path. Please install nmap to use this feature.")
            return
        
        # Create a form for the scan parameters
        with st.form("vulnerability_scan_form"):
            # Target IP address
            target_ip = st.text_input("Target IP Address", 
                                   help="Enter the IP address to scan")
            
            # Port selection
            port_count_options = {
                "100 ports": 100,
                "500 ports": 500,
                "1000 ports (default)": 1000,
                "2000 ports": 2000,
                "All ports (slower)": 65535
            }
            port_count_selection = st.selectbox(
                "Number of ports to scan",
                options=list(port_count_options.keys()),
                index=2,  # Default to 1000 ports
                help="Select how many ports to scan. More ports will take longer."
            )
            port_count = port_count_options[port_count_selection]
            
            # Vulnerability scanning option
            vuln_scan = st.checkbox("Include vulnerability scanning", 
                                 value=True,
                                 help="Run vulnerability scripts to detect potential security issues")
            
            # Scan name (optional)
            scan_name = st.text_input("Scan Name (optional)", 
                                   help="Enter a name for this scan")
            
            # Submit button
            submitted = st.form_submit_button("Start Scan")
            
            if submitted:
                if not target_ip or target_ip.strip() == "":
                    st.error("Please enter a target IP address")
                    return
                
                # Store the target IP in session state to start the scan immediately
                st.session_state.scan_target_ip = target_ip
                st.session_state.scan_vuln_option = vuln_scan
                st.session_state.scan_name = scan_name
                st.session_state.scan_port_count = port_count
                st.session_state.start_scan_immediately = True
                st.session_state.scan_type = "vulnerability"
                st.rerun()
    
    def render(self):
        """Main render function for the vulnerability scanner"""
        st.title("Vulnerability Scanner")
        
        # Create a back button that goes to vulnerability overview instead of dashboard
        if st.button("◀️ Back to Overview"):
            st.session_state.view = "vuln_overview"
            st.rerun()
        
        # Check if we should start a scan immediately
        if st.session_state.get("start_scan_immediately", False):
            # Get scan parameters from session state
            target_ip = st.session_state.get("scan_target_ip", "")
            vuln_scan = st.session_state.get("scan_vuln_option", True)
            scan_name = st.session_state.get("scan_name", "")
            
            # Clear the flag
            st.session_state.start_scan_immediately = False
            
            # Run the scan immediately
            if target_ip:
                success = self._run_scan(target_ip, scan_name, vuln_scan)
                if not success:
                    st.error("Failed to start the scan. Please try again.")
                    # Reset to show the form
                    st.session_state.scan_phase = "Ready"
        
        # Show scanner intro and options if no scan is running
        if not st.session_state.scan_running and st.session_state.scan_phase in ["Ready", "Error"]:
            self.render_scanner_intro()
            self.run_scan()
        else:
            # Show scan progress or results
            self._render_scan_progress()
    
    def render_scanner_intro(self):
        """Render the scanner introduction"""
        st.markdown("""
        ## Network Vulnerability Scanner
        
        This tool uses Nmap to scan for open ports and potential vulnerabilities on network devices.
        
        **Features:**
        - Detect open ports and running services
        - Identify potential security vulnerabilities
        - Get AI-powered analysis and recommendations
        
        **Note:** Only scan systems you have permission to test.
        """)
    
    def _render_scan_progress(self):
        """Render the scan progress interface"""
        # Create columns for the progress bar and status
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.progress(st.session_state.scan_progress / 100)
        
        with col2:
            # Add spinning animation for active scans
            if st.session_state.scan_phase in ["Scanning", "Analyzing"]:
                spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
                import time
                spinner_idx = int(time.time() * 5) % len(spinner_chars)
                st.markdown(f"<h3 style='color: #1E90FF;'>{spinner_chars[spinner_idx]} {st.session_state.scan_phase}...</h3>", unsafe_allow_html=True)
            else:
                st.write(f"Status: {st.session_state.scan_phase}")
        
        # Show scan details
        st.markdown(f"**Target:** {st.session_state.scan_target_ip}")
        st.markdown(f"**Started:** {st.session_state.scan_start_time}")
        
        # If there's an error, show it
        if st.session_state.scan_error:
            st.error(f"Error: {st.session_state.scan_error}")
            
            if st.button("Start New Scan"):
                st.session_state.scan_phase = "Ready"
                st.session_state.scan_error = None
                st.session_state.scan_output = ""
                st.session_state.scan_progress = 0
                st.rerun()
        
        # If scan is complete, show results
        elif st.session_state.scan_phase == "Complete":
            # Show scan results in tabs
            tab1, tab2, tab3 = st.tabs(["Scan Output", "Analysis", "Actions"])
            
            with tab1:
                # Show the scan output in a text area
                st.text_area("Raw Scan Output", st.session_state.scan_output, height=400)
            
            with tab2:
                # Show the analysis results
                if st.session_state.scan_analysis:
                    analysis = st.session_state.scan_analysis
                    
                    # Display risk level with appropriate color
                    risk_level = analysis.get("risk_level", "Unknown")
                    risk_color = {
                        "Critical": "#ff0000",
                        "High": "#ff3b3b",
                        "Medium": "#ff8c00",
                        "Low": "#ffe900"
                    }.get(risk_level, "#0095ff")
                    
                    st.markdown(f"### Risk Level: <span style='color: {risk_color};'>{risk_level}</span>", unsafe_allow_html=True)
                    
                    # Display summary
                    st.markdown("### Summary")
                    st.markdown(analysis.get("summary", "No summary available"))
                    
                    # Display vulnerabilities
                    st.markdown("### Vulnerabilities")
                    vulns = analysis.get("vulnerabilities", [])
                    if vulns:
                        for i, vuln in enumerate(vulns):
                            severity = vuln.get("severity", "Unknown")
                            severity_color = {
                                "Critical": "#ff0000",
                                "High": "#ff3b3b",
                                "Medium": "#ff8c00",
                                "Low": "#ffe900"
                            }.get(severity, "#0095ff")
                            
                            st.markdown(f"""
                            <div style="padding: 10px; border-left: 4px solid {severity_color}; margin-bottom: 10px; background: rgba(0,0,0,0.05);">
                                <div style="font-weight: bold;">{vuln.get("name", "Unknown vulnerability")}</div>
                                <div>Severity: <span style="color: {severity_color};">{severity}</span></div>
                                <div>Affected: {vuln.get("affected_component", "Unknown")}</div>
                                <div>Description: {vuln.get("description", "No description available")}</div>
                                <div>Remediation: {vuln.get("remediation", "No remediation available")}</div>
                            </div>
                            """, unsafe_allow_html=True)
                    else:
                        st.info("No specific vulnerabilities were identified")
                    
            
            # Display recommendations
            st.markdown("### Recommendations")
            recommendations = analysis.get("recommendations", [])
            if recommendations:
                for rec in recommendations:
                    st.markdown(f"- {rec}")
            else:
                st.info("No specific recommendations available")
                
            # Add action buttons
            st.markdown("### Actions")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("Save to Database", key="save_to_db", use_container_width=True):
                    # Save the scan results to the database
                    success, scan_id = self._save_scan_to_db(
                        st.session_state.scan_target_ip,
                        st.session_state.scan_output,
                        st.session_state.scan_analysis
                    )
                    
                    if success:
                        add_notification(
                            f"Vulnerability scan for {st.session_state.scan_target_ip} saved to database", 
                            "success"
                        )
                        # Redirect to overview page
                        st.session_state.view = "vuln_overview"
                        st.rerun()
                    else:
                        st.error(f"Error saving scan: {scan_id}")
            
            with col2:
                if st.button("Close Analysis", key="close_analysis", use_container_width=True):
                    # Reset the scan state
                    st.session_state.scan_phase = "Ready"
                    st.session_state.scan_error = None
                    st.session_state.scan_output = ""
                    st.session_state.scan_progress = 0
                    st.session_state.scan_analysis = None
                    st.rerun()
        
        # If scan is running or analyzing, show the output
        else:
            # Show the scan output in a text area with auto-scroll
            st.text_area("Live Scan Output", st.session_state.scan_output, height=400)
            
            # Add a cancel button
            if st.button("Cancel Scan"):
                st.session_state.scan_phase = "Ready"
                st.session_state.scan_error = None
                st.session_state.scan_output = ""
                st.session_state.scan_progress = 0
                st.rerun()

# Export all possible function names that app.py might be looking for
def render_scanner():
    """Render the vulnerability scanner page"""
    scanner = VulnerabilityScanner()
    scanner.render()

def render_vuln_scanner():
    """Alternative name that might be used in app.py"""
    render_scanner()

def render():
    """Generic render function"""
    render_scanner()

if __name__ == "__main__":
    render_scanner()
