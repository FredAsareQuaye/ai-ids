import streamlit as st
import pandas as pd
import json
import os
import sqlite3
from datetime import datetime
import traceback
from fpdf import FPDF
import sys
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path to import components
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

# OpenRouter AI setup
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
GEMINI_AVAILABLE = bool(OPENROUTER_API_KEY)  # reuse flag name so rest of code unchanged

class ScanResultsPage:
    def __init__(self):
        # Path to SIEM database - updated to use the frontend data directory
        self.db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')
        
        # Reports directory
        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def load_vulnerability_scans(self):
        """Load vulnerability scans from database"""
        try:
            if not os.path.exists(self.db_path):
                return [], []
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Load sniper scans
            sniper_scans = []
            try:
                cursor.execute('''
                    SELECT scan_id, scan_type, target, status, timestamp, execution_time, 
                           ports_found, command, output, error
                    FROM vulnerability_scans 
                    ORDER BY created_at DESC
                ''')
                
                for row in cursor.fetchall():
                    scan = {
                        "scan_id": row[0],
                        "type": "Sniper Scan",
                        "scan_type": row[1],
                        "target": row[2],
                        "status": row[3],
                        "timestamp": row[4],
                        "execution_time": row[5],
                        "ports_found": row[6],
                        "command": row[7],
                        "output": row[8],
                        "error": row[9]
                    }
                    sniper_scans.append(scan)
            except sqlite3.OperationalError:
                pass  # Table doesn't exist yet
            
            # Load network scans
            network_scans = []
            try:
                cursor.execute('''
                    SELECT scan_id, scan_type, targets_summary, target_count, status, 
                           timestamp, execution_time, hosts_up, total_ports, command, output, error
                    FROM network_scans 
                    ORDER BY created_at DESC
                ''')
                
                for row in cursor.fetchall():
                    scan = {
                        "scan_id": row[0],
                        "type": "Network Scan",
                        "scan_type": row[1],
                        "target": row[2],
                        "target_count": row[3],
                        "status": row[4],
                        "timestamp": row[5],
                        "execution_time": row[6],
                        "hosts_up": row[7],
                        "ports_found": row[8],
                        "command": row[9],
                        "output": row[10],
                        "error": row[11]
                    }
                    network_scans.append(scan)
            except sqlite3.OperationalError:
                pass  # Table doesn't exist yet
            
            conn.close()
            return sniper_scans, network_scans
            
        except Exception as e:
            st.error(f"Error loading vulnerability scans: {str(e)}")
            return [], []

    def render_vulnerability_scans(self):
        """Render vulnerability scans section"""
        page_header("Scan Results", "Browse and analyse completed vulnerability scan reports")
        
        sniper_scans, network_scans = self.load_vulnerability_scans()
        
        if not sniper_scans and not network_scans:
            st.info("No vulnerability scans found. Run scans using the Sniper Scan or Multi-Scan pages.")
            return
        
        # Create tabs for different scan types
        tab1, tab2, tab3 = st.tabs(["📊 All Scans", "🎯 Sniper Scans", "🌐 Network Scans"])
        
        with tab1:
            # Combined view
            all_scans = []
            all_scans.extend(sniper_scans)
            all_scans.extend(network_scans)
            
            # Sort by timestamp
            all_scans.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            if all_scans:
                self.display_scan_table(all_scans, "All Vulnerability Scans")
            else:
                st.info("No scans available")
        
        with tab2:
            # Sniper scans only
            if sniper_scans:
                self.display_scan_table(sniper_scans, "Sniper Scans (Single Target)")
            else:
                st.info("No sniper scans found. Use the Sniper Scan page to scan single targets.")
        
        with tab3:
            # Network scans only
            if network_scans:
                self.display_scan_table(network_scans, "Network Scans (Multiple Targets)")
            else:
                st.info("No network scans found. Use the Multi-Scan page to scan network ranges.")

    def display_scan_table(self, scans, title):
        """Display scans in a table format"""
        st.markdown(f"#### {title}")
        
        # Summary metrics
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.get('status') == 'Completed'])
        failed_scans = len([s for s in scans if s.get('status') == 'Failed'])
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Scans", total_scans)
        with col2:
            st.metric("Completed", completed_scans)
        with col3:
            st.metric("Failed", failed_scans)
        with col4:
            success_rate = (completed_scans / total_scans * 100) if total_scans > 0 else 0
            st.metric("Success Rate", f"{success_rate:.1f}%")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox(f"Filter by Status", ["All", "Completed", "Failed", "Running", "Error"], key=f"status_{title}")
        with col2:
            scan_type_filter = st.selectbox(f"Filter by Type", ["All", "Sniper Scan", "Network Scan"], key=f"type_{title}")
        with col3:
            limit = st.selectbox(f"Show Results", [25, 50, 100, 200], key=f"limit_{title}")
        
        # Apply filters
        filtered_scans = scans
        if status_filter != "All":
            filtered_scans = [s for s in filtered_scans if s.get('status') == status_filter]
        if scan_type_filter != "All":
            filtered_scans = [s for s in filtered_scans if s.get('type') == scan_type_filter]
        
        filtered_scans = filtered_scans[:limit]
        
        # Display scans
        for i, scan in enumerate(filtered_scans):
            status_color = {"Completed": "#22c55e", "Failed": "#ef4444", "Running": "#1ec8ff", "Error": "#f97316"}.get(scan.get("status"), "#64748b")
            
            
            with st.expander(f"{scan.get('target', 'Unknown')} — {scan.get('timestamp', 'Unknown')} [{scan.get('status', '')}]"):
                # Scan details
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.text(f"Scan ID: {scan.get('scan_id', 'N/A')[:16]}...")
                    st.text(f"Type: {scan.get('type', 'N/A')}")
                    st.text(f"Target: {scan.get('target', 'N/A')}")
                
                with col2:
                    st.text(f"Status: {scan.get('status', 'N/A')}")
                    st.text(f"Scan Method: {scan.get('scan_type', 'N/A')}")
                    if scan.get('target_count'):
                        st.text(f"Target Count: {scan.get('target_count', 'N/A')}")
                
                with col3:
                    st.text(f"Timestamp: {scan.get('timestamp', 'N/A')}")
                    if scan.get('execution_time'):
                        st.text(f"Duration: {scan.get('execution_time', 'N/A')}")
                    if scan.get('ports_found') is not None:
                        st.text(f"Ports Found: {scan.get('ports_found', 0)}")
                    if scan.get('hosts_up') is not None:
                        st.text(f"Hosts Up: {scan.get('hosts_up', 0)}")
                
                with col4:
                    if st.button(f"📥 Download Report", key=f"download_{scan.get('scan_id', i)}"):
                        self.download_vulnerability_scan_report(scan)
                    if st.button(f"📋 View Details", key=f"details_{scan.get('scan_id', i)}"):
                        self.show_scan_details(scan)
                
                # Command executed
                if scan.get('command'):
                    with st.expander("🖥️ Command Executed"):
                        st.code(scan.get('command'), language="bash")
                
                # Show error if any
                if scan.get('error'):
                    st.error(f"Error: {scan.get('error')}")

    def show_scan_details(self, scan):
        """Show detailed scan information"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#334155;margin:16px 0 8px'>Detailed Scan Information</div>", unsafe_allow_html=True)
        
        # Basic information
        st.json({
            "scan_id": scan.get('scan_id'),
            "type": scan.get('type'),
            "scan_type": scan.get('scan_type'),
            "target": scan.get('target'),
            "status": scan.get('status'),
            "timestamp": scan.get('timestamp'),
            "execution_time": scan.get('execution_time'),
            "ports_found": scan.get('ports_found'),
            "hosts_up": scan.get('hosts_up'),
            "target_count": scan.get('target_count')
        })
        
        # Output
        if scan.get('output'):
            with st.expander("📄 Full Scan Output", expanded=True):
                st.text(scan.get('output'))

    def download_vulnerability_scan_report(self, scan):
        """Generate and download vulnerability scan report"""
        try:
            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append("VULNERABILITY SCAN REPORT")
            report_lines.append("=" * 80)
            report_lines.append("")
            
            # Scan Information
            report_lines.append("SCAN INFORMATION:")
            report_lines.append("-" * 40)
            report_lines.append(f"Scan ID: {scan.get('scan_id', 'N/A')}")
            report_lines.append(f"Scan Type: {scan.get('type', 'N/A')}")
            report_lines.append(f"Target: {scan.get('target', 'N/A')}")
            report_lines.append(f"Status: {scan.get('status', 'N/A')}")
            report_lines.append(f"Timestamp: {scan.get('timestamp', 'N/A')}")
            report_lines.append(f"Duration: {scan.get('execution_time', 'N/A')}")
            
            if scan.get('ports_found') is not None:
                report_lines.append(f"Ports Found: {scan.get('ports_found')}")
            if scan.get('hosts_up') is not None:
                report_lines.append(f"Hosts Up: {scan.get('hosts_up')}")
            if scan.get('target_count'):
                report_lines.append(f"Target Count: {scan.get('target_count')}")
            
            report_lines.append("")
            
            # Command Executed
            report_lines.append("COMMAND EXECUTED:")
            report_lines.append("-" * 40)
            report_lines.append(scan.get('command', 'N/A'))
            report_lines.append("")
            
            # Full Output
            report_lines.append("SCAN OUTPUT:")
            report_lines.append("-" * 40)
            report_lines.append(scan.get('output', 'No output available'))
            report_lines.append("")
            
            # Errors
            if scan.get('error'):
                report_lines.append("ERRORS:")
                report_lines.append("-" * 40)
                report_lines.append(scan.get('error'))
                report_lines.append("")
            
            # Footer
            report_lines.append("=" * 80)
            report_lines.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append("Generated by SIEM System - Vulnerability Scan Module")
            report_lines.append("=" * 80)
            
            report_content = "\n".join(report_lines)
            
            st.download_button(
                label="📥 Download Full Report",
                data=report_content,
                file_name=f"vuln_scan_report_{scan.get('scan_id', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
            
        except Exception as e:
            st.error(f"❌ Error generating report: {str(e)}")
        """Generate a PDF report from the scan results"""
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "Security Vulnerability Scan Report", ln=True, align="C")
            pdf.ln(5)
            
            # Scan Information
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"Target: {scan_results['target']}", ln=True)
            pdf.cell(0, 10, f"Scan Type: {scan_results['scan_type']}", ln=True)
            pdf.cell(0, 10, f"Scan Date: {scan_results['scan_date']}", ln=True)
            
            # Reachability
            if 'reachable' in scan_results:
                pdf.cell(0, 10, f"Host Reachable: {'Yes' if scan_results['reachable'] else 'No'}", ln=True)
                
            pdf.ln(10)
            
            # Host information if available
            if 'host_info' in scan_results:
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Host Information", ln=True)
                pdf.ln(5)
                
                host_info = scan_results['host_info']
                for key, value in host_info.items():
                    pdf.set_font("Arial", "", 11)
                    pdf.cell(0, 8, f"{key.capitalize()}: {value}", ln=True)
                
                pdf.ln(5)
            
            # Vulnerabilities if they exist
            if 'vulnerabilities' in scan_results and scan_results['vulnerabilities']:
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Vulnerabilities", ln=True)
                pdf.ln(5)
                
                # Count by severity
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in scan_results['vulnerabilities']:
                    severity = vuln.get('severity', 'medium').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                # Summary of vulnerabilities by severity
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "Summary", ln=True)
                pdf.set_font("Arial", "", 11)
                
                pdf.cell(70, 8, f"Critical: {severity_counts['critical']}", ln=False)
                pdf.cell(70, 8, f"High: {severity_counts['high']}", ln=True)
                pdf.cell(70, 8, f"Medium: {severity_counts['medium']}", ln=False)
                pdf.cell(70, 8, f"Low: {severity_counts['low']}", ln=True)
                pdf.ln(5)
                
                # Detailed vulnerability information
                pdf.set_font("Arial", "B", 12)
                pdf.cell(0, 10, "Vulnerability Details", ln=True)
                
                for vuln in scan_results['vulnerabilities']:
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 8, f"Port {vuln.get('port', 'N/A')} - {vuln.get('service', 'Unknown')}", ln=True)
                    
                    pdf.set_font("Arial", "", 10)
                    pdf.cell(0, 8, f"Issue: {vuln.get('name', 'Unknown vulnerability')}", ln=True)
                    pdf.cell(0, 8, f"Severity: {vuln.get('severity', 'Unknown').upper()}", ln=True)
                    pdf.cell(0, 8, f"CVE: {vuln.get('cve', 'N/A')}", ln=True)
                    
                    # Details with word wrapping
                    pdf.set_font("Arial", "", 10)
                    pdf.multi_cell(0, 8, f"Details: {vuln.get('details', 'No details available')}")
                    
                    pdf.ln(5)
            
            # Services if they exist
            if 'services' in scan_results and scan_results['services']:
                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Open Ports and Services", ln=True)
                pdf.ln(5)
                
                for service in scan_results['services']:
                    pdf.set_font("Arial", "B", 11)
                    pdf.cell(0, 8, f"Port {service.get('port', 'N/A')} - {service.get('service', 'Unknown')}", ln=True)
                    
                    if service.get('details'):
                        pdf.set_font("Arial", "", 10)
                        pdf.multi_cell(0, 8, f"Details: {service.get('details', '')}")
                    
                    pdf.ln(3)
            
            # Save the PDF
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vuln_scan_{scan_results['target'].replace('.', '_')}_{timestamp}.pdf"
            filepath = os.path.join(self.reports_dir, filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            pdf.output(filepath)
            return filepath
            
        except Exception as e:
            st.error(f"Failed to generate PDF report: {str(e)}")
            st.error(traceback.format_exc())
            return None

    def store_in_database(self, scan_results):
        """Store scan results in the database"""
        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if table exists and has the correct structure
            cursor.execute("PRAGMA table_info(vulnerability_scans)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # If table doesn't exist or doesn't have the right structure, create it
            if not columns or 'results' not in column_names:
                # Drop table if it exists but with wrong structure
                if columns:
                    cursor.execute('DROP TABLE vulnerability_scans')
                    
                # Create table with correct structure
                cursor.execute('''
                CREATE TABLE vulnerability_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    results TEXT NOT NULL
                )
                ''')
            
            # Convert scan results to JSON string
            results_json = json.dumps(scan_results)
            
            # Insert the scan results into the database
            cursor.execute('''
            INSERT INTO vulnerability_scans (target, scan_type, scan_date, results)
            VALUES (?, ?, ?, ?)
            ''', (
                scan_results['target'],
                scan_results['scan_type'],
                scan_results['scan_date'],
                results_json
            ))
            
            # Commit and close
            conn.commit()
            conn.close()
            
            add_notification(
                f"Vulnerability scan saved for {scan_results['target']}",
                "success"
            )
            
            return True
            
        except Exception as e:
            st.error(f"Failed to save scan results to database: {str(e)}")
            st.error(traceback.format_exc())
            return False

    def generate_ai_summary(self, scan_results):
        """Generate an AI summary of the scan results using DeepSeek API"""
        try:
            if not GEMINI_AVAILABLE:
                return self._generate_fallback_summary(scan_results)

            scan_data = {
                "target":          scan_results.get('target', 'Unknown'),
                "scan_type":       scan_results.get('scan_type', 'Unknown'),
                "scan_date":       scan_results.get('scan_date', 'Unknown'),
                "host_info":       scan_results.get('host_info', {}),
                "services":        scan_results.get('services', []),
                "vulnerabilities": scan_results.get('vulnerabilities', []),
                "reachable":       scan_results.get('reachable', False),
            }

            prompt = (
                "You are a cybersecurity expert analyzing the results of a vulnerability scan. "
                "Provide a detailed security analysis of the following scan results.\n\n"
                f"Target: {scan_data['target']}\n"
                f"Scan Type: {scan_data['scan_type']}\n"
                f"Date: {scan_data['scan_date']}\n"
                f"Host Reachable: {scan_data['reachable']}\n\n"
                f"Host Information:\n{json.dumps(scan_data['host_info'], indent=2) if scan_data['host_info'] else 'None'}\n\n"
                f"Discovered Services:\n{json.dumps(scan_data['services'], indent=2) if scan_data['services'] else 'None'}\n\n"
                f"Vulnerabilities Found:\n{json.dumps(scan_data['vulnerabilities'], indent=2) if scan_data['vulnerabilities'] else 'None'}\n\n"
                "Provide:\n"
                "1. Overall risk assessment and security posture\n"
                "2. Critical vulnerabilities and their impact\n"
                "3. Service analysis and potential attack vectors\n"
                "4. Specific remediation recommendations\n"
                "5. Security best practices relevant to the findings\n\n"
                "Format as a detailed markdown report with clear sections and actionable insights."
            )

            import requests as _req
            r = _req.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/yourusername/aisiem",
                    "X-Title": "AI-IDS",
                },
                json={"model": os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat"), "messages": [{"role": "user", "content": prompt}], "stream": False},
                timeout=45,
            )
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

        except Exception as e:
            st.error(f"Error generating AI analysis: {str(e)}")
            return self._generate_fallback_summary(scan_results)
    
    def _generate_fallback_summary(self, scan_results):
        """Generate a fallback summary when Gemini API is not available"""
        try:
            # AI mode simulation - in a real application, this would call an AI API
            summary = []
            
            # Basic header
            summary.append("# AI Security Analysis Summary")
            summary.append(f"## Target: {scan_results['target']}")
            summary.append(f"Scan performed on: {scan_results['scan_date']}")
            
            # Host information
            if 'host_info' in scan_results:
                host_info = scan_results['host_info']
                summary.append("\n## Host Information")
                
                if 'os' in host_info:
                    summary.append(f"- Operating System: **{host_info['os']}**")
                
                if 'status' in host_info:
                    summary.append(f"- Host Status: **{host_info['status']}**")
                
                if 'mac' in host_info:
                    summary.append(f"- MAC Address: {host_info['mac']} ({host_info.get('vendor', 'Unknown')})")
            
            # Vulnerability summary
            if 'vulnerabilities' in scan_results and scan_results['vulnerabilities']:
                vulns = scan_results['vulnerabilities']
                
                # Count by severity
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in vulns:
                    severity = vuln.get('severity', 'medium').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                # Overall risk assessment
                risk_level = "Low"
                if severity_counts['critical'] > 0:
                    risk_level = "Critical"
                elif severity_counts['high'] > 0:
                    risk_level = "High"
                elif severity_counts['medium'] > 3:
                    risk_level = "Medium-High"
                elif severity_counts['medium'] > 0:
                    risk_level = "Medium"
                
                summary.append(f"\n## Overall Risk Assessment: **{risk_level}**")
                summary.append(f"Found **{len(vulns)}** potential vulnerabilities:")
                summary.append(f"- Critical: {severity_counts['critical']}")
                summary.append(f"- High: {severity_counts['high']}")
                summary.append(f"- Medium: {severity_counts['medium']}")
                summary.append(f"- Low: {severity_counts['low']}")
                
                # Top vulnerabilities
                if vulns:
                    # Sort by severity
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    sorted_vulns = sorted(
                        vulns, 
                        key=lambda v: severity_order.get(v.get('severity', 'medium').lower(), 4)
                    )
                    
                    # Show top 3 or all if less than 3
                    top_vulns = sorted_vulns[:3]
                    
                    summary.append("\n## Top Vulnerabilities")
                    for i, vuln in enumerate(top_vulns, 1):
                        severity = vuln.get('severity', 'medium').upper()
                        summary.append(f"### {i}. {vuln.get('name', 'Unknown Vulnerability')} ({severity})")
                        summary.append(f"- **Port**: {vuln.get('port', 'N/A')} ({vuln.get('service', 'Unknown')})")
                        if vuln.get('cve', 'N/A') != 'N/A':
                            summary.append(f"- **CVE**: {vuln.get('cve', 'N/A')}")
                        summary.append(f"- **Details**: {vuln.get('details', 'No details available')}")
                
                # Recommendations
                summary.append("\n## Recommendations")
                
                if severity_counts['critical'] > 0:
                    summary.append("- **URGENT**: Address critical vulnerabilities immediately")
                    summary.append("- Consider taking affected systems offline until patched")
                
                if severity_counts['high'] > 0:
                    summary.append("- Prioritize patching high severity vulnerabilities")
                    summary.append("- Implement mitigations for vulnerabilities that cannot be immediately patched")
                
                if 'services' in scan_results and scan_results['services']:
                    services = scan_results['services']
                    open_ports = [int(s.get('port', 0)) for s in services]
                    
                    if any(p in open_ports for p in [21, 23, 25, 110, 143]):
                        summary.append("- Consider replacing cleartext protocols with encrypted alternatives")
                    
                    if 22 in open_ports:
                        summary.append("- Ensure SSH is properly configured (disable root login, use key-based authentication)")
                    
                    if any(p in open_ports for p in [80, 443, 8080, 8443]):
                        summary.append("- Review web server configurations and implement security headers")
                        summary.append("- Consider using a Web Application Firewall (WAF)")
                
                summary.append("- Implement regular vulnerability scanning and patching")
                summary.append("- Review and update your security policies")
            
            elif 'services' in scan_results and scan_results['services']:
                services = scan_results['services']
                summary.append(f"\n## Service Analysis")
                summary.append(f"Found **{len(services)}** open services/ports:")
                
                # Group services by common categories
                web_services = []
                db_services = []
                remote_access = []
                mail_services = []
                other_services = []
                
                for service in services:
                    port = service.get('port', 'N/A')
                    name = service.get('service', 'unknown')
                    
                    if name in ['http', 'https', 'www'] or port in ['80', '443', '8080', '8443']:
                        web_services.append(service)
                    elif name in ['mysql', 'postgresql', 'mongodb', 'redis'] or port in ['3306', '5432', '27017']:
                        db_services.append(service)
                    elif name in ['ssh', 'rdp', 'telnet', 'vnc'] or port in ['22', '3389', '23', '5900']:
                        remote_access.append(service)
                    elif name in ['smtp', 'pop3', 'imap'] or port in ['25', '110', '143']:
                        mail_services.append(service)
                    else:
                        other_services.append(service)
                
                # Web services section
                if web_services:
                    summary.append("\n### Web Services")
                    for service in web_services:
                        summary.append(f"- Port {service.get('port')}: {service.get('service')} {service.get('details', '')}")
                    summary.append("**Recommendations:**")
                    summary.append("- Ensure web servers are patched and securely configured")
                    summary.append("- Implement security headers and HTTPS")
                    summary.append("- Consider implementing a Web Application Firewall")
                
                # Remote access section
                if remote_access:
                    summary.append("\n### Remote Access Services")
                    for service in remote_access:
                        summary.append(f"- Port {service.get('port')}: {service.get('service')} {service.get('details', '')}")
                    summary.append("**Recommendations:**")
                    summary.append("- Use strong authentication mechanisms (key-based for SSH, MFA where available)")
                    summary.append("- Limit access to trusted IP addresses when possible")
                    summary.append("- Avoid cleartext protocols like Telnet")
                
                # Database section
                if db_services:
                    summary.append("\n### Database Services")
                    for service in db_services:
                        summary.append(f"- Port {service.get('port')}: {service.get('service')} {service.get('details', '')}")
                    summary.append("**Recommendations:**")
                    summary.append("- Restrict database access to localhost or trusted networks")
                    summary.append("- Use strong authentication and encryption")
                    summary.append("- Regularly update database software")
                
                # Mail services section
                if mail_services:
                    summary.append("\n### Mail Services")
                    for service in mail_services:
                        summary.append(f"- Port {service.get('port')}: {service.get('service')} {service.get('details', '')}")
                    summary.append("**Recommendations:**")
                    summary.append("- Implement email encryption (TLS)")
                    summary.append("- Configure SPF, DKIM and DMARC records")
                    summary.append("- Use anti-spam and anti-phishing technologies")
                
                # Other services
                if other_services:
                    summary.append("\n### Other Services")
                    for service in other_services:
                        summary.append(f"- Port {service.get('port')}: {service.get('service')} {service.get('details', '')}")
                
                # General security recommendations
                summary.append("\n## General Security Recommendations")
                summary.append("- Implement a regular patching and update schedule")
                summary.append("- Only expose necessary services to the network")
                summary.append("- Implement network segmentation and firewalls")
                summary.append("- Deploy intrusion detection/prevention systems")
                summary.append("- Maintain backups and disaster recovery plans")
            else:
                summary.append("\n## No vulnerabilities or open services found")
                summary.append("The target appears to be secure or is not responding to scan attempts.")
                
            return "\n".join(summary)
        except Exception as e:
            st.error(f"Failed to generate AI summary: {str(e)}")
            return "AI summary generation failed. Please try again later."

    def render(self):
        """Render the scan results page"""
        # Apply custom CSS
        st.markdown("""
        <style>
        .main-header {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 1rem;
            color: #ff4b4b;
        }
        .severity-critical {
            color: #ff2b2b;
            font-weight: bold;
        }
        .severity-high {
            color: #ff8c00;
            font-weight: bold;
        }
        .severity-medium {
            color: #ffcc00;
            font-weight: bold;
        }
        .severity-low {
            color: #00cc00;
            font-weight: bold;
        }
        .result-section {
            padding: 1.5rem;
            border-radius: 0.5rem;
            background-color: #f8f9fa;
            margin-bottom: 1.5rem;
            border-left: 4px solid #ff4b4b;
        }
        </style>
        """, unsafe_allow_html=True)
        
        st.markdown("<div class='main-header'>Scan Results</div>", unsafe_allow_html=True)
        
        # Get scan results from session state
        if 'scan_results' not in st.session_state:
            st.error("No scan results available. Please run a scan first.")
            if st.button("⬅️ Return to Scanner", key="no_results_btn"):
                st.session_state.view = "vuln_overview"
                st.query_params["view"] = "vuln_overview"
                st.rerun()
            return
        
        scan_results = st.session_state.scan_results
        
        # Basic scan information
        st.markdown("<div class='result-section'>", unsafe_allow_html=True)
        st.subheader("Scan Information")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"**Target:** {scan_results['target']}")
            st.markdown(f"**Scan Type:** {scan_results['scan_type'].capitalize()}")
        
        with col2:
            st.markdown(f"**Scan Date:** {scan_results['scan_date']}")
            st.markdown(f"**Port Range:** {scan_results.get('port_range', 'Default')}")
        
        with col3:
            # Host reachability status
            reachable = scan_results.get('reachable', False)
            if reachable:
                st.markdown("**Host Status:** 🟢 Reachable")
            else:
                st.markdown("**Host Status:** 🟠 Not Directly Reachable (forced scan)")
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Result tabs - vulnerabilities, services, raw output
        tab1, tab2, tab3 = st.tabs(["Vulnerabilities & Findings", "Services & Ports", "Raw Scan Output"])
        
        with tab1:
            st.markdown("<div class='result-section'>", unsafe_allow_html=True)
            if 'vulnerabilities' in scan_results and scan_results['vulnerabilities']:
                vulns = scan_results['vulnerabilities']
                st.subheader(f"Found {len(vulns)} Potential Vulnerabilities")
                
                # Count by severity
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in vulns:
                    severity = vuln.get('severity', 'medium').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                # Display metrics for each severity level
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Critical", severity_counts["critical"], delta=None, 
                              delta_color="inverse")
                with col2:
                    st.metric("High", severity_counts["high"], delta=None, 
                              delta_color="inverse")
                with col3:
                    st.metric("Medium", severity_counts["medium"], delta=None, 
                              delta_color="inverse")
                with col4:
                    st.metric("Low", severity_counts["low"], delta=None, 
                              delta_color="inverse")
                
                # Display vulnerabilities in a table format
                if vulns:
                    # Convert to dataframe for better display
                    vuln_data = []
                    for vuln in vulns:
                        vuln_data.append({
                            'Port': vuln.get('port', 'N/A'),
                            'Service': vuln.get('service', 'Unknown'),
                            'Vulnerability': vuln.get('name', 'Unknown'),
                            'Severity': vuln.get('severity', 'medium').upper(),
                            'CVE': vuln.get('cve', 'N/A')
                        })
                    
                    df = pd.DataFrame(vuln_data)
                    st.dataframe(df, use_container_width=True, height=300)
                    
                    # Detailed vulnerability information
                    st.subheader("Detailed Findings")
                    
                    # Sort by severity first
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    sorted_vulns = sorted(
                        vulns, 
                        key=lambda v: severity_order.get(v.get('severity', 'medium').lower(), 4)
                    )
                    
                    for i, vuln in enumerate(sorted_vulns):
                        severity = vuln.get('severity', 'medium').lower()
                        severity_class = f"severity-{severity}"
                        
                        with st.expander(
                            f"{i+1}. {vuln.get('name', 'Unknown Vulnerability')} " + 
                            f"(Port {vuln.get('port', 'N/A')}, " + 
                            f"Severity: {severity.upper()})"
                        ):
                            st.markdown(f"**Service:** {vuln.get('service', 'Unknown')}")
                            st.markdown(f"**CVE:** {vuln.get('cve', 'N/A')}")
                            st.markdown(f"**Severity:** <span class='{severity_class}'>{severity.upper()}</span>", unsafe_allow_html=True)
                            st.markdown("**Details:**")
                            st.markdown(vuln.get('details', 'No details available'))
            else:
                st.info("No vulnerabilities detected in this scan.")
                
                if 'services' in scan_results and scan_results['services']:
                    st.markdown("Open services were found but no known vulnerabilities were detected.")
                    st.markdown("Consider additional targeted scanning for more thorough analysis.")
            st.markdown("</div>", unsafe_allow_html=True)
                
        with tab2:
            st.markdown("<div class='result-section'>", unsafe_allow_html=True)
            if 'services' in scan_results and scan_results['services']:
                services = scan_results['services']
                st.subheader(f"Found {len(services)} Open Services")
                
                # Convert to dataframe
                service_data = []
                for service in services:
                    service_data.append({
                        'Port': service.get('port', 'N/A'),
                        'Service': service.get('service', 'Unknown'),
                        'Version': service.get('version', 'N/A'),
                        'Details': service.get('details', '')
                    })
                
                # Display as table
                df = pd.DataFrame(service_data)
                st.dataframe(df, use_container_width=True)
                
                # Show host info if available
                if 'host_info' in scan_results and scan_results['host_info']:
                    host_info = scan_results['host_info']
                    st.subheader("Host Information")
                    
                    info_text = []
                    if 'os' in host_info:
                        info_text.append(f"**OS:** {host_info['os']}")
                    if 'status' in host_info:
                        info_text.append(f"**Status:** {host_info['status']}")
                    if 'latency' in host_info:
                        info_text.append(f"**Latency:** {host_info['latency']} seconds")
                    if 'mac' in host_info:
                        info_text.append(f"**MAC:** {host_info['mac']} ({host_info.get('vendor', 'Unknown')})")
                    
                    st.markdown(" | ".join(info_text), unsafe_allow_html=True)
            else:
                st.info("No open ports or services were detected.")
                
                # Check for host info
                if 'host_info' in scan_results:
                    host_info = scan_results['host_info']
                    if host_info.get('status', 'down') == 'up':
                        st.markdown("The host appears to be up but has no accessible open ports.")
                    else:
                        st.markdown("The host may be down or blocking all scan attempts.")
            st.markdown("</div>", unsafe_allow_html=True)
        
        with tab3:
            st.markdown("<div class='result-section'>", unsafe_allow_html=True)
            st.subheader("Raw Nmap Output")
            if 'raw_output' in scan_results:
                st.code(scan_results['raw_output'], language="bash")
            else:
                st.warning("Raw scan output is not available.")
            st.markdown("</div>", unsafe_allow_html=True)
        
        # Actions section
        st.markdown("---")
        st.subheader("Actions")
        
        col1, col2, col3 = st.columns(3)
        
        # AI Summary button - only active if AI mode is enabled
        with col1:
            ai_mode = st.session_state.get("ai_mode", False)
            if st.button("🤖 Generate AI Summary", 
                         use_container_width=True, 
                         disabled=not ai_mode):
                if ai_mode:
                    with st.spinner("Generating AI analysis..."):
                        ai_summary = self.generate_ai_summary(scan_results)
                        st.session_state.ai_summary = ai_summary
                        st.rerun()  # Refresh to show the summary
                else:
                    st.info("AI mode is disabled. Enable it in sidebar settings.")
        
        # Save to Database button
        with col2:
            if st.button("💾 Save Scan Results", use_container_width=True):
                with st.spinner("Saving results to database..."):
                    success = self.store_in_database(scan_results)
                    if success:
                        st.success("Results saved to database successfully!")
                        
                        # Generate PDF
                        with st.spinner("Generating PDF report..."):
                            pdf_path = self.generate_pdf_report(scan_results)
                            if pdf_path:
                                # Provide download option
                                with open(pdf_path, "rb") as pdf_file:
                                    st.download_button(
                                        "📥 Download PDF Report",
                                        pdf_file,
                                        file_name=os.path.basename(pdf_path),
                                        mime="application/pdf",
                                        key="download_pdf_btn"
                                    )
                        
                        # Option to navigate to vulnerability overview
                        if st.button("📊 View in Vulnerability Overview"):
                            st.session_state.view = "vuln_overview"
                            st.query_params["view"] = "vuln_overview"
                            st.rerun()
                    else:
                        st.error("Failed to save results to database.")
        
        # Close/Return button
        with col3:
            if st.button("🔙 Return to Overview", use_container_width=True):
                st.session_state.view = "vuln_overview"
                st.query_params["view"] = "vuln_overview"
                st.rerun()
        
        # Display AI summary if available
        if hasattr(st.session_state, 'ai_summary') and st.session_state.ai_summary:
            st.markdown("---")
            st.markdown("<div class='result-section'>", unsafe_allow_html=True)
            st.subheader("🤖 AI Security Analysis")
            st.markdown(st.session_state.ai_summary)
            st.markdown("</div>", unsafe_allow_html=True)
        
        # Add vulnerability scans section
        st.markdown("---")
        self.render_vulnerability_scans()

def render_scan_results():
    """Main entry point for the scan results page"""
    page = ScanResultsPage()
    page.render()

if __name__ == "__main__":
    render_scan_results()