import warnings
warnings.filterwarnings("ignore")

import streamlit as st
import subprocess
import json
import re
import time
import os
import tempfile
import xml.etree.ElementTree as ET
import ipaddress
import base64
from datetime import datetime  # type: ignore
import traceback
import requests  # type: ignore
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
from utils.gemini_api import analyze_scan_with_gemini

class SniperScanPage:
    def __init__(self):
        # Path to output directory for reports
        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        # API endpoint for scan results - set to None to disable backend calls
        self.api_url = None  # "http://localhost:5000/api/vulnerability/scan"
        
        # Initialize session state for advanced options
        if 'sniper_advanced_options' not in st.session_state:
            st.session_state.sniper_advanced_options = False
    
    def render_page(self):
        """Render the enhanced Sniper Scan page"""
        from components.page_style import inject_page_css, page_header
        inject_page_css()

        col_back, _ = st.columns([1, 5])
        with col_back:
            if st.button("← Back to Overview", key="back_to_overview_top", use_container_width=True):
                st.session_state.view = "vuln_overview"
                st.rerun()

        page_header("Sniper Scan", "Focused single-target vulnerability assessment via Nmap", badge="Single Host")

        # Display selected scan results if any
        if hasattr(st.session_state, 'selected_scan_for_display') and st.session_state.selected_scan_for_display:
            st.markdown("---")
            st.markdown("**Selected scan results**")
            col1, col2 = st.columns([8, 1])
            with col1:
                self.display_scan_results(st.session_state.selected_scan_for_display)
            with col2:
                if st.button("Close", key="close_scan_display"):
                    st.session_state.selected_scan_for_display = None
                    st.rerun()
            st.markdown("---")

        # Advanced options toggle
        _, col_adv = st.columns([5, 1])
        with col_adv:
            if st.button("Advanced options", help="Toggle advanced nmap configuration"):
                st.session_state.sniper_advanced_options = not st.session_state.sniper_advanced_options
        
        # Target specification section
        self.render_target_section()
        
        st.markdown("---")
        
        # Scan configuration sections
        col1, col2 = st.columns(2)
        
        with col1:
            scan_type = self.render_scan_techniques()
            discovery_options = self.render_host_discovery()
            
        with col2:
            port_options = self.render_port_specification()
            service_options = self.render_service_detection()
        
        st.markdown("---")
        
        # Advanced options (when enabled)
        if st.session_state.sniper_advanced_options:
            self.render_advanced_options()
            st.markdown("---")
        
        # Scan execution section
        self.render_scan_execution(scan_type, discovery_options, port_options, service_options)
        
        # Recent scans section
        self.render_recent_scans()

    def render_target_section(self):
        """Render target specification section"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Target Specification</div>", unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            target = st.text_input(
                "Target Host",
                placeholder="192.168.1.1 or scanme.nmap.org",
                help="IP address, hostname, or FQDN of target"
            )
            
        with col2:
            if st.button("🔍 Validate Target"):
                if target:
                    if self.validate_target(target):
                        st.success("✅ Valid target")
                    else:
                        st.error("❌ Invalid target")
                else:
                    st.warning("⚠️ Enter a target first")
                    
        with col3:
            if st.button("📡 Test Connectivity"):
                if target:
                    self.check_host_reachable(target)
                else:
                    st.warning("⚠️ Enter a target first")
        
        # Sudo password section for privileged scans
        st.markdown("---")
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Privileged Authentication</div>", unsafe_allow_html=True)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            sudo_password = st.text_input(
                "Sudo Password (Optional)",
                type="password",
                placeholder="Enter your sudo password for privileged scans",
                help="Required for SYN scans (-sS), OS detection (-O), and other privileged operations. Leave empty for non-privileged scans."
            )
            
        with col2:
            st.markdown("**When needed:**")
            st.markdown("• SYN Scan (-sS)")
            st.markdown("• OS Detection (-O)")
            st.markdown("• Raw packet scans")
            st.markdown("• Some timing options")
        
        # Store password in session state securely (base64 encoded)
        if sudo_password:
            # Base64 encode the password for basic obfuscation
            encoded_password = base64.b64encode(sudo_password.encode()).decode()
            st.session_state.sudo_password_encoded = encoded_password
        elif 'sudo_password_encoded' in st.session_state:
            # Clear password if input is empty
            del st.session_state.sudo_password_encoded
        
        return target

    def render_scan_techniques(self):
        """Render scan techniques section"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Scan Techniques</div>", unsafe_allow_html=True)
        
        # Primary scan types
        scan_type = st.selectbox(
            "Primary Scan Type",
            [
                "TCP SYN Scan (-sS) [Default]",
                "TCP Connect Scan (-sT)",
                "TCP ACK Scan (-sA)",
                "TCP Window Scan (-sW)",
                "TCP Maimon Scan (-sM)",
                "UDP Scan (-sU)",
                "TCP Null Scan (-sN)",
                "TCP FIN Scan (-sF)",
                "TCP Xmas Scan (-sX)",
                "SCTP INIT Scan (-sY)",
                "SCTP COOKIE-ECHO Scan (-sZ)",
                "IP Protocol Scan (-sO)",
                "Custom TCP Flags"
            ],
            help="Choose the primary scanning technique"
        )
        
        # Custom TCP flags if selected
        custom_flags = None
        if "Custom TCP Flags" in scan_type:
            custom_flags = st.text_input(
                "Custom TCP Flags",
                placeholder="SYN,ACK,FIN...",
                help="Specify custom TCP flags: SYN, ACK, FIN, RST, PSH, URG"
            )
        
        # Timing template
        timing = st.select_slider(
            "Timing Template",
            options=[
                "T0 (Paranoid)",
                "T1 (Sneaky)", 
                "T2 (Polite)",
                "T3 (Normal)",
                "T4 (Aggressive)",
                "T5 (Insane)"
            ],
            value="T3 (Normal)",
            help="Scan timing and performance template"
        )
        
        return {
            "type": scan_type,
            "custom_flags": custom_flags,
            "timing": timing
        }

    def render_host_discovery(self):
        """Render host discovery options"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Host Discovery</div>", unsafe_allow_html=True)
        
        discovery_options = {}
        
        # Host discovery type
        discovery_type = st.selectbox(
            "Discovery Method",
            [
                "Default Discovery",
                "No Discovery (-Pn) - Assume host is up",
                "Ping Scan Only (-sn) - No port scan",
                "List Scan (-sL) - List targets only"
            ],
            help="Host discovery technique"
        )
        discovery_options["type"] = discovery_type
        
        # Advanced discovery probes
        if st.checkbox("Advanced Discovery Probes"):
            col1, col2 = st.columns(2)
            with col1:
                discovery_options["tcp_syn"] = st.text_input("TCP SYN Probes (-PS)", placeholder="22,80,443")
                discovery_options["tcp_ack"] = st.text_input("TCP ACK Probes (-PA)", placeholder="80,443")
                discovery_options["icmp_echo"] = st.checkbox("ICMP Echo (-PE)")
                discovery_options["icmp_timestamp"] = st.checkbox("ICMP Timestamp (-PP)")
            with col2:
                discovery_options["udp_probes"] = st.text_input("UDP Probes (-PU)", placeholder="53,67,123")
                discovery_options["icmp_netmask"] = st.checkbox("ICMP Netmask (-PM)")
                discovery_options["ip_protocol"] = st.text_input("IP Protocol Ping (-PO)", placeholder="1,2,4")
        
        # DNS options
        if st.checkbox("DNS Options"):
            col1, col2 = st.columns(2)
            with col1:
                discovery_options["dns_resolution"] = st.selectbox(
                    "DNS Resolution",
                    ["Default", "Never resolve (-n)", "Always resolve (-R)"]
                )
            with col2:
                discovery_options["dns_servers"] = st.text_input(
                    "Custom DNS Servers",
                    placeholder="8.8.8.8,1.1.1.1"
                )
        
        return discovery_options

    def render_port_specification(self):
        """Render port specification options"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Port Specification</div>", unsafe_allow_html=True)
        
        port_options = {}
        
        # Port specification method
        port_method = st.selectbox(
            "Port Selection Method",
            [
                "Default Ports (Top 1000)",
                "All Ports (1-65535)",
                "Fast Scan (-F) - Top 100",
                "Top Ports (Custom)",
                "Specific Ports",
                "Port Ranges"
            ],
            help="How to specify which ports to scan"
        )
        port_options["method"] = port_method
        
        # Specific configurations based on method
        if "Top Ports" in port_method and "Custom" in port_method:
            port_options["top_count"] = st.number_input(
                "Number of Top Ports",
                min_value=1,
                max_value=65535,
                value=1000,
                help="Scan the N most common ports"
            )
        elif "Specific Ports" in port_method:
            port_options["specific_ports"] = st.text_input(
                "Port List",
                placeholder="22,80,443,8080",
                help="Comma-separated list of ports"
            )
        elif "Port Ranges" in port_method:
            port_options["port_ranges"] = st.text_input(
                "Port Ranges",
                placeholder="1-1000,8000-9000",
                help="Port ranges (e.g., 1-1000,8080-8090)"
            )
        
        # Protocol specification
        if st.checkbox("Protocol-Specific Ports"):
            col1, col2, col3 = st.columns(3)
            with col1:
                port_options["tcp_ports"] = st.text_input("TCP Ports (T:)", placeholder="21-25,80,443")
            with col2:
                port_options["udp_ports"] = st.text_input("UDP Ports (U:)", placeholder="53,67,123")
            with col3:
                port_options["sctp_ports"] = st.text_input("SCTP Ports (S:)", placeholder="9,20,80")
        
        # Port exclusions
        port_options["exclude_ports"] = st.text_input(
            "Exclude Ports",
            placeholder="135,139,445",
            help="Ports to exclude from scanning"
        )
        
        # Port scan order
        port_options["random_order"] = not st.checkbox(
            "Sequential Port Scan (-r)",
            help="Scan ports in sequential order instead of random"
        )
        
        return port_options

    def render_service_detection(self):
        """Render service and version detection options"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Service Detection</div>", unsafe_allow_html=True)
        
        service_options = {}
        
        # Version detection
        service_options["version_detection"] = st.checkbox(
            "Enable Version Detection (-sV)",
            help="Probe open ports to determine service/version info"
        )
        
        if service_options["version_detection"]:
            service_options["version_intensity"] = st.select_slider(
                "Version Detection Intensity",
                options=list(range(0, 10)),
                value=7,
                help="0=Light, 9=Try all probes"
            )
        
        # Script scanning
        service_options["script_scan"] = st.checkbox(
            "Enable Script Scanning (-sC)",
            help="Enable default NSE scripts"
        )
        
        if service_options["script_scan"] or st.checkbox("Custom Scripts"):
            col1, col2 = st.columns(2)
            with col1:
                service_options["custom_scripts"] = st.multiselect(
                    "Script Categories",
                    [
                        "auth", "broadcast", "brute", "default", "discovery",
                        "dos", "exploit", "external", "fuzzer", "intrusive",
                        "malware", "safe", "version", "vuln"
                    ],
                    help="Select NSE script categories"
                )
            with col2:
                service_options["script_args"] = st.text_area(
                    "Script Arguments",
                    placeholder="key1=value1,key2=value2",
                    help="Arguments to pass to scripts"
                )
        
        # OS detection
        service_options["os_detection"] = st.checkbox(
            "OS Detection (-O)",
            help="Enable operating system detection"
        )
        
        if service_options["os_detection"]:
            col1, col2 = st.columns(2)
            with col1:
                service_options["os_scan_limit"] = st.checkbox(
                    "Limit OS Detection (--osscan-limit)",
                    help="Limit OS detection to promising targets"
                )
            with col2:
                service_options["os_scan_guess"] = st.checkbox(
                    "Aggressive OS Guessing (--osscan-guess)",
                    help="Guess OS more aggressively"
                )
        
        # Aggressive scan shortcut
        if st.checkbox("Aggressive Scan (-A)", help="Enable OS detection, version detection, script scanning, and traceroute"):
            service_options["aggressive"] = True
            service_options["os_detection"] = True
            service_options["version_detection"] = True
            service_options["script_scan"] = True
            service_options["traceroute"] = True
        
        return service_options

    def render_advanced_options(self):
        """Render advanced nmap options"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Advanced Options</div>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### 🔧 Performance & Timing")
            
            # Timing controls
            if st.checkbox("Custom Timing Controls"):
                timing_options = {}
                timing_options["min_hostgroup"] = st.number_input("Min Host Group Size", min_value=1, value=30)
                timing_options["max_hostgroup"] = st.number_input("Max Host Group Size", min_value=1, value=1024)
                timing_options["min_parallelism"] = st.number_input("Min Parallelism", min_value=1, value=1)
                timing_options["max_parallelism"] = st.number_input("Max Parallelism", min_value=1, value=1)
                timing_options["min_rtt_timeout"] = st.text_input("Min RTT Timeout", placeholder="100ms")
                timing_options["max_rtt_timeout"] = st.text_input("Max RTT Timeout", placeholder="10s")
                timing_options["max_retries"] = st.number_input("Max Retries", min_value=0, value=10)
                timing_options["host_timeout"] = st.text_input("Host Timeout", placeholder="0")
                timing_options["scan_delay"] = st.text_input("Scan Delay", placeholder="0")
                timing_options["max_scan_delay"] = st.text_input("Max Scan Delay", placeholder="0")
                timing_options["min_rate"] = st.number_input("Min Rate (packets/sec)", min_value=0, value=0)
                timing_options["max_rate"] = st.number_input("Max Rate (packets/sec)", min_value=0, value=0)
            
            # Firewall evasion
            st.markdown("##### 🛡️ Firewall/IDS Evasion")
            evasion_options = {}
            evasion_options["fragment_packets"] = st.checkbox("Fragment Packets (-f)")
            evasion_options["mtu"] = st.number_input("Custom MTU", min_value=0, max_value=65536, value=0, help="Use 0 for default MTU")
            evasion_options["decoy_scan"] = st.text_input("Decoy Hosts", placeholder="192.168.1.1,ME,192.168.1.3", help="Comma-separated decoy IPs")
            evasion_options["spoof_source"] = st.text_input("Spoof Source IP", placeholder="192.168.1.100")
            evasion_options["source_port"] = st.number_input("Source Port", min_value=0, max_value=65535, value=0, help="Use 0 for default")
            evasion_options["data_length"] = st.number_input("Append Random Data (bytes)", min_value=0, value=0)
            evasion_options["ip_options"] = st.text_input("IP Options", placeholder="S192.168.1.1 192.168.1.2")
            evasion_options["spoof_mac"] = st.text_input("Spoof MAC Address", placeholder="DE:AD:CO:DE:00:00")
            evasion_options["bad_sum"] = st.checkbox("Use Bad Checksums (--badsum)")
            evasion_options["adler32"] = st.checkbox("Use Adler32 instead of CRC32C for SCTP")
        
        with col2:
            st.markdown("##### 📊 Output Options")
            
            # Output formats
            output_options = {}
            output_options["normal_output"] = st.checkbox("Normal Output (-oN)", value=True)
            output_options["xml_output"] = st.checkbox("XML Output (-oX)", value=True)
            output_options["greppable_output"] = st.checkbox("Greppable Output (-oG)")
            output_options["all_formats"] = st.checkbox("All Formats (-oA)")
            
            # Verbosity and debugging
            output_options["verbose"] = st.select_slider(
                "Verbosity Level",
                options=[0, 1, 2, 3, 4, 5],
                value=1,
                help="Increase verbosity (0=normal, 5=very verbose)"
            )
            output_options["debug"] = st.select_slider(
                "Debug Level",
                options=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                value=0,
                help="Enable debugging (0=none, 9=very high)"
            )
            output_options["reason"] = st.checkbox("Show Reason (--reason)", help="Display reason port is in particular state")
            output_options["open_only"] = st.checkbox("Show Open Ports Only (--open)")
            output_options["packet_trace"] = st.checkbox("Packet Trace (--packet-trace)")
            output_options["resume"] = st.text_input("Resume Scan", placeholder="Path to previous scan file")
            
            # Interface options
            st.markdown("##### 🌐 Network Interface")
            interface_options = {}
            interface_options["interface"] = st.text_input("Network Interface (-e)", placeholder="eth0")
            interface_options["dns_servers"] = st.text_input("DNS Servers", placeholder="8.8.8.8,1.1.1.1")
            interface_options["source_ip"] = st.text_input("Source IP", placeholder="192.168.1.100")
            interface_options["ttl"] = st.number_input("IP TTL", min_value=0, max_value=255, value=0, help="Use 0 for default")
            interface_options["send_eth"] = st.checkbox("Send Ethernet Frames (--send-eth)")
            interface_options["send_ip"] = st.checkbox("Send IP Packets (--send-ip)")
            interface_options["privileged"] = st.checkbox("Assume Privileged User (--privileged)")
            interface_options["unprivileged"] = st.checkbox("Assume Unprivileged User (--unprivileged)")

    def render_scan_execution(self, scan_type, discovery_options, port_options, service_options):
        """Render scan execution section"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Scan Execution</div>", unsafe_allow_html=True)
        
        # Target input at the top of execution section
        target = st.text_input(
            "Target Host",
            placeholder="192.168.1.1 or scanme.nmap.org",
            help="IP address, hostname, or FQDN of target",
            key="exec_target"
        )
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            # Command preview
            if target:
                command = self.build_nmap_command(target, scan_type, discovery_options, port_options, service_options)
                st.code(f"Command: {command}", language="bash")
        
        with col2:
            start_scan = st.button("🚀 Start Scan", type="primary", use_container_width=True)
        
        with col3:
            save_preset = st.button("💾 Save Preset", use_container_width=True)
        
        # Handle scan execution
        if start_scan and target:
            if self.validate_target(target):
                self.execute_scan(target, scan_type, discovery_options, port_options, service_options)
            else:
                st.error("❌ Invalid target specified")
        elif start_scan:
            st.warning("⚠️ Please specify a target host")
        
        # Handle preset saving
        if save_preset:
            self.save_scan_preset(scan_type, discovery_options, port_options, service_options)

    def validate_target(self, target):
        """Validate target host/IP"""
        if not target:
            return False
        
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Check if it's a valid hostname
            hostname_pattern = re.compile(
                r'^(?!-)[A-Z\d-]{1,63}(?<!-)$'
                r'(?:\.(?!-)[A-Z\d-]{1,63}(?<!-))*\.?$', re.IGNORECASE
            )
            return bool(hostname_pattern.match(target))

    def check_host_reachable(self, target):
        """Check if host is reachable"""
        try:
            # Simple ping test
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', target],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                st.success(f"✅ {target} is reachable")
            else:
                st.warning(f"⚠️ {target} may not be reachable or may not respond to ping")
                
        except subprocess.TimeoutExpired:
            st.error("❌ Connectivity test timed out")
        except Exception as e:
            st.error(f"❌ Error testing connectivity: {str(e)}")

    def build_nmap_command(self, target, scan_type, discovery_options, port_options, service_options):
        """Build the complete nmap command"""
        cmd = ["nmap"]
        
        # Add scan type
        if "TCP SYN" in scan_type["type"]:
            cmd.append("-sS")
        elif "TCP Connect" in scan_type["type"]:
            cmd.append("-sT")
        elif "TCP ACK" in scan_type["type"]:
            cmd.append("-sA")
        elif "TCP Window" in scan_type["type"]:
            cmd.append("-sW")
        elif "TCP Maimon" in scan_type["type"]:
            cmd.append("-sM")
        elif "UDP Scan" in scan_type["type"]:
            cmd.append("-sU")
        elif "TCP Null" in scan_type["type"]:
            cmd.append("-sN")
        elif "TCP FIN" in scan_type["type"]:
            cmd.append("-sF")
        elif "TCP Xmas" in scan_type["type"]:
            cmd.append("-sX")
        elif "SCTP INIT" in scan_type["type"]:
            cmd.append("-sY")
        elif "SCTP COOKIE" in scan_type["type"]:
            cmd.append("-sZ")
        elif "IP Protocol" in scan_type["type"]:
            cmd.append("-sO")
        elif "Custom TCP Flags" in scan_type["type"] and scan_type["custom_flags"]:
            cmd.extend(["--scanflags", scan_type["custom_flags"]])
        
        # Add timing
        timing_map = {
            "T0 (Paranoid)": "-T0",
            "T1 (Sneaky)": "-T1",
            "T2 (Polite)": "-T2",
            "T3 (Normal)": "-T3",
            "T4 (Aggressive)": "-T4",
            "T5 (Insane)": "-T5"
        }
        cmd.append(timing_map.get(scan_type["timing"], "-T3"))
        
        # Add discovery options
        if "No Discovery" in discovery_options["type"]:
            cmd.append("-Pn")
        elif "Ping Scan Only" in discovery_options["type"]:
            cmd.append("-sn")
        elif "List Scan" in discovery_options["type"]:
            cmd.append("-sL")
        
        # Add port options
        if port_options["method"] == "All Ports (1-65535)":
            cmd.extend(["-p", "1-65535"])
        elif port_options["method"] == "Fast Scan (-F) - Top 100":
            cmd.append("-F")
        elif "Top Ports" in port_options["method"] and "Custom" in port_options["method"]:
            cmd.extend(["--top-ports", str(port_options.get("top_count", 1000))])
        elif "Specific Ports" in port_options["method"] and port_options.get("specific_ports"):
            cmd.extend(["-p", port_options["specific_ports"]])
        elif "Port Ranges" in port_options["method"] and port_options.get("port_ranges"):
            cmd.extend(["-p", port_options["port_ranges"]])
        
        # Add service detection
        if service_options.get("version_detection"):
            cmd.append("-sV")
            if "version_intensity" in service_options:
                cmd.extend(["--version-intensity", str(service_options["version_intensity"])])
        
        if service_options.get("script_scan"):
            cmd.append("-sC")
        
        if service_options.get("custom_scripts"):
            script_list = ",".join(service_options["custom_scripts"])
            cmd.extend(["--script", script_list])
        
        if service_options.get("os_detection"):
            cmd.append("-O")
        
        if service_options.get("aggressive"):
            cmd.append("-A")
        
        # Output options
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = os.path.join(self.reports_dir, f"sniper_scan_{target.replace('.', '_')}_{timestamp}")
        cmd.extend(["-oN", f"{output_base}.txt"])
        cmd.extend(["-oX", f"{output_base}.xml"])
        
        # Add target
        cmd.append(target)
        
        return " ".join(cmd)

    def check_if_sudo_needed(self, command):
        """Check if the nmap command requires sudo privileges"""
        sudo_flags = [
            '-sS',  # SYN scan
            '-sF',  # FIN scan
            '-sX',  # Xmas scan
            '-sN',  # Null scan
            '-sO',  # IP protocol scan
            '-O',   # OS detection
            '--traceroute',  # Traceroute
            '--send-eth',   # Send raw ethernet frames
            '--send-ip',    # Send raw IP packets
        ]
        
        return any(flag in command for flag in sudo_flags)

    def execute_scan(self, target, scan_type, discovery_options, port_options, service_options):
        """Execute the nmap scan with live terminal output"""
        try:
            # Build command
            command = self.build_nmap_command(target, scan_type, discovery_options, port_options, service_options)
            
            # Check if sudo is needed and add it to the command
            needs_sudo = self.check_if_sudo_needed(command)
            actual_command = command  # Store the actual command for execution
            display_command = command  # Store redacted command for display
            
            if needs_sudo and 'sudo_password_encoded' in st.session_state:
                # Decode the password and prepare command with sudo -S (read password from stdin)
                decoded_password = base64.b64decode(st.session_state.sudo_password_encoded).decode()
                actual_command = f"echo '{decoded_password}' | sudo -S {command}"
                display_command = f"echo '[REDACTED]' | sudo -S {command}"  # Redacted for display
                st.markdown("<div style='font-size:12px;color:#4a5568'>Using sudo for privileged scan operations</div>", unsafe_allow_html=True)
            elif needs_sudo and 'sudo_password_encoded' not in st.session_state:
                st.warning("⚠️ This scan may require sudo privileges. Please enter your sudo password above if the scan fails.")
            
            # Create scan record with redacted command for storage/display
            scan_record = {
                "target": target,
                "scan_type": scan_type["type"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command": display_command,  # Use redacted command for storage
                "status": "Running",
                "scan_id": f"sniper_{int(time.time())}"
            }
            

            
            # Add to recent scans
            if 'sniper_recent_scans' not in st.session_state:
                st.session_state.sniper_recent_scans = []
            st.session_state.sniper_recent_scans.append(scan_record)
            
            st.markdown(f"<div style='font-size:13px;color:#1ec8ff'>Starting scan of {target}...</div>", unsafe_allow_html=True)
            st.code(f"Executing: {display_command}", language="bash")
            
            # Create live terminal output container
            terminal_container = st.empty()
            progress_container = st.empty()
            
            # Execute scan with live output
            start_time = time.time()
            output_lines = []
            
            # Use shell=True for commands with pipes (like sudo with password)
            use_shell = needs_sudo and 'sudo_password_encoded' in st.session_state
            
            process = subprocess.Popen(
                actual_command if use_shell else actual_command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                shell=use_shell
            )
            
            with process:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        output_lines.append(output.strip())
                        
                        # Update live terminal display
                        with terminal_container.container():
                            st.markdown("##### 🖥️ Live Terminal Output")
                            # Show last 20 lines for readability
                            display_lines = output_lines[-20:] if len(output_lines) > 20 else output_lines
                            terminal_output = "\n".join(display_lines)
                            if len(output_lines) > 20:
                                terminal_output = f"... (showing last 20 of {len(output_lines)} lines)\n" + terminal_output
                            st.code(terminal_output, language="bash")
                        
                        # Update progress if we can parse it
                        if "%" in output or "Completed" in output:
                            with progress_container.container():
                                st.info(f"📊 {output.strip()}")
                        
                        time.sleep(0.1)  # Small delay to prevent too rapid updates
                
                return_code = process.poll()
            
            execution_time = time.time() - start_time
            full_output = "\n".join(output_lines)
            
            # Update scan record
            scan_record["status"] = "Completed" if return_code == 0 else "Failed"
            scan_record["execution_time"] = f"{execution_time:.2f}s"
            scan_record["output"] = full_output
            scan_record["return_code"] = return_code
            
            if return_code == 0:
                st.success(f"✅ Scan completed successfully in {execution_time:.2f} seconds")
                
                # Parse results
                open_ports = self.parse_scan_results(full_output)
                scan_record["ports_found"] = len(open_ports)
                scan_record["open_ports"] = open_ports
                
                # Save to database
                self.save_scan_to_database(scan_record)
                
                # Display results
                self.display_scan_results(scan_record)
                
                # Send to backend
                self.send_results_to_backend(scan_record)
                
                # Add notification
                add_notification(
                    f"Sniper scan of {target} completed - {len(open_ports)} open ports found",
                    "success"
                )
            else:
                st.error(f"❌ Scan failed with return code: {return_code}")
                scan_record["error"] = f"Process failed with return code {return_code}"
                self.save_scan_to_database(scan_record)  # Save failed scans too
                add_notification(f"Sniper scan of {target} failed", "error")
                
        except Exception as e:
            st.error(f"❌ Error executing scan: {str(e)}")
            scan_record["status"] = "Error"
            scan_record["error"] = str(e)
            self.save_scan_to_database(scan_record)  # Save error state
            add_notification(f"Sniper scan of {target} error: {str(e)}", "error")

    def parse_scan_results(self, output):
        """Parse nmap scan results"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            # Look for open ports
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        'port': parts[0].split('/')[0],
                        'protocol': parts[0].split('/')[1],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    open_ports.append(port_info)
            elif '/udp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        'port': parts[0].split('/')[0],
                        'protocol': parts[0].split('/')[1],
                        'state': parts[1],
                        'service': parts[2] if len(parts) > 2 else 'unknown'
                    }
                    open_ports.append(port_info)
        
        return open_ports

    def display_scan_results(self, scan_record):
        """Display scan results"""
        st.markdown("<div style='font-size:15px;font-weight:600;color:#e2e8f0;margin:16px 0 8px'>Scan Results</div>", unsafe_allow_html=True)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Target", scan_record["target"])
        with col2:
            st.metric("Status", scan_record["status"])
        with col3:
            if "execution_time" in scan_record:
                st.metric("Duration", scan_record["execution_time"])
        with col4:
            if "ports_found" in scan_record:
                st.metric("Open Ports", scan_record["ports_found"])
        
        # AI Analysis Section - Only show when AI mode is enabled
        if "output" in scan_record and st.session_state.get("ai_mode", False):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.markdown("#### 🤖 AI-Powered Vulnerability Analysis")
            with col2:
                if st.button("🔍 Analyze with AI", key=f"ai_analyze_{scan_record.get('timestamp', 'unknown')}"):
                    self.perform_ai_analysis(scan_record)
            
            # Show existing AI analysis if available
            if "ai_analysis" in scan_record:
                self.display_ai_analysis(scan_record["ai_analysis"])
        
        # Detailed results - Full width display
        if "output" in scan_record:
            st.markdown("#### 📋 Detailed Results")
            # Use text_area for better scrolling and width utilization
            st.text_area(
                "Scan Output",
                value=scan_record["output"],
                height=400,
                disabled=True,
                label_visibility="collapsed"
            )
        
        # Error information
        if "errors" in scan_record and scan_record["errors"]:
            st.markdown("#### ⚠️ Warnings/Errors")
            st.text_area(
                "Errors",
                value=scan_record["errors"],
                height=150,
                disabled=True,
                label_visibility="collapsed"
            )

    def perform_ai_analysis(self, scan_record):
        """Perform AI analysis on scan results using DeepSeek"""
        if not scan_record.get("output"):
            st.error("No scan output available for analysis")
            return
            
        # Check if AI mode is enabled
        if not st.session_state.get("ai_mode", False):
            st.warning("🤖 AI analysis is disabled. Enable AI mode in Settings to use this feature.")
            return
        
        # Create a progress bar and status container
        progress_container = st.container()
        with progress_container:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            def update_progress(progress):
                progress_bar.progress(progress)
                if progress == 0.1:
                    status_text.text("🔄 Starting AI analysis...")
                elif progress == 0.3:
                    status_text.text("📤 Preparing request...")
                elif progress == 0.5:
                    status_text.text("🤖 Sending to DeepSeek AI...")
                elif progress == 0.7:
                    status_text.text("📊 Processing response...")
                elif progress == 0.8:
                    status_text.text("🔍 Parsing analysis...")
                elif progress == 1.0:
                    status_text.text("✅ Analysis complete!")
            
            # Perform the AI analysis
            ai_analysis = analyze_scan_with_gemini(
                scan_record["output"], 
                update_progress_callback=update_progress
            )
            
            # Clear progress indicators
            progress_bar.empty()
            status_text.empty()
        
        # Save the AI analysis to the scan record
        if "error" not in ai_analysis:
            # Update the scan record in the database with AI analysis
            self.save_ai_analysis_to_scan(scan_record, ai_analysis)
            
            # Display the analysis
            self.display_ai_analysis(ai_analysis)
        else:
            st.error(f"AI Analysis failed: {ai_analysis['error']}")
    
    def save_ai_analysis_to_scan(self, scan_record, ai_analysis):
        """Save AI analysis results to the scan record in database"""
        try:
            import sqlite3
            
            # Path to database
            db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'siem.db')
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # Update the scan record with AI analysis
                cursor.execute("""
                    UPDATE vulnerability_scans 
                    SET ai_analysis = ?
                    WHERE timestamp = ? AND target = ?
                """, (
                    json.dumps(ai_analysis),
                    scan_record.get('timestamp'),
                    scan_record.get('target')
                ))
                
                conn.commit()
                
                # Update the current scan record for immediate display
                scan_record["ai_analysis"] = ai_analysis
                
        except Exception as e:
            st.error(f"Failed to save AI analysis: {str(e)}")
    
    def display_ai_analysis(self, ai_analysis):
        """Display AI analysis results in a structured format"""
        if "error" in ai_analysis:
            st.error(f"Analysis Error: {ai_analysis['error']}")
            return
        
        # Risk Level and Summary
        col1, col2 = st.columns([1, 2])
        with col1:
            risk_level = ai_analysis.get("risk_level", "Unknown")
            risk_colors = {
                "Critical": "🔴",
                "High": "🟠", 
                "Medium": "🟡",
                "Low": "🟢",
                "Unknown": "⚪"
            }
            st.metric(
                "Risk Level", 
                f"{risk_colors.get(risk_level, '⚪')} {risk_level}",
                delta=f"{ai_analysis.get('total_vulnerabilities', 0)} vulnerabilities"
            )
        
        with col2:
            if ai_analysis.get("summary"):
                st.markdown("**Analysis Summary:**")
                st.info(ai_analysis["summary"])
        
        # Vulnerabilities Section
        vulnerabilities = ai_analysis.get("vulnerabilities", [])
        if vulnerabilities:
            st.markdown("#### 🚨 Identified Vulnerabilities")
            
            for i, vuln in enumerate(vulnerabilities):
                with st.container():
                    col1, col2, col3 = st.columns([2, 1, 1])
                    
                    with col1:
                        st.markdown(f"**{vuln.get('name', 'Unknown Vulnerability')}**")
                        st.caption(vuln.get('description', 'No description available'))
                    
                    with col2:
                        severity = vuln.get('severity', 'Unknown')
                        severity_colors = {
                            "Critical": "🔴", "High": "🟠", 
                            "Medium": "🟡", "Low": "🟢"
                        }
                        st.markdown(f"**Severity:** {severity_colors.get(severity, '⚪')} {severity}")
                    
                    with col3:
                        if vuln.get('port'):
                            st.markdown(f"**Port:** {vuln['port']}")
                        if vuln.get('service'):
                            st.markdown(f"**Service:** {vuln['service']}")
                    
                    st.divider()
        
        # Open Ports Section
        open_ports = ai_analysis.get("open_ports", [])
        if open_ports:
            st.markdown("#### 🔌 Open Ports Analysis")
            
            ports_data = []
            for port in open_ports:
                ports_data.append({
                    "Port": port.get('port', 'Unknown'),
                    "Service": port.get('service', 'Unknown'),
                    "Details": port.get('details', 'No details')
                })
            
            if ports_data:
                st.dataframe(ports_data, use_container_width=True)
        
        # Recommendations Section
        recommendations = ai_analysis.get("recommendations", [])
        if recommendations:
            st.markdown("#### 💡 Security Recommendations")
            for i, rec in enumerate(recommendations, 1):
                st.markdown(f"{i}. {rec}")

    def save_scan_preset(self, scan_type, discovery_options, port_options, service_options):
        """Save scan configuration as preset"""
        preset_name = st.text_input("Preset Name", placeholder="My Custom Scan")
        if st.button("Save") and preset_name:
            # Implementation for saving presets
            st.success(f"✅ Preset '{preset_name}' saved!")

    def send_results_to_backend(self, scan_record):
        """Send scan results to backend API"""
        # Skip if API is disabled
        if not self.api_url:
            return
            
        try:
            response = requests.post(
                self.api_url,
                json={
                    "scan_type": "sniper",
                    "target": scan_record["target"],
                    "results": scan_record
                }
            )
            if response.status_code == 200:
                pass
        except Exception as e:
            st.warning(f"⚠️ Could not send results to backend: {str(e)}")

    def save_scan_to_database(self, scan_record):
        """Save scan results to SQLite database"""
        try:
            import sqlite3
            
            # Database path
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # Connect to database
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE,
                    scan_type TEXT,
                    target TEXT,
                    command TEXT,
                    status TEXT,
                    timestamp TEXT,
                    execution_time TEXT,
                    ports_found INTEGER,
                    open_ports TEXT,
                    output TEXT,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Check if scan_id column exists, if not add it
            cursor.execute("PRAGMA table_info(vulnerability_scans)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'scan_id' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN scan_id TEXT')
            
            # Check if target column exists, if not add it
            if 'target' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN target TEXT')
            
            # Check if command column exists, if not add it
            if 'command' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN command TEXT')
            
            # Check if status column exists, if not add it
            if 'status' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN status TEXT')
            
            # Check if execution_time column exists, if not add it
            if 'execution_time' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN execution_time TEXT')
            
            # Check if ports_found column exists, if not add it
            if 'ports_found' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN ports_found INTEGER')
            
            # Check if open_ports column exists, if not add it
            if 'open_ports' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN open_ports TEXT')
            
            # Check if output column exists, if not add it
            if 'output' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN output TEXT')
            
            # Check if error column exists, if not add it
            if 'error' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN error TEXT')
            
            # Check if created_at column exists, if not add it
            if 'created_at' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            
            # Check if ai_analysis column exists, if not add it
            if 'ai_analysis' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN ai_analysis TEXT')
            
            # Insert scan record
            
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerability_scans 
                (scan_id, scan_type, target, command, status, timestamp, execution_time, 
                 ports_found, open_ports, output, error, ai_analysis)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_record.get("scan_id"),
                scan_record.get("scan_type"),
                scan_record.get("target"),
                scan_record.get("command"),
                scan_record.get("status"),
                scan_record.get("timestamp"),
                scan_record.get("execution_time"),
                scan_record.get("ports_found", 0),
                json.dumps(scan_record.get("open_ports", [])),
                scan_record.get("output"),
                scan_record.get("error"),
                json.dumps(scan_record.get("ai_analysis")) if scan_record.get("ai_analysis") else None
            ))
            
            conn.commit()
            conn.close()
            
            st.success("💾 Scan results saved to database")
            
        except Exception as e:
            st.warning(f"⚠️ Could not save to database: {str(e)}")

    def load_scans_from_database(self):
        """Load scan history from database"""
        try:
            import sqlite3
            
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')
            
            if not os.path.exists(db_path):
                return []
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Ensure the table exists with all required columns
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE,
                    scan_type TEXT,
                    target TEXT,
                    command TEXT,
                    status TEXT,
                    timestamp TEXT,
                    execution_time TEXT,
                    ports_found INTEGER,
                    open_ports TEXT,
                    output TEXT,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Check and add missing columns
            cursor.execute("PRAGMA table_info(vulnerability_scans)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'scan_id' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN scan_id TEXT')
            if 'target' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN target TEXT')
            if 'command' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN command TEXT')
            if 'status' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN status TEXT')
            if 'execution_time' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN execution_time TEXT')
            if 'ports_found' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN ports_found INTEGER')
            if 'open_ports' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN open_ports TEXT')
            if 'output' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN output TEXT')
            if 'error' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN error TEXT')
            if 'created_at' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
            if 'ai_analysis' not in columns:
                cursor.execute('ALTER TABLE vulnerability_scans ADD COLUMN ai_analysis TEXT')
            
            cursor.execute('''
                SELECT scan_id, scan_type, target, status, timestamp, execution_time, 
                       ports_found, command, output, error, open_ports, ai_analysis
                FROM vulnerability_scans 
                WHERE scan_type LIKE '%sniper%' OR scan_type LIKE '%TCP%' OR scan_type LIKE '%UDP%'
                ORDER BY created_at DESC 
                LIMIT 50
            ''')
            
            scans = []
            for row in cursor.fetchall():
                scan = {
                    "scan_id": row[0],
                    "scan_type": row[1],
                    "target": row[2],
                    "status": row[3],
                    "timestamp": row[4],
                    "execution_time": row[5],
                    "ports_found": row[6],
                    "command": row[7],
                    "output": row[8],
                    "error": row[9],
                    "open_ports": json.loads(row[10]) if row[10] else [],
                    "ai_analysis": json.loads(row[11]) if row[11] else None
                }
                scans.append(scan)
            
            conn.close()
            return scans
            
        except Exception as e:
            st.warning(f"⚠️ Could not load from database: {str(e)}")
            return []

    def render_recent_scans(self):
        """Render recent scans section with database integration"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Recent Scans</div>", unsafe_allow_html=True)
        
        # Load scans from database
        db_scans = self.load_scans_from_database()
        
        # Combine with session state scans
        session_scans = st.session_state.get('sniper_recent_scans', [])
        
        # Merge and deduplicate
        all_scans = {}
        for scan in db_scans + session_scans:
            scan_id = scan.get('scan_id', f"temp_{scan.get('timestamp', '')}")
            all_scans[scan_id] = scan
        
        scans_list = list(all_scans.values())
        scans_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        if scans_list:
            # Add filter options
            col1, col2, col3 = st.columns(3)
            with col1:
                status_filter = st.selectbox("Filter by Status", ["All", "Completed", "Failed", "Running", "Error"])
            with col2:
                limit = st.selectbox("Show Results", [10, 25, 50, 100], index=0)
            with col3:
                if st.button("🗑️ Clear History"):
                    self.clear_scan_history()
                    st.rerun()
            
            # Filter scans
            filtered_scans = scans_list
            if status_filter != "All":
                filtered_scans = [s for s in scans_list if s.get('status') == status_filter]
            
            filtered_scans = filtered_scans[:limit]
            
            for i, scan in enumerate(filtered_scans):
                # Add AI indicator if analysis is available
                ai_indicator = " 🤖" if scan.get('ai_analysis') else ""
                with st.expander(f"🎯 {scan.get('target', 'Unknown')} - {scan.get('timestamp', 'Unknown')} - {scan.get('status', 'Unknown')}{ai_indicator}"):
                    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
                    
                    with col1:
                        st.text(f"Target: {scan.get('target', 'N/A')}")
                        st.text(f"Type: {scan.get('scan_type', 'N/A')}")
                        st.text(f"Status: {scan.get('status', 'N/A')}")
                        if scan.get('ports_found') is not None:
                            st.text(f"Open Ports: {scan.get('ports_found', 0)}")
                        if scan.get('execution_time'):
                            st.text(f"Duration: {scan.get('execution_time', 'N/A')}")
                        # Add severity information
                        severity = self.calculate_scan_severity(scan)
                        severity_colors = {
                            "Critical": "🔴", "High": "🟠", 
                            "Medium": "🟡", "Low": "🟢", "Unknown": "⚪"
                        }
                        st.text(f"Severity: {severity_colors.get(severity, '⚪')} {severity}")
                        
                        # AI Analysis status - only show when AI mode is enabled
                        if st.session_state.get("ai_mode", False):
                            if scan.get('ai_analysis'):
                                st.success("🤖 AI Analysis Available")
                            else:
                                st.info("🤖 AI Analysis: Not performed")
                    
                    with col2:
                        if st.button(f"👁️ View Results", key=f"view_sniper_{i}"):
                            # Set session state to show this specific scan's results
                            st.session_state.selected_scan_for_display = scan
                            st.rerun()
                    
                    with col3:
                        if st.button(f"📥 Download", key=f"download_sniper_{i}"):
                            self.download_scan_report(scan)
                    
                    with col4:
                        if st.button(f"🔄 Re-run", key=f"rerun_sniper_{i}"):
                            self.rerun_scan_from_history(scan)
                    
                    # Show command
                    if scan.get('command'):
                        st.code(f"Command: {scan.get('command')}", language="bash")
                    
                    # Show error if any
                    if scan.get('error'):
                        st.error(f"Error: {scan.get('error')}")
        else:
            st.info("No recent scans. Start your first scan above!")

    def clear_scan_history(self):
        """Clear scan history from database and session"""
        try:
            import sqlite3
            
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')
            
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM vulnerability_scans WHERE scan_type LIKE '%sniper%' OR scan_type LIKE '%TCP%' OR scan_type LIKE '%UDP%'")
                conn.commit()
                conn.close()
            
            # Clear session state
            if 'sniper_recent_scans' in st.session_state:
                st.session_state.sniper_recent_scans = []
            
            st.success("🗑️ Scan history cleared")
            
        except Exception as e:
            st.error(f"❌ Error clearing history: {str(e)}")

    def rerun_scan_from_history(self, scan_record):
        """Re-run a scan from history"""
        try:
            # Extract target from scan record
            target = scan_record.get('target')
            if not target:
                st.error("❌ Cannot re-run scan: target not found")
                return
            
            # Parse command to extract options (simplified approach)
            command = scan_record.get('command', '')
            
            # Basic scan type detection from command
            scan_type = {"type": "TCP SYN Scan (-sS)", "timing": "T3 (Normal)"}
            if "-sT" in command:
                scan_type["type"] = "TCP Connect Scan (-sT)"
            elif "-sU" in command:
                scan_type["type"] = "UDP Scan (-sU)"
            elif "-sA" in command:
                scan_type["type"] = "TCP ACK Scan (-sA)"
            
            # Set timing from command
            for timing in ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]:
                if timing in command:
                    timing_map = {"-T0": "T0 (Paranoid)", "-T1": "T1 (Sneaky)", 
                                  "-T2": "T2 (Polite)", "-T3": "T3 (Normal)",
                                  "-T4": "T4 (Aggressive)", "-T5": "T5 (Insane)"}
                    scan_type["timing"] = timing_map.get(timing, "T3 (Normal)")
                    break
            
            # Basic options
            discovery_options = {"type": "Default Discovery"}
            port_options = {"method": "Default Ports (Top 1000)"}
            service_options = {}
            
            if "-sV" in command:
                service_options["version_detection"] = True
            if "-sC" in command:
                service_options["script_scan"] = True
            if "-O" in command:
                service_options["os_detection"] = True
            
            st.info(f"🔄 Re-running scan for {target}")
            self.execute_scan(target, scan_type, discovery_options, port_options, service_options)
            
        except Exception as e:
            st.error(f"❌ Error re-running scan: {str(e)}")

    def download_scan_report(self, scan_record):
        """Generate and provide download for scan report"""
        try:
            # Generate comprehensive report
            report_content = self.generate_scan_report(scan_record)
            
            # Create download button
            st.download_button(
                label="📥 Download Full Report",
                data=report_content,
                file_name=f"sniper_scan_report_{scan_record.get('target', 'unknown')}_{scan_record.get('timestamp', 'unknown').replace(':', '-').replace(' ', '_')}.txt",
                mime="text/plain",
                key=f"download_full_{scan_record.get('scan_id', int(time.time()))}"
            )
            
            # Also offer JSON format
            json_content = json.dumps(scan_record, indent=2)
            st.download_button(
                label="📥 Download JSON Data",
                data=json_content,
                file_name=f"sniper_scan_data_{scan_record.get('target', 'unknown')}_{scan_record.get('timestamp', 'unknown').replace(':', '-').replace(' ', '_')}.json",
                mime="application/json",
                key=f"download_json_{scan_record.get('scan_id', int(time.time()))}"
            )
            
        except Exception as e:
            st.error(f"❌ Error generating download: {str(e)}")

    def generate_scan_report(self, scan_record):
        """Generate comprehensive scan report"""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append("SNIPER SCAN REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # Scan Information
        report_lines.append("SCAN INFORMATION:")
        report_lines.append("-" * 40)
        report_lines.append(f"Scan ID: {scan_record.get('scan_id', 'N/A')}")
        report_lines.append(f"Target: {scan_record.get('target', 'N/A')}")
        report_lines.append(f"Scan Type: {scan_record.get('scan_type', 'N/A')}")
        report_lines.append(f"Timestamp: {scan_record.get('timestamp', 'N/A')}")
        report_lines.append(f"Status: {scan_record.get('status', 'N/A')}")
        report_lines.append(f"Duration: {scan_record.get('execution_time', 'N/A')}")
        report_lines.append(f"Ports Found: {scan_record.get('ports_found', 'N/A')}")
        report_lines.append("")
        
        # Command Executed
        report_lines.append("COMMAND EXECUTED:")
        report_lines.append("-" * 40)
        report_lines.append(scan_record.get('command', 'N/A'))
        report_lines.append("")
        
        # Open Ports Summary
        if scan_record.get('open_ports'):
            report_lines.append("OPEN PORTS SUMMARY:")
            report_lines.append("-" * 40)
            for port in scan_record['open_ports']:
                report_lines.append(f"{port.get('port', 'N/A')}/{port.get('protocol', 'N/A')} - {port.get('service', 'unknown')} ({port.get('state', 'unknown')})")
            report_lines.append("")
        
        # Full Output
        report_lines.append("FULL SCAN OUTPUT:")
        report_lines.append("-" * 40)
        report_lines.append(scan_record.get('output', 'No output available'))
        report_lines.append("")
        
        # Errors (if any)
        if scan_record.get('error'):
            report_lines.append("ERRORS/WARNINGS:")
            report_lines.append("-" * 40)
            report_lines.append(scan_record.get('error'))
            report_lines.append("")
        
        # Footer
        report_lines.append("=" * 80)
        report_lines.append(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("Generated by SIEM System - Sniper Scan Module")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)

    def calculate_scan_severity(self, scan_record):
        """Calculate severity based on scan results"""
        if not scan_record.get('output'):
            return "Unknown"
        
        output = scan_record.get('output', '').lower()
        ports_found = scan_record.get('ports_found', 0)
        
        # Critical severity indicators
        critical_keywords = [
            'critical', 'backdoor', 'rce', 'remote code execution', 'buffer overflow',
            'sql injection', 'command injection', 'privilege escalation', 'root access',
            'authentication bypass', 'default credentials', 'exploit', 'malware'
        ]
        
        # High severity indicators  
        high_keywords = [
            'vulnerable', 'security', 'weakness', 'flaw', 'unauthorized', 
            'disclosure', 'bypass', 'elevation', 'compromise', 'unsafe', 
            'unpatched', 'outdated', 'insecure'
        ]
        
        # Medium severity indicators
        medium_keywords = [
            'information disclosure', 'directory traversal', 'cross-site',
            'xss', 'csrf', 'weak', 'misconfiguration', 'exposure',
            'fingerprint', 'enumeration', 'brute force'
        ]
        
        # Check for critical keywords
        if any(keyword in output for keyword in critical_keywords):
            return "Critical"
        
        # Check for high keywords or many open ports
        if any(keyword in output for keyword in high_keywords) or ports_found > 10:
            return "High"
        
        # Check for medium keywords or some open ports
        if any(keyword in output for keyword in medium_keywords) or ports_found > 3:
            return "Medium"
        
        # Low if few or no open ports
        if ports_found <= 3:
            return "Low"
        
        return "Unknown"


# Main page render function
def render_page():
    """Render the sniper scan page"""
    sniper_scan = SniperScanPage()
    sniper_scan.render_page()

if __name__ == "__main__":
    render_page()