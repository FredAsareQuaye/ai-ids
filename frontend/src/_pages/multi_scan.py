import streamlit as st
import subprocess
import json
import re
import time
import os
import tempfile
import xml.etree.ElementTree as ET
import ipaddress
from datetime import datetime
import traceback
import requests  # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
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

class MultiScanPage:
    def __init__(self):
        # Path to output directory for reports
        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
            
        # API endpoint for scan results
        # API endpoint for scan results - set to None to disable backend calls
        self.api_url = None  # "http://localhost:5000/api/vulnerability/scan"
        
        # Initialize session state for advanced options
        if 'multi_advanced_options' not in st.session_state:
            st.session_state.multi_advanced_options = False
    
    def render_page(self):
        """Render the enhanced Multi-Scan page"""
        # Add back button at the top
        col1, col2 = st.columns([2, 7])
        with col1:
            if st.button("← Back to Overview", key="back_to_overview_multi", use_container_width=True):
                st.session_state.view = "vuln_overview"
                st.rerun()
        
        from components.page_style import inject_page_css, page_header
        inject_page_css()
        page_header("Multi-Target Scan", "Network range and subnet vulnerability assessment via Nmap", badge="Network Range")
        
        # Quick preset or advanced configuration toggle
        col1, col2 = st.columns([3, 1])
        with col1:
            pass
        with col2:
            if st.button("Advanced options", help="Toggle advanced nmap configuration"):
                st.session_state.multi_advanced_options = not st.session_state.multi_advanced_options
        
        # Target specification section
        target_config = self.render_target_section()
        
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
        if st.session_state.multi_advanced_options:
            self.render_advanced_options()
            st.markdown("---")
        
        # Scan execution section
        self.render_scan_execution(target_config, scan_type, discovery_options, port_options, service_options)
        
        # Recent scans section
        self.render_recent_scans()

    def render_target_section(self):
        """Render enhanced target specification section for multi-scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Target Specification</div>", unsafe_allow_html=True)
        
        # Target specification method
        target_method = st.selectbox(
            "Target Specification Method",
            [
                "Single Network/Subnet",
                "Multiple Individual Hosts",
                "Host List from File",
                "IP Range",
                "Custom Nmap Target Format"
            ],
            help="Choose how to specify multiple targets"
        )
        
        target_config = {"method": target_method}
        
        if target_method == "Single Network/Subnet":
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                target_config["subnet"] = st.text_input(
                    "Network/Subnet",
                    placeholder="192.168.1.0/24 or 10.0.0.0/16",
                    help="CIDR notation network"
                )
            with col2:
                if st.button("🔍 Validate Subnet"):
                    if target_config.get("subnet"):
                        if self.validate_subnet(target_config["subnet"]):
                            st.success("✅ Valid subnet")
                        else:
                            st.error("❌ Invalid subnet")
            with col3:
                if st.button("📊 Count Hosts"):
                    if target_config.get("subnet"):
                        count = self.count_hosts_in_subnet(target_config["subnet"])
                        if count:
                            st.info(f"📊 {count} hosts")
        
        elif target_method == "Multiple Individual Hosts":
            target_config["hosts"] = st.text_area(
                "Host List (one per line or comma-separated)",
                placeholder="192.168.1.1\n192.168.1.10\n192.168.1.20\nor\n192.168.1.1,192.168.1.10,192.168.1.20",
                help="Enter multiple IP addresses or hostnames"
            )
            
            if target_config.get("hosts"):
                hosts = self.parse_host_list(target_config["hosts"])
                st.info(f"📊 {len(hosts)} hosts specified")
        
        elif target_method == "Host List from File":
            uploaded_file = st.file_uploader(
                "Upload Host List File",
                type=['txt', 'csv'],
                help="Text file with one host per line"
            )
            if uploaded_file:
                hosts = uploaded_file.read().decode().strip().split('\n')
                target_config["file_hosts"] = [h.strip() for h in hosts if h.strip()]
                st.info(f"📊 {len(target_config['file_hosts'])} hosts loaded from file")
        
        elif target_method == "IP Range":
            col1, col2 = st.columns(2)
            with col1:
                target_config["start_ip"] = st.text_input("Start IP", placeholder="192.168.1.1")
            with col2:
                target_config["end_ip"] = st.text_input("End IP", placeholder="192.168.1.100")
            
            if target_config.get("start_ip") and target_config.get("end_ip"):
                try:
                    start = ipaddress.ip_address(target_config["start_ip"])
                    end = ipaddress.ip_address(target_config["end_ip"])
                    count = int(end) - int(start) + 1
                    st.info(f"📊 {count} hosts in range")
                except:
                    st.error("❌ Invalid IP range")
        
        elif target_method == "Custom Nmap Target Format":
            target_config["custom"] = st.text_input(
                "Nmap Target Format",
                placeholder="192.168.1.1-20,192.168.2.1/24",
                help="Use nmap target format (ranges, wildcards, etc.)"
            )
        
        # Exclusions
        st.markdown("##### 🚫 Target Exclusions")
        col1, col2 = st.columns(2)
        with col1:
            target_config["exclude_hosts"] = st.text_input(
                "Exclude Hosts",
                placeholder="192.168.1.1,192.168.1.10",
                help="Hosts to exclude from scanning"
            )
        with col2:
            target_config["exclude_file"] = st.file_uploader(
                "Exclude List File",
                type=['txt'],
                help="File with hosts to exclude"
            )
        
        return target_config

    def render_scan_techniques(self):
        """Render scan techniques section optimized for multi-target scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Scan Techniques</div>", unsafe_allow_html=True)
        
        # Scan presets for multi-scanning
        scan_preset = st.selectbox(
            "Scan Preset",
            [
                "Custom Configuration",
                "Quick Network Discovery",
                "Comprehensive Port Scan",
                "Stealth Reconnaissance", 
                "Service Enumeration",
                "Vulnerability Assessment",
                "Performance Optimized"
            ],
            help="Pre-configured scan templates optimized for network scanning"
        )
        
        if scan_preset != "Custom Configuration":
            return self.get_preset_configuration(scan_preset)
        
        # Custom configuration
        scan_type = st.selectbox(
            "Primary Scan Type",
            [
                "TCP SYN Scan (-sS) [Default]",
                "TCP Connect Scan (-sT)",
                "TCP ACK Scan (-sA)",
                "UDP Scan (-sU)",
                "TCP SYN + UDP Combo",
                "Ping Scan Only (-sn)",
                "List Scan (-sL)"
            ],
            help="Choose the primary scanning technique"
        )
        
        # Timing template (important for network scans)
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
            help="Scan timing and performance template - higher values are faster but more detectable"
        )
        
        # Parallel scanning options
        col1, col2 = st.columns(2)
        with col1:
            max_hostgroup = st.number_input(
                "Max Host Group Size",
                min_value=1,
                max_value=256,
                value=64,
                help="Maximum number of hosts scanned in parallel"
            )
        with col2:
            max_parallelism = st.number_input(
                "Max Port Parallelism",
                min_value=1,
                max_value=100,
                value=10,
                help="Maximum parallel port scans per host"
            )
        
        return {
            "preset": scan_preset,
            "type": scan_type,
            "timing": timing,
            "max_hostgroup": max_hostgroup,
            "max_parallelism": max_parallelism
        }

    def render_host_discovery(self):
        """Render host discovery options optimized for network scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Host Discovery</div>", unsafe_allow_html=True)
        
        discovery_options = {}
        
        # Discovery strategy
        discovery_strategy = st.selectbox(
            "Discovery Strategy",
            [
                "Default Discovery (ICMP + TCP)",
                "Aggressive Discovery (Multiple Probes)",
                "Stealth Discovery (TCP Only)",
                "No Discovery (-Pn) - Assume all hosts up",
                "Ping Scan Only (-sn) - No port scan"
            ],
            help="Host discovery approach for network scanning"
        )
        discovery_options["strategy"] = discovery_strategy
        
        # Custom discovery probes (for advanced users)
        if st.checkbox("Custom Discovery Configuration"):
            col1, col2 = st.columns(2)
            with col1:
                discovery_options["tcp_syn_ports"] = st.text_input(
                    "TCP SYN Discovery Ports (-PS)",
                    placeholder="22,80,443,8080",
                    help="Ports for TCP SYN discovery"
                )
                discovery_options["tcp_ack_ports"] = st.text_input(
                    "TCP ACK Discovery Ports (-PA)", 
                    placeholder="80,443"
                )
                discovery_options["icmp_echo"] = st.checkbox("ICMP Echo (-PE)", value=True)
                discovery_options["icmp_timestamp"] = st.checkbox("ICMP Timestamp (-PP)")
            with col2:
                discovery_options["udp_ports"] = st.text_input(
                    "UDP Discovery Ports (-PU)",
                    placeholder="53,67,123,161"
                )
                discovery_options["icmp_netmask"] = st.checkbox("ICMP Netmask (-PM)")
                discovery_options["arp_discovery"] = st.checkbox("ARP Discovery (-PR)", value=True, help="Use ARP for local network")
        
        # DNS options for network scanning
        col1, col2 = st.columns(2)
        with col1:
            discovery_options["dns_resolution"] = st.selectbox(
                "DNS Resolution",
                ["Default", "Never resolve (-n)", "Always resolve (-R)"],
                help="DNS resolution strategy"
            )
        with col2:
            discovery_options["reverse_dns"] = st.checkbox(
                "Reverse DNS Lookup",
                value=True,
                help="Perform reverse DNS lookups"
            )
        
        return discovery_options

    def render_port_specification(self):
        """Render port specification optimized for network scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Port Specification</div>", unsafe_allow_html=True)
        
        port_options = {}
        
        # Port scanning strategy
        port_strategy = st.selectbox(
            "Port Scanning Strategy",
            [
                "Top 1000 Ports (Default)",
                "Top 100 Ports (Fast)",
                "Top 10000 Ports (Comprehensive)",
                "All Ports (1-65535) - Very Slow",
                "Common Service Ports",
                "Custom Port List",
                "Service-Specific Ports"
            ],
            help="Port selection strategy for network scanning"
        )
        port_options["strategy"] = port_strategy
        
        # Strategy-specific options
        if "Top" in port_strategy and "Custom" not in port_strategy:
            # Extract number from strategy string
            if "100" in port_strategy:
                port_options["top_ports"] = 100
            elif "10000" in port_strategy:
                port_options["top_ports"] = 10000
            else:
                port_options["top_ports"] = 1000
        
        elif port_strategy == "Custom Port List":
            port_options["custom_ports"] = st.text_input(
                "Port List",
                placeholder="22,80,443,8080,3389",
                help="Comma-separated list of ports"
            )
        
        elif port_strategy == "Service-Specific Ports":
            services = st.multiselect(
                "Service Categories",
                [
                    "Web (80,443,8080,8443)",
                    "SSH/Telnet (22,23)",
                    "FTP (20,21)",
                    "Mail (25,110,143,993,995)",
                    "DNS (53)",
                    "Database (1433,3306,5432,1521)",
                    "Remote Access (3389,5900,5901)",
                    "File Sharing (139,445,2049)",
                    "SNMP (161,162)",
                    "Common High Ports (8000-9000)"
                ]
            )
            port_options["service_ports"] = services
        
        # Protocol selection
        col1, col2 = st.columns(2)
        with col1:
            port_options["tcp_scan"] = st.checkbox("TCP Scan", value=True)
        with col2:
            port_options["udp_scan"] = st.checkbox("UDP Scan (Slower)", help="UDP scanning is significantly slower")
        
        # Port scan optimization
        if st.checkbox("Port Scan Optimization"):
            col1, col2 = st.columns(2)
            with col1:
                port_options["random_order"] = st.checkbox("Random Port Order", value=True)
                port_options["fast_scan"] = st.checkbox("Fast Scan (-F)")
            with col2:
                port_options["top_ports_custom"] = st.number_input(
                    "Custom Top Ports Count",
                    min_value=1,
                    max_value=65535,
                    value=1000,
                    help="Number of most common ports to scan"
                )
        
        return port_options

    def render_service_detection(self):
        """Render service detection options for network scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Service Detection</div>", unsafe_allow_html=True)
        
        service_options = {}
        
        # Service detection level
        detection_level = st.selectbox(
            "Detection Level",
            [
                "None - Port states only",
                "Basic - Service names",
                "Standard - Service + version detection",
                "Aggressive - Full service enumeration",
                "Custom Configuration"
            ],
            help="Level of service detection to perform"
        )
        service_options["level"] = detection_level
        
        if detection_level != "None - Port states only":
            # Version detection
            if detection_level in ["Standard - Service + version detection", "Aggressive - Full service enumeration"]:
                service_options["version_detection"] = True
                service_options["version_intensity"] = st.select_slider(
                    "Version Detection Intensity",
                    options=list(range(0, 10)),
                    value=7 if "Aggressive" in detection_level else 5,
                    help="0=Light, 9=Try all probes (slower but more thorough)"
                )
            
            # Script scanning
            if detection_level in ["Aggressive - Full service enumeration", "Custom Configuration"]:
                service_options["script_scanning"] = st.checkbox("Enable NSE Scripts (-sC)", value="Aggressive" in detection_level)
                
                if service_options.get("script_scanning"):
                    script_categories = st.multiselect(
                        "Script Categories",
                        [
                            "default", "safe", "discovery", "version", "auth",
                            "brute", "vuln", "exploit", "intrusive", "malware"
                        ],
                        default=["default", "safe"] if "Aggressive" not in detection_level else ["default", "safe", "discovery"],
                        help="NSE script categories to run"
                    )
                    service_options["script_categories"] = script_categories
            
            # OS detection
            if detection_level in ["Aggressive - Full service enumeration", "Custom Configuration"]:
                service_options["os_detection"] = st.checkbox("OS Detection (-O)", value="Aggressive" in detection_level)
                
                if service_options.get("os_detection"):
                    col1, col2 = st.columns(2)
                    with col1:
                        service_options["os_scan_limit"] = st.checkbox("Limit OS detection (--osscan-limit)")
                    with col2:
                        service_options["os_scan_guess"] = st.checkbox("Aggressive OS guessing (--osscan-guess)")
        
        # Performance considerations for network scanning
        if st.checkbox("Performance Tuning"):
            col1, col2 = st.columns(2)
            with col1:
                service_options["max_rtt_timeout"] = st.text_input("Max RTT Timeout", placeholder="3s")
                service_options["max_retries"] = st.number_input("Max Retries", min_value=0, max_value=10, value=3)
            with col2:
                service_options["scan_delay"] = st.text_input("Scan Delay", placeholder="1s")
                service_options["max_scan_delay"] = st.text_input("Max Scan Delay", placeholder="10s")
        
        return service_options

    def render_advanced_options(self):
        """Render advanced nmap options for network scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>️ Advanced Options</div>", unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("##### 🔧 Performance & Timing")
            
            # Custom timing controls for network scanning
            if st.checkbox("Custom Timing Controls"):
                timing_options = {}
                timing_options["min_hostgroup"] = st.number_input("Min Host Group Size", min_value=1, value=30)
                timing_options["max_hostgroup"] = st.number_input("Max Host Group Size", min_value=1, value=1024)
                timing_options["min_parallelism"] = st.number_input("Min Parallelism", min_value=1, value=1)
                timing_options["max_parallelism"] = st.number_input("Max Parallelism", min_value=1, value=100)
                timing_options["min_rtt_timeout"] = st.text_input("Min RTT Timeout", placeholder="100ms")
                timing_options["max_rtt_timeout"] = st.text_input("Max RTT Timeout", placeholder="10s")
                timing_options["max_retries"] = st.number_input("Max Retries", min_value=0, value=10)
                timing_options["host_timeout"] = st.text_input("Host Timeout", placeholder="30m")
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
            
            # Network-specific options
            st.markdown("##### 🌐 Network Options")
            interface_options = {}
            interface_options["interface"] = st.text_input("Network Interface (-e)", placeholder="eth0")
            interface_options["dns_servers"] = st.text_input("DNS Servers", placeholder="8.8.8.8,1.1.1.1")
            interface_options["source_ip"] = st.text_input("Source IP", placeholder="192.168.1.100")
            interface_options["randomize_hosts"] = st.checkbox("Randomize Target Order", value=True, help="Randomize target order")
            interface_options["send_eth"] = st.checkbox("Send Ethernet Frames (--send-eth)")
            interface_options["privileged"] = st.checkbox("Assume Privileged User (--privileged)")
            
            # Sudo Authentication for Privileged Scans
            st.markdown("##### 🔐 Sudo Authentication")
            st.info("Some scan types require root privileges (SYN scans, OS detection, raw packets)")
            
            col_sudo1, col_sudo2 = st.columns([2, 1])
            with col_sudo1:
                sudo_password = st.text_input(
                    "Sudo Password",
                    type="password",
                    help="Password for sudo authentication when privileged scans are needed",
                    placeholder="Enter sudo password if needed for advanced scans"
                )
                
                if sudo_password:
                    st.session_state.sudo_password = sudo_password
                    st.success("🔐 Sudo password stored for this session")
                elif 'sudo_password' in st.session_state:
                    del st.session_state.sudo_password
            
            with col_sudo2:
                st.markdown("**Requires Sudo:**")
                st.markdown("• SYN Scan (-sS)")
                st.markdown("• FIN/Xmas/Null Scans")
                st.markdown("• OS Detection (-O)")
                st.markdown("• Raw packet sending")
                st.markdown("• Traceroute")
                
            if 'sudo_password' in st.session_state:
                st.success("✅ Sudo authentication ready for privileged operations")
            else:
                st.warning("⚠️ No sudo password - privileged scans may fail")

    def render_scan_execution(self, target_config, scan_type, discovery_options, port_options, service_options):
        """Render scan execution section for network scanning"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Scan Execution</div>", unsafe_allow_html=True)
        
        # Validate targets before showing execution options
        targets = self.build_target_list(target_config)
        if not targets:
            st.warning("⚠️ Please specify targets above")
            return
        
        # Show target summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Targets", len(targets))
        with col2:
            estimated_time = self.estimate_scan_time(targets, scan_type, port_options)
            st.metric("Estimated Time", estimated_time)
        with col3:
            if target_config["method"] == "Single Network/Subnet":
                network = ipaddress.ip_network(target_config.get("subnet", "0.0.0.0/32"), strict=False)
                st.metric("Network Size", f"/{network.prefixlen}")
        
        # Command preview
        if targets:
            command = self.build_nmap_command(targets, scan_type, discovery_options, port_options, service_options)
            with st.expander("🔍 Command Preview"):
                st.code(f"Command: {command}", language="bash")
        
        # Execution controls
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            start_scan = st.button("🚀 Start Network Scan", type="primary", use_container_width=True)
        
        with col2:
            dry_run = st.button("👁️ Dry Run", use_container_width=True, help="Show what would be scanned without executing")
        
        with col3:
            save_preset = st.button("💾 Save Preset", use_container_width=True)
        
        with col4:
            load_preset = st.button("📂 Load Preset", use_container_width=True)
        
        # Scan options
        scan_options = {}
        col1, col2 = st.columns(2)
        with col1:
            scan_options["parallel_execution"] = st.checkbox("Parallel Subnet Scanning", value=True, help="Scan subnet ranges in parallel")
            scan_options["resume_capability"] = st.checkbox("Enable Resume", help="Allow resuming interrupted scans")
        with col2:
            scan_options["real_time_updates"] = st.checkbox("Real-time Updates", value=True, help="Show scan progress in real-time")
            scan_options["auto_export"] = st.checkbox("Auto-export Results", help="Automatically export results when complete")
        
        # Handle execution
        if start_scan:
            self.execute_network_scan(targets, scan_type, discovery_options, port_options, service_options, scan_options)
        
        elif dry_run:
            self.show_dry_run_preview(targets, scan_type, discovery_options, port_options, service_options)
        
        elif save_preset:
            self.save_scan_preset(scan_type, discovery_options, port_options, service_options)
        
        elif load_preset:
            self.load_scan_preset()

    def save_scan_to_database(self, scan_record):
        """Save network scan results to SQLite database"""
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
                CREATE TABLE IF NOT EXISTS network_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE,
                    scan_type TEXT,
                    targets TEXT,
                    targets_summary TEXT,
                    target_count INTEGER,
                    command TEXT,
                    status TEXT,
                    timestamp TEXT,
                    execution_time TEXT,
                    hosts_up INTEGER,
                    hosts_down INTEGER,
                    total_ports INTEGER,
                    services_detected TEXT,
                    output TEXT,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Check if scan_id column exists, if not add it
            cursor.execute("PRAGMA table_info(network_scans)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'scan_id' not in columns:
                cursor.execute('ALTER TABLE network_scans ADD COLUMN scan_id TEXT')
            
            # Insert scan record
            cursor.execute('''
                INSERT OR REPLACE INTO network_scans 
                (scan_id, scan_type, targets, targets_summary, target_count, command, status, 
                 timestamp, execution_time, hosts_up, hosts_down, total_ports, services_detected, output, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_record.get("scan_id"),
                scan_record.get("scan_type"),
                json.dumps(scan_record.get("targets", [])),
                scan_record.get("targets_summary"),
                scan_record.get("target_count", 0),
                scan_record.get("command"),
                scan_record.get("status"),
                scan_record.get("timestamp"),
                scan_record.get("execution_time"),
                scan_record.get("hosts_up", 0),
                scan_record.get("hosts_down", 0),
                scan_record.get("total_ports", 0),
                json.dumps(scan_record.get("services_detected", [])),
                scan_record.get("output"),
                scan_record.get("error")
            ))
            
            conn.commit()
            conn.close()
            
            st.success("💾 Network scan results saved to database")
            
        except Exception as e:
            st.warning(f"⚠️ Could not save to database: {str(e)}")

    def load_scans_from_database(self):
        """Load network scan history from database"""
        try:
            import sqlite3
            
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')
            
            if not os.path.exists(db_path):
                return []
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT scan_id, scan_type, targets, targets_summary, target_count, status, 
                       timestamp, execution_time, hosts_up, hosts_down, total_ports, 
                       services_detected, command, output, error
                FROM network_scans 
                ORDER BY created_at DESC 
                LIMIT 100
            ''')
            
            scans = []
            for row in cursor.fetchall():
                scan = {
                    "scan_id": row[0],
                    "scan_type": row[1],
                    "targets": json.loads(row[2]) if row[2] else [],
                    "targets_summary": row[3],
                    "target_count": row[4],
                    "status": row[5],
                    "timestamp": row[6],
                    "execution_time": row[7],
                    "hosts_up": row[8],
                    "hosts_down": row[9],
                    "total_ports": row[10],
                    "services_detected": json.loads(row[11]) if row[11] else [],
                    "command": row[12],
                    "output": row[13],
                    "error": row[14]
                }
                scans.append(scan)
            
            conn.close()
            return scans
            
        except Exception as e:
            st.warning(f"⚠️ Could not load from database: {str(e)}")
            return []

    def render_recent_scans(self):
        """Render recent network scans section with database integration"""
        st.markdown("<div style='font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#334155;margin:20px 0 8px'>Recent Network Scans</div>", unsafe_allow_html=True)
        
        # Load scans from database
        db_scans = self.load_scans_from_database()
        
        # Combine with session state scans
        session_scans = st.session_state.get('multi_recent_scans', [])
        
        # Merge and deduplicate
        all_scans = {}
        for scan in db_scans + session_scans:
            scan_id = scan.get('scan_id', f"temp_{scan.get('timestamp', '')}")
            all_scans[scan_id] = scan
        
        scans_list = list(all_scans.values())
        scans_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        if scans_list:
            # Add filter and control options
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                status_filter = st.selectbox("Filter by Status", ["All", "Completed", "Failed", "Running", "Error"])
            with col2:
                limit = st.selectbox("Show Results", [10, 25, 50, 100], index=0)
            with col3:
                if st.button("📊 Export All"):
                    self.export_all_scans(scans_list)
            with col4:
                if st.button("🗑️ Clear History"):
                    self.clear_network_scan_history()
                    st.rerun()
            
            # Filter scans
            filtered_scans = scans_list
            if status_filter != "All":
                filtered_scans = [s for s in scans_list if s.get('status') == status_filter]
            
            filtered_scans = filtered_scans[:limit]
            
            # Display scans
            for i, scan in enumerate(filtered_scans):
                status_emoji = {"Completed": "✅", "Failed": "❌", "Running": "🔄", "Error": "⚠️"}.get(scan.get('status'), "❓")
                
                with st.expander(f"{status_emoji} Network Scan - {scan.get('targets_summary', 'Unknown')} - {scan.get('timestamp', 'Unknown')}"):
                    # Scan summary
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.text(f"Targets: {scan.get('target_count', 'N/A')}")
                        st.text(f"Type: {scan.get('scan_type', 'N/A')}")
                        st.text(f"Status: {scan.get('status', 'N/A')}")
                    
                    with col2:
                        st.text(f"Hosts Up: {scan.get('hosts_up', 'N/A')}")
                        st.text(f"Hosts Down: {scan.get('hosts_down', 'N/A')}")
                        st.text(f"Open Ports: {scan.get('total_ports', 'N/A')}")
                    
                    with col3:
                        if scan.get('execution_time'):
                            st.text(f"Duration: {scan.get('execution_time')}")
                        if scan.get('services_detected'):
                            st.text(f"Services: {len(scan.get('services_detected', []))}")
                        st.text(f"Scan ID: {scan.get('scan_id', 'N/A')[:12]}...")
                    
                    with col4:
                        if st.button(f"👁️ View Details", key=f"view_multi_{i}"):
                            self.display_network_scan_results(scan)
                        if st.button(f"📥 Download", key=f"download_multi_{i}"):
                            self.download_network_scan_report(scan)
                        if st.button(f"🔄 Re-run", key=f"rerun_multi_{i}"):
                            self.rerun_network_scan(scan)
                    
                    # Show targets
                    if scan.get('targets'):
                        with st.expander(f"🎯 Targets ({len(scan['targets'])})"):
                            st.write(", ".join(scan['targets']))
                    
                    # Show services detected
                    if scan.get('services_detected'):
                        with st.expander(f"🔍 Services Detected ({len(scan['services_detected'])})"):
                            st.write(", ".join(scan['services_detected']))
                    
                    # Show command
                    if scan.get('command'):
                        with st.expander("🖥️ Command Executed"):
                            st.code(scan.get('command'), language="bash")
                    
                    # Show error if any
                    if scan.get('error'):
                        st.error(f"Error: {scan.get('error')}")
        else:
            st.info("No recent network scans. Start your first network scan above!")

    def clear_network_scan_history(self):
        """Clear network scan history from database and session"""
        try:
            import sqlite3
            
            db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'siem.db')
            
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM network_scans")
                conn.commit()
                conn.close()
            
            # Clear session state
            if 'multi_recent_scans' in st.session_state:
                st.session_state.multi_recent_scans = []
            
            st.success("🗑️ Network scan history cleared")
            
        except Exception as e:
            st.error(f"❌ Error clearing history: {str(e)}")

    def export_all_scans(self, scans_list):
        """Export all scans to a comprehensive report"""
        try:
            report_lines = []
            report_lines.append("=" * 100)
            report_lines.append("COMPREHENSIVE NETWORK SCAN REPORT")
            report_lines.append("=" * 100)
            report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append(f"Total Scans: {len(scans_list)}")
            report_lines.append("")
            
            for i, scan in enumerate(scans_list, 1):
                report_lines.append(f"SCAN #{i}")
                report_lines.append("-" * 50)
                report_lines.append(f"Scan ID: {scan.get('scan_id', 'N/A')}")
                report_lines.append(f"Targets: {scan.get('targets_summary', 'N/A')} ({scan.get('target_count', 'N/A')} total)")
                report_lines.append(f"Type: {scan.get('scan_type', 'N/A')}")
                report_lines.append(f"Status: {scan.get('status', 'N/A')}")
                report_lines.append(f"Timestamp: {scan.get('timestamp', 'N/A')}")
                report_lines.append(f"Duration: {scan.get('execution_time', 'N/A')}")
                report_lines.append(f"Hosts Up: {scan.get('hosts_up', 'N/A')}")
                report_lines.append(f"Open Ports: {scan.get('total_ports', 'N/A')}")
                if scan.get('services_detected'):
                    report_lines.append(f"Services: {', '.join(scan['services_detected'])}")
                report_lines.append("")
            
            report_content = "\n".join(report_lines)
            
            st.download_button(
                label="📥 Download All Scans Report",
                data=report_content,
                file_name=f"network_scans_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
            
        except Exception as e:
            st.error(f"❌ Error generating export: {str(e)}")

    def rerun_network_scan(self, scan_record):
        """Re-run a network scan from history"""
        try:
            targets = scan_record.get('targets', [])
            if not targets:
                st.error("❌ Cannot re-run scan: targets not found")
                return
            
            # Parse command to extract basic options (simplified)
            command = scan_record.get('command', '')
            
            # Build basic configuration from command
            scan_type = {"type": "TCP SYN Scan (-sS)", "timing": "T3 (Normal)", "max_hostgroup": 64, "max_parallelism": 10}
            if "-sT" in command:
                scan_type["type"] = "TCP Connect Scan (-sT)"
            elif "-sU" in command:
                scan_type["type"] = "UDP Scan (-sU)"
            elif "-sn" in command:
                scan_type["type"] = "Ping Scan Only (-sn)"
            
            # Extract timing
            for timing in ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]:
                if timing in command:
                    timing_map = {"-T0": "T0 (Paranoid)", "-T1": "T1 (Sneaky)", 
                                  "-T2": "T2 (Polite)", "-T3": "T3 (Normal)",
                                  "-T4": "T4 (Aggressive)", "-T5": "T5 (Insane)"}
                    scan_type["timing"] = timing_map.get(timing, "T3 (Normal)")
                    break
            
            # Basic options
            discovery_options = {"strategy": "Default Discovery"}
            port_options = {"strategy": "Top 1000 Ports (Default)"}
            service_options = {"level": "None - Port states only"}
            scan_options = {"real_time_updates": True}
            
            if "-sV" in command:
                service_options["level"] = "Standard - Service + version detection"
                service_options["version_detection"] = True
            if "-sC" in command:
                service_options["script_scanning"] = True
            if "-O" in command:
                service_options["os_detection"] = True
            
            # Build target config
            target_config = {"method": "Multiple Individual Hosts", "hosts": "\n".join(targets)}
            
            st.info(f"🔄 Re-running network scan for {len(targets)} target(s)")
            self.execute_network_scan(targets, scan_type, discovery_options, port_options, service_options, scan_options)
            
        except Exception as e:
            st.error(f"❌ Error re-running scan: {str(e)}")

    def download_network_scan_report(self, scan_record):
        """Generate and provide download for network scan report"""
        try:
            # Generate comprehensive report
            report_content = self.generate_network_scan_report(scan_record)
            
            # Create download button
            st.download_button(
                label="📥 Download Full Report",
                data=report_content,
                file_name=f"network_scan_report_{scan_record.get('scan_id', 'unknown')}_{scan_record.get('timestamp', 'unknown').replace(':', '-').replace(' ', '_')}.txt",
                mime="text/plain",
                key=f"download_net_full_{scan_record.get('scan_id', int(time.time()))}"
            )
            
            # Also offer JSON format
            json_content = json.dumps(scan_record, indent=2)
            st.download_button(
                label="📥 Download JSON Data",
                data=json_content,
                file_name=f"network_scan_data_{scan_record.get('scan_id', 'unknown')}_{scan_record.get('timestamp', 'unknown').replace(':', '-').replace(' ', '_')}.json",
                mime="application/json",
                key=f"download_net_json_{scan_record.get('scan_id', int(time.time()))}"
            )
            
        except Exception as e:
            st.error(f"❌ Error generating download: {str(e)}")

    def generate_network_scan_report(self, scan_record):
        """Generate comprehensive network scan report"""
        report_lines = []
        report_lines.append("=" * 100)
        report_lines.append("NETWORK SCAN REPORT")
        report_lines.append("=" * 100)
        report_lines.append("")
        
        # Scan Information
        report_lines.append("SCAN INFORMATION:")
        report_lines.append("-" * 50)
        report_lines.append(f"Scan ID: {scan_record.get('scan_id', 'N/A')}")
        report_lines.append(f"Targets: {scan_record.get('targets_summary', 'N/A')} ({scan_record.get('target_count', 'N/A')} total)")
        report_lines.append(f"Scan Type: {scan_record.get('scan_type', 'N/A')}")
        report_lines.append(f"Timestamp: {scan_record.get('timestamp', 'N/A')}")
        report_lines.append(f"Status: {scan_record.get('status', 'N/A')}")
        report_lines.append(f"Duration: {scan_record.get('execution_time', 'N/A')}")
        report_lines.append("")
        
        # Results Summary
        report_lines.append("RESULTS SUMMARY:")
        report_lines.append("-" * 50)
        report_lines.append(f"Hosts Up: {scan_record.get('hosts_up', 'N/A')}")
        report_lines.append(f"Hosts Down: {scan_record.get('hosts_down', 'N/A')}")
        report_lines.append(f"Total Open Ports: {scan_record.get('total_ports', 'N/A')}")
        if scan_record.get('services_detected'):
            report_lines.append(f"Services Detected: {', '.join(scan_record['services_detected'])}")
        report_lines.append("")
        
        # Target List
        if scan_record.get('targets'):
            report_lines.append("TARGET LIST:")
            report_lines.append("-" * 50)
            for target in scan_record['targets']:
                report_lines.append(f"  • {target}")
            report_lines.append("")
        
        # Command Executed
        report_lines.append("COMMAND EXECUTED:")
        report_lines.append("-" * 50)
        report_lines.append(scan_record.get('command', 'N/A'))
        report_lines.append("")
        
        # Full Output
        report_lines.append("FULL SCAN OUTPUT:")
        report_lines.append("-" * 50)
        report_lines.append(scan_record.get('output', 'No output available'))
        report_lines.append("")
        
        # Errors (if any)
        if scan_record.get('error'):
            report_lines.append("ERRORS/WARNINGS:")
            report_lines.append("-" * 50)
            report_lines.append(scan_record.get('error'))
            report_lines.append("")
        
        # Footer
        report_lines.append("=" * 100)
        report_lines.append(f"Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("Generated by SIEM System - Multi-Scan Module")
        report_lines.append("=" * 100)
        
        return "\n".join(report_lines)

    # Utility methods
    def validate_subnet(self, subnet):
        """Validate subnet in CIDR notation"""
        try:
            ipaddress.ip_network(subnet, strict=False)
            return True
        except ValueError:
            return False

    def count_hosts_in_subnet(self, subnet):
        """Count number of hosts in subnet"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            return network.num_addresses
        except ValueError:
            return 0

    def parse_host_list(self, hosts_text):
        """Parse host list from text input"""
        hosts = []
        # Handle both newline and comma separated
        if '\n' in hosts_text:
            hosts = [h.strip() for h in hosts_text.split('\n') if h.strip()]
        else:
            hosts = [h.strip() for h in hosts_text.split(',') if h.strip()]
        return hosts

    def get_preset_configuration(self, preset):
        """Get predefined scan configurations"""
        presets = {
            "Quick Network Discovery": {
                "type": "Ping Scan Only (-sn)",
                "timing": "T4 (Aggressive)",
                "max_hostgroup": 128,
                "max_parallelism": 50
            },
            "Comprehensive Port Scan": {
                "type": "TCP SYN Scan (-sS)",
                "timing": "T3 (Normal)",
                "max_hostgroup": 64,
                "max_parallelism": 10
            },
            "Stealth Reconnaissance": {
                "type": "TCP SYN Scan (-sS)",
                "timing": "T1 (Sneaky)",
                "max_hostgroup": 16,
                "max_parallelism": 5
            },
            "Service Enumeration": {
                "type": "TCP SYN Scan (-sS)",
                "timing": "T3 (Normal)",
                "max_hostgroup": 32,
                "max_parallelism": 10
            },
            "Vulnerability Assessment": {
                "type": "TCP SYN Scan (-sS)",
                "timing": "T4 (Aggressive)",
                "max_hostgroup": 64,
                "max_parallelism": 20
            },
            "Performance Optimized": {
                "type": "TCP SYN Scan (-sS)",
                "timing": "T5 (Insane)",
                "max_hostgroup": 256,
                "max_parallelism": 100
            }
        }
        return presets.get(preset, presets["Comprehensive Port Scan"])

    def build_target_list(self, target_config):
        """Build list of targets from configuration"""
        targets = []
        
        method = target_config["method"]
        
        if method == "Single Network/Subnet" and target_config.get("subnet"):
            targets.append(target_config["subnet"])
        
        elif method == "Multiple Individual Hosts" and target_config.get("hosts"):
            targets = self.parse_host_list(target_config["hosts"])
        
        elif method == "Host List from File" and target_config.get("file_hosts"):
            targets = target_config["file_hosts"]
        
        elif method == "IP Range" and target_config.get("start_ip") and target_config.get("end_ip"):
            targets.append(f"{target_config['start_ip']}-{target_config['end_ip']}")
        
        elif method == "Custom Nmap Target Format" and target_config.get("custom"):
            targets.append(target_config["custom"])
        
        return targets

    def estimate_scan_time(self, targets, scan_type, port_options):
        """Estimate scan completion time"""
        # Simplified estimation logic
        base_time_per_host = 30  # seconds
        
        # Adjust based on scan type
        if "UDP" in scan_type.get("type", ""):
            base_time_per_host *= 3
        if "All Ports" in port_options.get("strategy", ""):
            base_time_per_host *= 10
        elif "Top 10000" in port_options.get("strategy", ""):
            base_time_per_host *= 5
        
        # Timing adjustment
        timing = scan_type.get("timing", "T3 (Normal)")
        if "T5" in timing:
            base_time_per_host *= 0.3
        elif "T4" in timing:
            base_time_per_host *= 0.5
        elif "T1" in timing:
            base_time_per_host *= 3
        elif "T0" in timing:
            base_time_per_host *= 10
        
        # Calculate total estimated time
        host_count = len(targets)
        for target in targets:
            if "/" in target:  # CIDR notation
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    host_count += network.num_addresses - 1
                except:
                    pass
        
        total_seconds = host_count * base_time_per_host
        
        # Format time estimate
        if total_seconds < 60:
            return f"{int(total_seconds)}s"
        elif total_seconds < 3600:
            return f"{int(total_seconds/60)}m"
        else:
            return f"{int(total_seconds/3600)}h {int((total_seconds%3600)/60)}m"

    def build_nmap_command(self, targets, scan_type, discovery_options, port_options, service_options):
        """Build the complete nmap command for network scanning"""
        cmd = ["nmap"]
        
        # Add scan type
        scan_type_value = scan_type.get("type", "TCP SYN Scan (-sS)")
        if "TCP SYN" in scan_type_value:
            cmd.append("-sS")
        elif "TCP Connect" in scan_type_value:
            cmd.append("-sT")
        elif "TCP ACK" in scan_type_value:
            cmd.append("-sA")
        elif "UDP Scan" in scan_type_value:
            cmd.append("-sU")
        elif "Ping Scan Only" in scan_type_value:
            cmd.append("-sn")
        elif "List Scan" in scan_type_value:
            cmd.append("-sL")
        elif "TCP SYN + UDP Combo" in scan_type_value:
            cmd.extend(["-sS", "-sU"])
        
        # Add timing
        timing_map = {
            "T0 (Paranoid)": "-T0",
            "T1 (Sneaky)": "-T1",
            "T2 (Polite)": "-T2",
            "T3 (Normal)": "-T3",
            "T4 (Aggressive)": "-T4",
            "T5 (Insane)": "-T5"
        }
        cmd.append(timing_map.get(scan_type.get("timing", "T3 (Normal)"), "-T3"))
        
        # Add discovery options
        discovery_strategy = discovery_options.get("strategy", "Default Discovery")
        if "No Discovery" in discovery_strategy:
            cmd.append("-Pn")
        elif "Ping Scan Only" in discovery_strategy:
            cmd.append("-sn")
        
        # Add port options
        port_strategy = port_options.get("strategy", "Top 1000 Ports")
        if "Top 100" in port_strategy:
            cmd.append("-F")
        elif "All Ports" in port_strategy:
            cmd.extend(["-p", "1-65535"])
        elif "Top 10000" in port_strategy:
            cmd.extend(["--top-ports", "10000"])
        elif port_options.get("custom_ports"):
            cmd.extend(["-p", port_options["custom_ports"]])
        
        # Add service detection
        if service_options.get("version_detection"):
            cmd.append("-sV")
        if service_options.get("script_scanning"):
            cmd.append("-sC")
        if service_options.get("os_detection"):
            cmd.append("-O")
        
        # Add parallelism options
        if scan_type.get("max_hostgroup"):
            cmd.extend(["--max-hostgroup", str(scan_type["max_hostgroup"])])
        if scan_type.get("max_parallelism"):
            cmd.extend(["--max-parallelism", str(scan_type["max_parallelism"])])
        
        # Output options
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_base = os.path.join(self.reports_dir, f"multi_scan_{timestamp}")
        cmd.extend(["-oN", f"{output_base}.txt"])
        cmd.extend(["-oX", f"{output_base}.xml"])
        
        # Add targets
        cmd.extend(targets)
        
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

    def execute_network_scan(self, targets, scan_type, discovery_options, port_options, service_options, scan_options):
        """Execute the network scan with progress tracking"""
        try:
            # Build command
            command = self.build_nmap_command(targets, scan_type, discovery_options, port_options, service_options)
            
            # Check if sudo is needed and add it to the command
            needs_sudo = self.check_if_sudo_needed(command)
            if needs_sudo and 'sudo_password' in st.session_state:
                # Prepare command with sudo -S (read password from stdin)
                command = f"echo '{st.session_state.sudo_password}' | sudo -S {command}"
                st.info("🔐 Using sudo for privileged scan operations")
            elif needs_sudo and 'sudo_password' not in st.session_state:
                st.warning("⚠️ This scan may require sudo privileges. Please enter your sudo password in Advanced Options if the scan fails.")
            
            # Create scan record
            scan_record = {
                "targets": targets,
                "targets_summary": ", ".join(targets[:3]) + ("..." if len(targets) > 3 else ""),
                "target_count": len(targets),
                "scan_type": scan_type.get("type", "Unknown"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "command": command,
                "status": "Running",
                "scan_id": f"multi_{int(time.time())}"
            }
            
            # Add to recent scans
            if 'multi_recent_scans' not in st.session_state:
                st.session_state.multi_recent_scans = []
            st.session_state.multi_recent_scans.append(scan_record)
            
            # Execute scan with real-time updates if enabled
            if scan_options.get("real_time_updates"):
                self.execute_standard_scan(command, scan_record)  # Using standard scan with live output
            else:
                self.execute_standard_scan(command, scan_record)
            
        except Exception as e:
            st.error(f"❌ Error executing network scan: {str(e)}")
            scan_record["status"] = "Error"
            scan_record["error"] = str(e)
            self.save_scan_to_database(scan_record)
            add_notification(f"Network scan error: {str(e)}", "error")

    def execute_standard_scan(self, command, scan_record):
        """Execute scan with live terminal output"""
        try:
            start_time = time.time()
            output_lines = []
            
            # Create live terminal output containers
            st.info(f"🚀 Starting network scan...")
            st.code(f"Executing: {command}", language="bash")
            
            terminal_container = st.empty()
            progress_container = st.empty()
            
            # Check if we need to use shell=True for sudo commands
            use_shell = 'sudo -S' in command
            needs_sudo = 'sudo_password' in st.session_state and use_shell
            
            # Execute with live output
            process = subprocess.Popen(
                command if use_shell else command.split(),
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
                            st.markdown("##### 🖥️ Live Network Scan Output")
                            # Show last 25 lines for network scans
                            display_lines = output_lines[-25:] if len(output_lines) > 25 else output_lines
                            terminal_output = "\n".join(display_lines)
                            if len(output_lines) > 25:
                                terminal_output = f"... (showing last 25 of {len(output_lines)} lines)\n" + terminal_output
                            st.code(terminal_output, language="bash")
                        
                        # Update progress for network scans
                        if any(keyword in output.lower() for keyword in ["scanning", "discovered", "completed", "%"]):
                            with progress_container.container():
                                st.info(f"📊 {output.strip()}")
                        
                        time.sleep(0.1)  # Small delay to prevent too rapid updates
                
                return_code = process.poll()
            
            execution_time = time.time() - start_time
            full_output = "\n".join(output_lines)
            
            # Update scan record
            scan_record["status"] = "Completed" if return_code == 0 else "Failed"
            scan_record["execution_time"] = f"{execution_time/60:.1f}m"
            scan_record["output"] = full_output
            scan_record["return_code"] = return_code
            
            if return_code == 0:
                st.success(f"✅ Network scan completed successfully in {execution_time/60:.1f} minutes")
                
                # Parse results
                scan_summary = self.parse_network_scan_results(full_output)
                scan_record.update(scan_summary)
                
                # Save to database
                self.save_scan_to_database(scan_record)
                
                # Display results
                self.display_network_scan_results(scan_record)
                
                # Send to backend
                self.send_results_to_backend(scan_record)
                
                # Add notification
                add_notification(
                    f"Network scan completed - {scan_summary.get('hosts_up', 0)} hosts up, {scan_summary.get('total_ports', 0)} open ports",
                    "success"
                )
            else:
                st.error(f"❌ Network scan failed with return code: {return_code}")
                scan_record["error"] = f"Process failed with return code {return_code}"
                self.save_scan_to_database(scan_record)  # Save failed scans too
                add_notification("Network scan failed", "error")
                
        except Exception as e:
            st.error(f"❌ Error during network scan: {str(e)}")
            scan_record["status"] = "Error"
            scan_record["error"] = str(e)
            self.save_scan_to_database(scan_record)
            add_notification(f"Network scan error: {str(e)}", "error")

    def execute_with_realtime_updates(self, command, scan_record):
        """Execute scan with real-time progress updates"""
        # Implementation for real-time updates would go here
        # For now, fall back to standard execution
        self.execute_standard_scan(command, scan_record)

    def parse_network_scan_results(self, output):
        """Parse network scan results and extract summary"""
        summary = {
            "hosts_up": 0,
            "hosts_down": 0,
            "total_ports": 0,
            "services_detected": []
        }
        
        lines = output.split('\n')
        
        for line in lines:
            # Count hosts up/down
            if "Host is up" in line:
                summary["hosts_up"] += 1
            elif "host down" in line:
                summary["hosts_down"] += 1
            
            # Count open ports
            if '/tcp' in line and 'open' in line:
                summary["total_ports"] += 1
                parts = line.split()
                if len(parts) >= 3:
                    service = parts[2]
                    if service not in summary["services_detected"]:
                        summary["services_detected"].append(service)
            elif '/udp' in line and 'open' in line:
                summary["total_ports"] += 1
        
        return summary

    def display_network_scan_results(self, scan_record):
        """Display network scan results"""
        st.markdown("<div style='font-size:15px;font-weight:600;color:#e2e8f0;margin:16px 0 8px'>Network Scan Results</div>", unsafe_allow_html=True)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Targets Scanned", scan_record["target_count"])
        with col2:
            st.metric("Hosts Up", scan_record.get("hosts_up", "N/A"))
        with col3:
            st.metric("Open Ports", scan_record.get("total_ports", "N/A"))
        with col4:
            st.metric("Duration", scan_record.get("execution_time", "N/A"))
        
        # Services detected
        if scan_record.get("services_detected"):
            st.markdown("##### 🔍 Services Detected")
            st.write(", ".join(scan_record["services_detected"]))
        
        # Detailed results
        if "output" in scan_record:
            with st.expander("📋 Detailed Results", expanded=False):
                st.text(scan_record["output"])

    def show_dry_run_preview(self, targets, scan_type, discovery_options, port_options, service_options):
        """Show what would be scanned without executing"""
        st.markdown("### 👁️ Dry Run Preview")
        
        command = self.build_nmap_command(targets, scan_type, discovery_options, port_options, service_options)
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("##### 🎯 Targets")
            for target in targets:
                st.write(f"• {target}")
        
        with col2:
            st.markdown("##### ⚙️ Configuration")
            st.write(f"**Scan Type:** {scan_type.get('type', 'Unknown')}")
            st.write(f"**Timing:** {scan_type.get('timing', 'T3 (Normal)')}")
            st.write(f"**Port Strategy:** {port_options.get('strategy', 'Top 1000 Ports')}")
            st.write(f"**Service Detection:** {service_options.get('level', 'None')}")
        
        st.markdown("##### 🖥️ Command")
        st.code(command, language="bash")

    def save_scan_preset(self, scan_type, discovery_options, port_options, service_options):
        """Save scan configuration as preset"""
        preset_name = st.text_input("Preset Name", placeholder="My Network Scan Preset")
        if st.button("Save Preset") and preset_name:
            # Implementation for saving presets
            st.success(f"✅ Preset '{preset_name}' saved!")

    def load_scan_preset(self):
        """Load saved scan preset"""
        # Implementation for loading presets
        st.info("📂 Preset loading functionality coming soon!")

    def export_network_scan_report(self, scan_record):
        """Export comprehensive network scan report"""
        try:
            report_content = f"""
NETWORK SCAN REPORT
===================

Scan Summary:
- Targets: {scan_record['target_count']} ({scan_record['targets_summary']})
- Scan Type: {scan_record['scan_type']}
- Timestamp: {scan_record['timestamp']}
- Duration: {scan_record.get('execution_time', 'N/A')}
- Status: {scan_record['status']}

Results Summary:
- Hosts Up: {scan_record.get('hosts_up', 'N/A')}
- Hosts Down: {scan_record.get('hosts_down', 'N/A')}
- Total Open Ports: {scan_record.get('total_ports', 'N/A')}
- Services Detected: {', '.join(scan_record.get('services_detected', []))}

Command Executed:
{scan_record.get('command', 'N/A')}

Detailed Output:
{scan_record.get('output', 'No output available')}

Errors/Warnings:
{scan_record.get('errors', 'None')}
"""
            
            st.download_button(
                label="📥 Download Network Scan Report",
                data=report_content,
                file_name=f"network_scan_report_{scan_record['timestamp'].replace(':', '-').replace(' ', '_')}.txt",
                mime="text/plain"
            )
        except Exception as e:
            st.error(f"❌ Error generating report: {str(e)}")

    def rerun_scan(self, scan_record):
        """Legacy method - redirects to rerun_network_scan"""
        self.rerun_network_scan(scan_record)

    def stop_scan(self, scan_record):
        """Stop a running scan (placeholder for future implementation)"""
        st.info("🛑 Stop scan functionality would terminate running process")

    def export_network_scan_report(self, scan_record):
        """Legacy method - redirects to download_network_scan_report"""
        self.download_network_scan_report(scan_record)

    def send_results_to_backend(self, scan_record):
        """Send scan results to backend API"""
        # Skip if API is disabled
        if not self.api_url:
            return
            
        try:
            response = requests.post(
                self.api_url,
                json={
                    "scan_type": "multi",
                    "targets": scan_record["targets"],
                    "results": scan_record
                },
                timeout=30
            )
            if response.status_code == 200:
                st.info("📡 Results sent to backend successfully")
        except Exception as e:
            st.warning(f"⚠️ Could not send results to backend: {str(e)}")

# Main page render function
def render_page():
    """Main render function for the page"""
    # Check if user is logged in
    if 'logged_in' not in st.session_state or not st.session_state.logged_in:
        st.error("❌ Please log in to access the Multi-Scan page")
        st.stop()
    
    # Create and render page
    page = MultiScanPage()
    page.render_page()