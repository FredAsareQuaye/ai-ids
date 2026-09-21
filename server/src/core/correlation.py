"""
MITRE ATT&CK Threat Correlation Engine
Detects attack patterns across multiple events using a sliding time window.
"""
import json
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# MITRE ATT&CK rule definitions
ATTACK_RULES = [
    {
        "id": "BRUTE_FORCE",
        "name": "Brute Force Attack",
        "mitre_id": "T1110",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/",
        "description": "5+ failed authentication attempts from same source within 5 minutes",
        "severity": "HIGH",
        "window_seconds": 300,
        "threshold": 5,
        "keywords": [
            "failed password", "failed login", "authentication failure",
            "invalid user", "invalid credentials", "logon failure",
            "account lockout", "bad password", "incorrect password"
        ],
    },
    {
        "id": "PORT_SCAN",
        "name": "Network Port Scan Detected",
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Connection attempts to multiple ports from same source detected",
        "severity": "MEDIUM",
        "window_seconds": 120,
        "threshold": 8,
        "keywords": [
            "port scan", "connection refused", "nmap", "masscan",
            "syn scan", "tcp scan", "udp scan", "service scan"
        ],
    },
    {
        "id": "PRIVILEGE_ESCALATION",
        "name": "Privilege Escalation Attempt",
        "mitre_id": "T1548",
        "mitre_tactic": "Privilege Escalation",
        "mitre_url": "https://attack.mitre.org/techniques/T1548/",
        "description": "Unauthorized privilege escalation detected",
        "severity": "CRITICAL",
        "window_seconds": 60,
        "threshold": 1,
        "keywords": [
            "sudo", "su root", "privilege escalation", "unauthorized root",
            "setuid", "setgid", "runas", "elevation required", "access denied admin"
        ],
    },
    {
        "id": "LOG_TAMPERING",
        "name": "Defense Evasion - Log Tampering",
        "mitre_id": "T1070",
        "mitre_tactic": "Defense Evasion",
        "mitre_url": "https://attack.mitre.org/techniques/T1070/",
        "description": "Attempt to clear or tamper with security logs",
        "severity": "CRITICAL",
        "window_seconds": 60,
        "threshold": 1,
        "keywords": [
            "log cleared", "audit log deleted", "event log cleared",
            "wevtutil cl", "clear-eventlog", "log file deleted",
            "security log wiped", "truncate log"
        ],
    },
    {
        "id": "CREDENTIAL_DUMP",
        "name": "Credential Dumping",
        "mitre_id": "T1003",
        "mitre_tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1003/",
        "description": "Attempt to access credential stores or dump hashes",
        "severity": "CRITICAL",
        "window_seconds": 60,
        "threshold": 1,
        "keywords": [
            "/etc/shadow", "ntds.dit", "lsass", "hashdump",
            "mimikatz", "credential dump", "sam database",
            "password hash", "secretsdump", "procdump lsass"
        ],
    },
    {
        "id": "LATERAL_MOVEMENT",
        "name": "Lateral Movement via Remote Services",
        "mitre_id": "T1021",
        "mitre_tactic": "Lateral Movement",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/",
        "description": "Remote access between internal hosts detected",
        "severity": "HIGH",
        "window_seconds": 300,
        "threshold": 3,
        "keywords": [
            "accepted password", "accepted publickey", "rdp session",
            "remote login", "winrm", "psexec", "wmiexec",
            "remote command execution", "ssh tunnel"
        ],
    },
    {
        "id": "MALWARE_EXECUTION",
        "name": "Suspicious Command Execution",
        "mitre_id": "T1059",
        "mitre_tactic": "Execution",
        "mitre_url": "https://attack.mitre.org/techniques/T1059/",
        "description": "Suspicious script or shell command execution detected",
        "severity": "HIGH",
        "window_seconds": 60,
        "threshold": 1,
        "keywords": [
            "malware", "shellcode", "powershell -enc", "powershell -nop",
            "cmd /c", "wget http", "curl http", "python -c import",
            "base64 -d |", "nc -e", "bash -i >&", "reverse shell"
        ],
    },
    {
        "id": "DATA_EXFILTRATION",
        "name": "Possible Data Exfiltration",
        "mitre_id": "T1041",
        "mitre_tactic": "Exfiltration",
        "mitre_url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Unusual outbound data transfer detected",
        "severity": "HIGH",
        "window_seconds": 300,
        "threshold": 1,
        "keywords": [
            "large data transfer", "exfiltration", "unusual upload",
            "sftp upload", "ftp transfer", "data sent external",
            "abnormal outbound", "bulk transfer"
        ],
    },
    {
        "id": "RECON",
        "name": "Reconnaissance Activity",
        "mitre_id": "T1595",
        "mitre_tactic": "Reconnaissance",
        "mitre_url": "https://attack.mitre.org/techniques/T1595/",
        "description": "Active scanning or enumeration of network resources",
        "severity": "MEDIUM",
        "window_seconds": 300,
        "threshold": 5,
        "keywords": [
            "network scan", "host discovery", "os detection", "service enumeration",
            "vulnerability scan", "nikto", "dirb", "gobuster", "ping sweep"
        ],
    },
    {
        "id": "PERSISTENCE",
        "name": "Persistence Mechanism Installed",
        "mitre_id": "T1547",
        "mitre_tactic": "Persistence",
        "mitre_url": "https://attack.mitre.org/techniques/T1547/",
        "description": "New startup entry, service, or scheduled task created",
        "severity": "HIGH",
        "window_seconds": 60,
        "threshold": 1,
        "keywords": [
            "new service installed", "startup registry", "scheduled task created",
            "crontab modified", "rc.local modified", "autorun added",
            "launchdaemon created", "systemd unit created"
        ],
    },
]


class CorrelationEngine:
    """
    Sliding-window event correlation engine with MITRE ATT&CK mapping.
    Maintains an in-memory window of recent events per source IP/host,
    detects rule matches, and emits correlation incidents.
    """

    def __init__(self, db=None):
        self.db = db
        # event_window[source] = deque of (timestamp, message, event_id)
        self.event_window: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # Track fired correlations to avoid duplicate alerts
        # key = (rule_id, source), value = last_fired datetime
        self.last_fired: Dict[tuple, datetime] = {}
        # Cooldown between re-firing same rule for same source (seconds)
        self.cooldown_seconds = 120

    def process_event(self, log_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a new event. Returns a correlation dict if a rule fires, else None.
        """
        source = log_data.get("source", "unknown")
        message = str(log_data.get("message", "")).lower()
        timestamp = datetime.now()

        # Add to sliding window
        self.event_window[source].append({
            "timestamp": timestamp,
            "message": message,
            "original": log_data,
        })

        # Prune expired events from window
        self._prune_window(source)

        # Check each rule against current window
        for rule in ATTACK_RULES:
            correlation = self._check_rule(rule, source, timestamp)
            if correlation:
                return correlation

        return None

    def _prune_window(self, source: str):
        """Remove events older than the longest rule window."""
        max_window = max(r["window_seconds"] for r in ATTACK_RULES)
        cutoff = datetime.now() - timedelta(seconds=max_window)
        window = self.event_window[source]
        while window and window[0]["timestamp"] < cutoff:
            window.popleft()

    def _check_rule(
        self, rule: Dict, source: str, now: datetime
    ) -> Optional[Dict[str, Any]]:
        """Check if a rule fires for the given source."""
        window_cutoff = now - timedelta(seconds=rule["window_seconds"])
        matching_events = []

        for event in self.event_window[source]:
            if event["timestamp"] < window_cutoff:
                continue
            msg = event["message"]
            if any(kw in msg for kw in rule["keywords"]):
                matching_events.append(event)

        if len(matching_events) < rule["threshold"]:
            return None

        # Check cooldown
        cooldown_key = (rule["id"], source)
        last = self.last_fired.get(cooldown_key)
        if last and (now - last).total_seconds() < self.cooldown_seconds:
            return None

        # Rule fires
        self.last_fired[cooldown_key] = now
        logger.warning(
            f"CORRELATION FIRED: {rule['name']} from {source} "
            f"({len(matching_events)} events matched rule {rule['mitre_id']})"
        )

        correlation = {
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "mitre_id": rule["mitre_id"],
            "mitre_tactic": rule["mitre_tactic"],
            "mitre_url": rule["mitre_url"],
            "description": rule["description"],
            "severity": rule["severity"],
            "source": source,
            "matched_count": len(matching_events),
            "threshold": rule["threshold"],
            "window_seconds": rule["window_seconds"],
            "fired_at": now.isoformat(),
            "sample_events": [
                e["original"].get("message", "")[:200]
                for e in matching_events[-3:]  # last 3 matching events as samples
            ],
        }

        # Persist to DB if available
        if self.db:
            try:
                self.db.store_correlation(correlation)
            except Exception as e:
                logger.error(f"Failed to store correlation: {e}")

        return correlation

    def get_recent_correlations(self, hours: int = 24) -> List[Dict]:
        """Return correlations fired in the last N hours."""
        if not self.db:
            return []
        return self.db.get_correlations(hours=hours)
