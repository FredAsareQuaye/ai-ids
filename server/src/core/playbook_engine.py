"""
Automated Incident Response - Playbook Engine
Executes response actions automatically when MITRE ATT&CK correlations fire.

Supported actions:
  block_ip     — iptables DROP (Linux) or Windows Firewall rule
  snapshot_db  — timestamped copy of siem.db for evidence preservation
  log_event    — create a SIEM log entry recording the automated action
  run_script   — execute a custom shell script with correlation context as env vars
"""
import json
import logging
import os
import platform
import shutil
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PLAYBOOKS_FILE = (
    Path(__file__).resolve().parent.parent.parent / "data" / "playbooks.json"
)

DEFAULT_PLAYBOOKS: List[Dict] = [
    {
        "id": "block-brute-force",
        "name": "Auto-block Brute Force IPs",
        "description": "Blocks source IP in the system firewall when brute force is detected.",
        "trigger_rule": "BRUTE_FORCE",
        "min_severity": "HIGH",
        "enabled": True,
        "actions": [
            {"type": "block_ip"},
            {"type": "snapshot_db"},
            {"type": "log_event",
             "message": "Playbook: Auto-blocked {source} for brute force (T1110)"},
        ],
    },
    {
        "id": "snapshot-log-tamper",
        "name": "Emergency Snapshot on Log Tampering",
        "description": "Preserves the database immediately when log tampering is detected.",
        "trigger_rule": "LOG_TAMPERING",
        "min_severity": "CRITICAL",
        "enabled": True,
        "actions": [
            {"type": "snapshot_db"},
            {"type": "log_event",
             "message": "Playbook: Emergency DB snapshot — log tampering from {source} (T1070)"},
        ],
    },
    {
        "id": "snapshot-credential-dump",
        "name": "Snapshot on Credential Dumping",
        "description": "Takes evidence snapshot when credential dumping activity is detected.",
        "trigger_rule": "CREDENTIAL_DUMP",
        "min_severity": "CRITICAL",
        "enabled": True,
        "actions": [
            {"type": "snapshot_db"},
            {"type": "log_event",
             "message": "Playbook: Credential dumping from {source} — snapshot taken (T1003)"},
        ],
    },
    {
        "id": "block-port-scan",
        "name": "Block Port Scanners",
        "description": "Blocks source IP when a port scan is detected. Disabled by default.",
        "trigger_rule": "PORT_SCAN",
        "min_severity": "MEDIUM",
        "enabled": False,
        "actions": [
            {"type": "block_ip"},
            {"type": "log_event",
             "message": "Playbook: Blocked {source} for port scanning (T1046)"},
        ],
    },
    {
        "id": "snapshot-malware",
        "name": "Snapshot on Malware Execution",
        "description": "Preserves evidence when suspicious execution is detected.",
        "trigger_rule": "MALWARE_EXECUTION",
        "min_severity": "HIGH",
        "enabled": True,
        "actions": [
            {"type": "snapshot_db"},
            {"type": "log_event",
             "message": "Playbook: Malware/suspicious execution from {source} (T1059)"},
        ],
    },
    {
        "id": "snapshot-persistence",
        "name": "Snapshot on Persistence Installation",
        "description": "Preserves evidence when a persistence mechanism is installed.",
        "trigger_rule": "PERSISTENCE",
        "min_severity": "HIGH",
        "enabled": True,
        "actions": [
            {"type": "snapshot_db"},
            {"type": "log_event",
             "message": "Playbook: Persistence mechanism installed from {source} (T1547)"},
        ],
    },
]

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_PRIVATE_PATTERNS = [
    r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^192\.168\.", r"^127\.", r"^::1$",
]


def _is_private_ip(ip: str) -> bool:
    return any(re.match(p, ip) for p in _PRIVATE_PATTERNS)


class PlaybookEngine:
    """
    Matches fired correlations against playbook rules and executes
    the configured response actions.
    """

    def __init__(self, db=None, notifier=None):
        self.db = db
        self.notifier = notifier
        self.playbooks: List[Dict] = self._load()
        self._blocked_ips: set = set()
        self.backup_dir = (
            Path(__file__).resolve().parent.parent.parent / "backups"
        )
        self.backup_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def execute(self, correlation: Dict[str, Any]) -> List[Dict]:
        """Run all matching playbooks for a correlation. Returns execution reports."""
        rule_id  = correlation.get("rule_id", "")
        severity = correlation.get("severity", "LOW").upper()
        source   = correlation.get("source", "unknown")
        reports  = []

        for pb in self.playbooks:
            if not pb.get("enabled", True):
                continue
            if pb.get("trigger_rule") != rule_id:
                continue
            min_sev = pb.get("min_severity", "LOW").upper()
            if _SEVERITY_ORDER.index(severity) < _SEVERITY_ORDER.index(min_sev):
                continue

            logger.warning(
                f"PLAYBOOK '{pb['name']}' triggered by {rule_id} from {source}"
            )
            report = {
                "playbook_id":   pb["id"],
                "playbook_name": pb["name"],
                "triggered_by":  rule_id,
                "source":        source,
                "executed_at":   datetime.now().isoformat(),
                "actions":       [],
            }
            for action in pb.get("actions", []):
                report["actions"].append(
                    self._run_action(action, correlation)
                )
            reports.append(report)

            if self.db:
                try:
                    self.db.store_playbook_execution(report)
                except Exception as e:
                    logger.error(f"Failed to store playbook execution: {e}")

        return reports

    def get_playbooks(self) -> List[Dict]:
        return self.playbooks

    def update_playbook(self, pb_id: str, updates: Dict) -> bool:
        for i, pb in enumerate(self.playbooks):
            if pb["id"] == pb_id:
                self.playbooks[i].update(updates)
                self._save(self.playbooks)
                return True
        return False

    def get_blocked_ips(self) -> List[str]:
        return sorted(self._blocked_ips)

    # ------------------------------------------------------------------ #
    #  Action implementations                                             #
    # ------------------------------------------------------------------ #

    def _run_action(self, action: Dict, correlation: Dict) -> Dict:
        atype  = action.get("type", "")
        source = correlation.get("source", "unknown")
        try:
            if atype == "block_ip":
                return self._block_ip(source)
            elif atype == "snapshot_db":
                return self._snapshot_db()
            elif atype == "log_event":
                msg = action.get("message", "Automated action executed").format(
                    source=source
                )
                return self._log_event(msg, correlation)
            elif atype == "run_script":
                return self._run_script(action.get("script", ""), correlation)
            return {"type": atype, "status": "unknown_action"}
        except Exception as e:
            logger.error(f"Action '{atype}' failed: {e}")
            return {"type": atype, "status": "error", "error": str(e)}

    def _block_ip(self, source: str) -> Dict:
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", source)
        if not m:
            return {"type": "block_ip", "status": "skipped",
                    "reason": "no_public_ip_in_source", "source": source}

        ip = m.group(1)

        if _is_private_ip(ip):
            return {"type": "block_ip", "status": "skipped",
                    "reason": "private_ip", "ip": ip}

        if ip in self._blocked_ips:
            return {"type": "block_ip", "status": "skipped",
                    "reason": "already_blocked", "ip": ip}

        sys_name = platform.system().lower()

        if sys_name == "linux" and shutil.which("iptables"):
            r = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0:
                self._blocked_ips.add(ip)
                logger.warning(f"PLAYBOOK: Blocked {ip} via iptables")
                return {"type": "block_ip", "status": "blocked",
                        "ip": ip, "method": "iptables"}
            return {"type": "block_ip", "status": "error",
                    "ip": ip, "error": r.stderr[:200]}

        if sys_name == "windows":
            r = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name=SIEM-Block-{ip}", "dir=in", "action=block",
                 f"remoteip={ip}"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                self._blocked_ips.add(ip)
                return {"type": "block_ip", "status": "blocked",
                        "ip": ip, "method": "windows_firewall"}
            return {"type": "block_ip", "status": "error",
                    "ip": ip, "error": r.stderr[:200]}

        return {"type": "block_ip", "status": "skipped",
                "reason": f"no_firewall_tool_on_{sys_name}"}

    def _snapshot_db(self) -> Dict:
        db_path = Path(__file__).resolve().parent.parent.parent / "siem.db"
        if not db_path.exists():
            return {"type": "snapshot_db", "status": "error",
                    "error": "siem.db not found"}
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = self.backup_dir / f"siem_snapshot_{ts}.db"
        try:
            shutil.copy2(db_path, dest)
            logger.info(f"PLAYBOOK: DB snapshot saved → {dest}")
            return {"type": "snapshot_db", "status": "ok", "path": str(dest)}
        except Exception as e:
            return {"type": "snapshot_db", "status": "error", "error": str(e)}

    def _log_event(self, message: str, correlation: Dict) -> Dict:
        if self.db:
            try:
                self.db.store_event({
                    "timestamp":  datetime.now().isoformat(),
                    "source":     "playbook_engine",
                    "message":    message,
                    "severity":   "HIGH",
                    "event_type": "automated_response",
                    "details": {
                        "triggered_by": correlation.get("rule_id"),
                        "mitre_id":     correlation.get("mitre_id"),
                    },
                    "analysis": {},
                })
            except Exception as e:
                logger.error(f"_log_event DB write failed: {e}")
        logger.info(f"PLAYBOOK LOG: {message}")
        return {"type": "log_event", "status": "ok", "message": message}

    def _run_script(self, script_path: str, correlation: Dict) -> Dict:
        if not script_path or not Path(script_path).exists():
            return {"type": "run_script", "status": "error",
                    "error": f"Script not found: {script_path}"}
        env = os.environ.copy()
        env.update({
            "SIEM_SOURCE":    correlation.get("source", ""),
            "SIEM_RULE":      correlation.get("rule_id", ""),
            "SIEM_MITRE":     correlation.get("mitre_id", ""),
            "SIEM_SEVERITY":  correlation.get("severity", ""),
            "SIEM_FIRED_AT":  correlation.get("fired_at", ""),
        })
        try:
            r = subprocess.run(
                [script_path], env=env, capture_output=True,
                text=True, timeout=30,
            )
            return {
                "type":       "run_script",
                "status":     "ok" if r.returncode == 0 else "error",
                "script":     script_path,
                "returncode": r.returncode,
                "output":     r.stdout[:500],
            }
        except subprocess.TimeoutExpired:
            return {"type": "run_script", "status": "error",
                    "error": "timeout_30s", "script": script_path}
        except Exception as e:
            return {"type": "run_script", "status": "error", "error": str(e)}

    # ------------------------------------------------------------------ #
    #  Persistence                                                         #
    # ------------------------------------------------------------------ #

    def _load(self) -> List[Dict]:
        if PLAYBOOKS_FILE.exists():
            try:
                return json.loads(PLAYBOOKS_FILE.read_text())
            except Exception as e:
                logger.error(f"Failed to load playbooks.json: {e}")
        self._save(DEFAULT_PLAYBOOKS)
        return list(DEFAULT_PLAYBOOKS)

    def _save(self, playbooks: List[Dict]):
        PLAYBOOKS_FILE.parent.mkdir(parents=True, exist_ok=True)
        PLAYBOOKS_FILE.write_text(json.dumps(playbooks, indent=2))
