"""
Structured Log Parser
Extracts actionable fields from Apache/Nginx access logs, SSH auth logs,
sudo events, Windows Event Log format, syslog, and JSON/key-value formats.
Enriches events before AI analysis and correlation.
"""
import json
import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Compiled patterns ────────────────────────────────────────────────────── #

# Apache/Nginx Combined Log Format
_APACHE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# SSH authentication events
_SSH_FAILED   = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')
_SSH_ACCEPTED = re.compile(r'Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)')
_SSH_INVALID  = re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)(?:\s+port (?P<port>\d+))?')
_SSH_DISCONNECT = re.compile(r'Disconnected from (?:invalid user )?(?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)')
_SSH_MAX_AUTH = re.compile(r'error: maximum authentication attempts exceeded for (?P<user>\S+) from (?P<ip>\S+)')

# Sudo
_SUDO = re.compile(
    r'(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+?)$'
)

# Syslog header: "Jan  1 12:34:56 host process[pid]: message"
_SYSLOG = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<body>.+)$'
)

# Windows Event XML/text patterns
_WIN_EID   = re.compile(r'EventID[>\s]+(\d+)')
_WIN_USER  = re.compile(r'SubjectUserName[>\s]+([^<\s\-]+)')
_WIN_TUSER = re.compile(r'TargetUserName[>\s]+([^<\s\-]+)')
_WIN_IP    = re.compile(r'IpAddress[>\s]+([^<\s\-]+)')
_WIN_LTYPE = re.compile(r'LogonType[>\s]+(\d+)')
_WIN_PROC  = re.compile(r'NewProcessName[>\s]+([^<\n]+)')
_WIN_SVC   = re.compile(r'ServiceName[>\s]+([^<\n\s]+)')

_LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
    "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
    "10": "RemoteInteractive", "11": "CachedInteractive",
}

_SUSPICIOUS_EVENT_IDS = {4625, 4697, 4719, 4720, 4726, 4740, 1102, 7045, 4104}

# Key=value pairs
_KV = re.compile(r'(\w[\w.]+)=(?:"([^"]*)"|([\S]*))')

# High-risk sudo commands
_DANGEROUS_CMDS = frozenset([
    "/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/perl",
    "passwd", "visudo", "chmod 777", "chown root", "rm -rf",
    "dd if=", "mkfs", "iptables -F", "ufw disable",
])


class LogParser:
    """
    Try multiple parsers in priority order and return the first match.
    Returns a dict of extracted fields; empty dict if unparseable.
    """

    def parse(self, message: str, source: str = "") -> Dict[str, Any]:
        if not message:
            return {}
        for fn in (
            self._json,
            self._apache,
            self._ssh,
            self._sudo,
            self._windows_event,
            self._syslog,
            self._kv,
        ):
            result = fn(message)
            if result:
                return result
        return {}

    # ── Individual parsers ──────────────────────────────────────────────── #

    def _json(self, msg: str) -> Optional[Dict]:
        s = msg.strip()
        if not (s.startswith("{") and s.endswith("}")):
            return None
        try:
            d = json.loads(s)
            return {
                "format":     "json",
                "level":      d.get("level") or d.get("severity") or d.get("lvl"),
                "ts":         d.get("timestamp") or d.get("ts") or d.get("time"),
                "msg":        d.get("message") or d.get("msg"),
                "username":   d.get("user") or d.get("username"),
                "source_ip":  d.get("ip") or d.get("src_ip") or d.get("remote_addr"),
                "service":    d.get("service") or d.get("app"),
                "extra":      d,
            }
        except Exception:
            return None

    def _apache(self, msg: str) -> Optional[Dict]:
        m = _APACHE.search(msg)
        if not m:
            return None
        status = int(m.group("status") or 0)
        method = m.group("method") or ""
        return {
            "format":       "apache_combined",
            "source_ip":    m.group("ip"),
            "http_method":  method,
            "http_path":    m.group("path"),
            "http_status":  status,
            "bytes":        m.group("bytes"),
            "user_agent":   m.group("ua"),
            "is_error":     status >= 400,
            "is_suspicious": (
                status in (401, 403) or
                method in ("TRACE", "CONNECT") or
                any(p in (m.group("path") or "") for p in
                    ("/etc/", "/proc/", "/../", "/.git/", "/wp-admin", "/phpMyAdmin"))
            ),
        }

    def _ssh(self, msg: str) -> Optional[Dict]:
        low = msg.lower()
        if "sshd" not in low and "ssh" not in low:
            return None

        for pattern, event_name, suspicious in (
            (_SSH_FAILED,     "failed_login",    True),
            (_SSH_INVALID,    "invalid_user",    True),
            (_SSH_MAX_AUTH,   "max_auth_exceeded", True),
            (_SSH_DISCONNECT, "disconnected",    False),
            (_SSH_ACCEPTED,   "successful_login", False),
        ):
            m = pattern.search(msg)
            if m:
                d = m.groupdict()
                return {
                    "format":       "ssh_auth",
                    "event":        event_name,
                    "username":     d.get("user"),
                    "source_ip":    d.get("ip"),
                    "port":         d.get("port"),
                    "auth_method":  d.get("method"),
                    "is_suspicious": suspicious,
                }
        return None

    def _sudo(self, msg: str) -> Optional[Dict]:
        if "sudo" not in msg.lower():
            return None
        m = _SUDO.search(msg)
        if not m:
            return None
        cmd = m.group("cmd").strip()
        dangerous = (
            any(d in cmd for d in _DANGEROUS_CMDS) or
            m.group("target") == "root"
        )
        return {
            "format":       "sudo",
            "event":        "sudo_command",
            "username":     m.group("user"),
            "target_user":  m.group("target"),
            "command":      cmd[:500],
            "is_suspicious": dangerous,
        }

    def _windows_event(self, msg: str) -> Optional[Dict]:
        if not any(k in msg for k in
                   ("EventID", "SubjectUserName", "TargetUserName", "LogonType")):
            return None

        f: Dict[str, Any] = {"format": "windows_event"}

        m = _WIN_EID.search(msg)
        if m:
            f["event_id"] = int(m.group(1))

        m = _WIN_USER.search(msg)
        if m and m.group(1) not in ("-", "N/A", "", "SYSTEM"):
            f["username"] = m.group(1)

        m = _WIN_TUSER.search(msg)
        if m and m.group(1) not in ("-", "N/A", "", "SYSTEM"):
            f["target_username"] = m.group(1)

        m = _WIN_IP.search(msg)
        if m and m.group(1) not in ("-", "::1", "127.0.0.1", ""):
            f["source_ip"] = m.group(1)

        m = _WIN_LTYPE.search(msg)
        if m:
            lt = m.group(1)
            f["logon_type"]      = lt
            f["logon_type_name"] = _LOGON_TYPES.get(lt, "Unknown")

        m = _WIN_PROC.search(msg)
        if m:
            f["new_process"] = m.group(1).strip()

        m = _WIN_SVC.search(msg)
        if m:
            f["service_name"] = m.group(1).strip()

        eid = f.get("event_id", 0)
        f["is_suspicious"] = eid in _SUSPICIOUS_EVENT_IDS

        return f if len(f) > 2 else None

    def _syslog(self, msg: str) -> Optional[Dict]:
        m = _SYSLOG.match(msg.strip())
        if not m:
            return None
        return {
            "format":   "syslog",
            "hostname": m.group("host"),
            "process":  m.group("proc").strip(),
            "pid":      m.group("pid"),
            "body":     m.group("body")[:500],
        }

    def _kv(self, msg: str) -> Optional[Dict]:
        pairs = _KV.findall(msg)
        if len(pairs) < 2:
            return None
        f: Dict[str, Any] = {"format": "key_value"}
        for key, vq, vp in pairs:
            f[key.lower()] = vq if vq else vp
        return f if len(f) > 2 else None


# Module-level singleton
_parser = LogParser()


def parse_log(message: str, source: str = "") -> Dict[str, Any]:
    """Parse a raw log message and return structured fields."""
    return _parser.parse(message, source)
