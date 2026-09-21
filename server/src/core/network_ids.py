"""
Network Threat Sensor — real-time network intrusion detection engine.

Tails an EVE-format JSON log stream produced by any compatible network
sensor daemon (configurable via NIDS_EVE_PATH env var).  Each line is
parsed into a structured event and stored in SQLite.

Supported event types: alert, dns, http, tls, ssh, smb, flow, fileinfo,
                       anomaly, stats (all others stored as "generic").

Severity mapping (alert.severity field, 1 = highest):
  1 → CRITICAL   2 → HIGH   3 → MEDIUM   4+ → LOW
"""

import sqlite3
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_EVE_PATH = os.environ.get("NIDS_EVE_PATH", "/var/log/suricata/eve.json")
POLL_INTERVAL   = float(os.environ.get("NIDS_POLL_INTERVAL", "2.0"))   # seconds
MAX_BATCH       = int(os.environ.get("NIDS_MAX_BATCH", "500"))

# MITRE ATT&CK category mapping (alert.category → technique)
CATEGORY_MITRE: Dict[str, Tuple[str, str]] = {
    "A Network Trojan was detected":         ("T1071", "Application Layer Protocol"),
    "Attempted Administrator Privilege Gain": ("T1068", "Exploitation for Privilege Escalation"),
    "Attempted Information Leak":            ("T1190", "Exploit Public-Facing Application"),
    "Attempted User Privilege Gain":         ("T1078", "Valid Accounts"),
    "Denial of Service":                     ("T1498", "Network Denial of Service"),
    "Executable Code was Detected":          ("T1059", "Command and Scripting Interpreter"),
    "Misc activity":                         ("T1040", "Network Sniffing"),
    "Misc attack":                           ("T1071", "Application Layer Protocol"),
    "Network Scan":                          ("T1046", "Network Service Discovery"),
    "Not Suspicious Traffic":                ("",      ""),
    "Potentially Bad Traffic":               ("T1071", "Application Layer Protocol"),
    "Successful Administrator Privilege Gain":("T1068","Exploitation for Privilege Escalation"),
    "Successful User Privilege Gain":        ("T1078", "Valid Accounts"),
    "Trojan Activity":                       ("T1071", "Application Layer Protocol"),
    "Unknown Traffic":                       ("T1040", "Network Sniffing"),
    "Web Application Attack":                ("T1190", "Exploit Public-Facing Application"),
    "exploit-kit":                           ("T1189", "Drive-by Compromise"),
    "malware-cnc":                           ("T1071", "Application Layer Protocol"),
    "policy-violation":                      ("T1562", "Impair Defenses"),
    "protocol-command-decode":               ("T1095", "Non-Application Layer Protocol"),
    "server-apache":                         ("T1190", "Exploit Public-Facing Application"),
    "sql-injection":                         ("T1190", "Exploit Public-Facing Application"),
}

PROTO_SEVERITY_BOOST = {"tcp": 0, "udp": 0, "icmp": 0, "http": 0, "tls": 0}


def _sev_from_int(n: int) -> str:
    return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(n, "LOW")


class NetworkThreatSensor:
    """
    Tails an EVE JSON log file, parses events, and stores them in SQLite.
    Call .start() to run the background tail thread.
    """

    def __init__(self, db_path: Path, eve_path: str = DEFAULT_EVE_PATH):
        self.db_path  = db_path
        self.eve_path = Path(eve_path)
        self._offset  = 0
        self._lock    = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._ensure_tables()
        self._restore_offset()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _ensure_tables(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS nids_events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT NOT NULL,
            event_type   TEXT NOT NULL DEFAULT 'generic',
            src_ip       TEXT,
            src_port     INTEGER,
            dest_ip      TEXT,
            dest_port    INTEGER,
            proto        TEXT,
            severity     TEXT NOT NULL DEFAULT 'LOW',
            sig_id       INTEGER,
            sig_name     TEXT,
            sig_category TEXT,
            sig_rev      INTEGER,
            action       TEXT,
            mitre_id     TEXT,
            mitre_name   TEXT,
            dns_query    TEXT,
            http_method  TEXT,
            http_url     TEXT,
            http_host    TEXT,
            http_status  INTEGER,
            tls_sni      TEXT,
            ssh_version  TEXT,
            raw          TEXT,
            acknowledged INTEGER DEFAULT 0,
            ingested_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_nids_ts   ON nids_events(ts);
        CREATE INDEX IF NOT EXISTS idx_nids_sev  ON nids_events(severity);
        CREATE INDEX IF NOT EXISTS idx_nids_type ON nids_events(event_type);

        CREATE TABLE IF NOT EXISTS nids_state (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        conn.commit()
        conn.close()

    def _restore_offset(self):
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT value FROM nids_state WHERE key='offset'").fetchone()
        conn.close()
        if row:
            try:
                self._offset = int(row[0])
            except Exception:
                self._offset = 0

    def _save_offset(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT OR REPLACE INTO nids_state (key, value) VALUES ('offset', ?)",
                     (str(self._offset),))
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------
    def _parse_line(self, raw: str) -> Optional[Dict]:
        raw = raw.strip()
        if not raw:
            return None
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError:
            return None

        etype = doc.get("event_type", "generic")
        ts    = doc.get("timestamp", datetime.utcnow().isoformat())

        base = {
            "ts":         ts,
            "event_type": etype,
            "src_ip":     doc.get("src_ip"),
            "src_port":   doc.get("src_port"),
            "dest_ip":    doc.get("dest_ip"),
            "dest_port":  doc.get("dest_port"),
            "proto":      doc.get("proto", "").upper(),
            "severity":   "LOW",
            "sig_id":     None,
            "sig_name":   None,
            "sig_category": None,
            "sig_rev":    None,
            "action":     None,
            "mitre_id":   None,
            "mitre_name": None,
            "dns_query":  None,
            "http_method": None,
            "http_url":   None,
            "http_host":  None,
            "http_status": None,
            "tls_sni":    None,
            "ssh_version": None,
            "raw":        raw[:4000],
        }

        if etype == "alert":
            al = doc.get("alert", {})
            sev_int = al.get("severity", 3)
            base["severity"]     = _sev_from_int(sev_int)
            base["sig_id"]       = al.get("signature_id")
            base["sig_name"]     = al.get("signature")
            base["sig_category"] = al.get("category")
            base["sig_rev"]      = al.get("rev")
            base["action"]       = al.get("action", "allowed")
            cat = al.get("category", "")
            mid, mname = CATEGORY_MITRE.get(cat, ("", ""))
            base["mitre_id"]   = mid or None
            base["mitre_name"] = mname or None

        elif etype == "dns":
            dns = doc.get("dns", {})
            base["dns_query"] = dns.get("rrname") or dns.get("query", {}).get("rrname")

        elif etype == "http":
            http = doc.get("http", {})
            base["http_method"] = http.get("http_method")
            base["http_url"]    = http.get("url")
            base["http_host"]   = http.get("hostname")
            base["http_status"] = http.get("status")

        elif etype == "tls":
            tls = doc.get("tls", {})
            base["tls_sni"] = tls.get("sni") or tls.get("subject")

        elif etype == "ssh":
            ssh = doc.get("ssh", {})
            base["ssh_version"] = (ssh.get("client", {}).get("software_version") or
                                   ssh.get("server", {}).get("software_version"))

        return base

    # ------------------------------------------------------------------
    # File tail
    # ------------------------------------------------------------------
    def ingest_file(self, max_lines: int = MAX_BATCH) -> int:
        """Read new lines from the EVE file. Returns count of events stored."""
        if not self.eve_path.exists():
            return 0

        new_events = []
        try:
            with open(self.eve_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._offset)
                count = 0
                for line in fh:
                    ev = self._parse_line(line)
                    if ev:
                        new_events.append(ev)
                    count += 1
                    if count >= max_lines:
                        break
                self._offset = fh.tell()
        except OSError:
            return 0

        if new_events:
            self._store(new_events)
        self._save_offset()
        return len(new_events)

    def ingest_raw(self, lines: List[str]) -> int:
        """Ingest a list of raw EVE JSON strings (used by API push endpoint)."""
        events = [ev for line in lines if (ev := self._parse_line(line))]
        if events:
            self._store(events)
        return len(events)

    def _store(self, events: List[Dict]):
        conn = sqlite3.connect(self.db_path)
        conn.executemany("""
            INSERT INTO nids_events
                (ts, event_type, src_ip, src_port, dest_ip, dest_port, proto,
                 severity, sig_id, sig_name, sig_category, sig_rev, action,
                 mitre_id, mitre_name, dns_query, http_method, http_url,
                 http_host, http_status, tls_sni, ssh_version, raw)
            VALUES
                (:ts,:event_type,:src_ip,:src_port,:dest_ip,:dest_port,:proto,
                 :severity,:sig_id,:sig_name,:sig_category,:sig_rev,:action,
                 :mitre_id,:mitre_name,:dns_query,:http_method,:http_url,
                 :http_host,:http_status,:tls_sni,:ssh_version,:raw)
        """, events)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Background thread
    # ------------------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="nids-tail")
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self.ingest_file()
            except Exception:
                pass
            time.sleep(POLL_INTERVAL)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------
    def get_alerts(self, hours: int = 24, limit: int = 500,
                   severity: Optional[str] = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        sql = """
            SELECT * FROM nids_events
            WHERE ts >= ? AND event_type = 'alert'
        """
        params: list = [since]
        if severity:
            sql += " AND severity = ?"
            params.append(severity.upper())
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_events(self, hours: int = 24, limit: int = 1000,
                   event_type: Optional[str] = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        sql = "SELECT * FROM nids_events WHERE ts >= ?"
        params: list = [since]
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self, hours: int = 24) -> Dict:
        conn = sqlite3.connect(self.db_path)
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        total     = conn.execute("SELECT COUNT(*) FROM nids_events WHERE ts >= ?", (since,)).fetchone()[0]
        alerts    = conn.execute("SELECT COUNT(*) FROM nids_events WHERE ts >= ? AND event_type='alert'", (since,)).fetchone()[0]
        critical  = conn.execute("SELECT COUNT(*) FROM nids_events WHERE ts >= ? AND severity='CRITICAL'", (since,)).fetchone()[0]
        high      = conn.execute("SELECT COUNT(*) FROM nids_events WHERE ts >= ? AND severity='HIGH'", (since,)).fetchone()[0]
        blocked   = conn.execute("SELECT COUNT(*) FROM nids_events WHERE ts >= ? AND action='blocked'", (since,)).fetchone()[0]

        # Top attacking IPs
        top_ips = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt FROM nids_events
            WHERE ts >= ? AND event_type='alert' AND src_ip IS NOT NULL
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
        """, (since,)).fetchall()

        # Top signatures
        top_sigs = conn.execute("""
            SELECT sig_name, sig_category, COUNT(*) as cnt FROM nids_events
            WHERE ts >= ? AND event_type='alert' AND sig_name IS NOT NULL
            GROUP BY sig_name ORDER BY cnt DESC LIMIT 15
        """, (since,)).fetchall()

        # Protocol breakdown
        protos = conn.execute("""
            SELECT proto, COUNT(*) as cnt FROM nids_events
            WHERE ts >= ? AND proto IS NOT NULL AND proto != ''
            GROUP BY proto ORDER BY cnt DESC
        """, (since,)).fetchall()

        # Event type breakdown
        types = conn.execute("""
            SELECT event_type, COUNT(*) as cnt FROM nids_events
            WHERE ts >= ? GROUP BY event_type ORDER BY cnt DESC
        """, (since,)).fetchall()

        # Hourly timeline (alerts only)
        timeline = conn.execute("""
            SELECT strftime('%Y-%m-%d %H:00', ts) as hour,
                   COUNT(*) as cnt
            FROM nids_events WHERE ts >= ? AND event_type='alert'
            GROUP BY hour ORDER BY hour
        """, (since,)).fetchall()

        # MITRE breakdown
        mitre = conn.execute("""
            SELECT mitre_id, mitre_name, COUNT(*) as cnt
            FROM nids_events
            WHERE ts >= ? AND mitre_id IS NOT NULL AND mitre_id != ''
            GROUP BY mitre_id ORDER BY cnt DESC LIMIT 12
        """, (since,)).fetchall()

        conn.close()
        return {
            "total_events": total,
            "total_alerts": alerts,
            "critical": critical,
            "high": high,
            "blocked": blocked,
            "top_src_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
            "top_signatures": [{"name": r[0], "category": r[1], "count": r[2]} for r in top_sigs],
            "protocols": {r[0]: r[1] for r in protos},
            "event_types": {r[0]: r[1] for r in types},
            "timeline": [{"hour": r[0], "count": r[1]} for r in timeline],
            "mitre": [{"id": r[0], "name": r[1], "count": r[2]} for r in mitre],
        }

    def get_dns_queries(self, hours: int = 24, limit: int = 200) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        rows = conn.execute("""
            SELECT dns_query, COUNT(*) as cnt, MAX(ts) as last_seen,
                   src_ip
            FROM nids_events
            WHERE ts >= ? AND event_type='dns' AND dns_query IS NOT NULL
            GROUP BY dns_query ORDER BY cnt DESC LIMIT ?
        """, (since, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_http_requests(self, hours: int = 24, limit: int = 200) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        rows = conn.execute("""
            SELECT src_ip, dest_ip, http_method, http_url, http_host,
                   http_status, ts FROM nids_events
            WHERE ts >= ? AND event_type='http' AND http_url IS NOT NULL
            ORDER BY ts DESC LIMIT ?
        """, (since, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def acknowledge(self, event_id: int):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE nids_events SET acknowledged=1 WHERE id=?", (event_id,))
        conn.commit()
        conn.close()

    def get_sensor_status(self) -> Dict:
        """Return sensor health information."""
        eve_exists = self.eve_path.exists()
        eve_size   = self.eve_path.stat().st_size if eve_exists else 0
        conn = sqlite3.connect(self.db_path)
        total   = conn.execute("SELECT COUNT(*) FROM nids_events").fetchone()[0]
        latest  = conn.execute("SELECT MAX(ingested_at) FROM nids_events").fetchone()[0]
        conn.close()
        return {
            "sensor_active": self._running,
            "eve_file_found": eve_exists,
            "eve_file_path": str(self.eve_path),
            "eve_file_size_bytes": eve_size,
            "file_offset": self._offset,
            "total_events_stored": total,
            "last_event_at": latest,
            "poll_interval_s": POLL_INTERVAL,
        }
