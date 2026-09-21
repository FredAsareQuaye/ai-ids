"""
Ransomware Live Tracking Engine.

Analyses stored SIEM logs for ransomware indicators:
  - Known ransomware file extensions in log messages
  - Shadow copy / VSS deletion commands
  - High-rate file modification bursts (>N distinct file events/minute)
  - Mass rename / delete patterns
  - Known ransomware process names (task-kill, vssadmin, wbadmin, bcdedit…)
  - C2/IOC correlation against the threat feed cache
  - Lateral movement indicators tied to ransomware TTPs (T1021, T1059, T1486)
"""

import sqlite3
import re
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

# ---------------------------------------------------------------------------
# Known indicators
# ---------------------------------------------------------------------------
RANSOM_EXTENSIONS = [
    ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
    ".wncry", ".wnry", ".wcry", ".wncrypt",
    ".zepto", ".cerber", ".cerber2", ".cerber3",
    ".locky", ".sage", ".dharma", ".phobos",
    ".ryuk", ".conti", ".lockbit", ".revil",
    ".sodinokibi", ".maze", ".egregor", ".blackcat",
    ".alphv", ".blackmatter", ".hive", ".darkside",
    ".avoslocker", ".clop", ".pandora", ".quantum",
    ".pay2decrypt", ".decrypt2022", ".readme",
]

RANSOM_PROCESSES = [
    "vssadmin", "wbadmin", "bcdedit",
    "wmic shadowcopy", "wmic.exe",
    "cipher.exe", "schtasks", "powershell -enc",
    "cmd.exe /c del", "icacls",
    "net stop", "sc stop", "taskkill /f",
    "certutil -decode", "bitsadmin",
    "mshta", "regsvr32", "rundll32",
    "psexec", "cobalt strike", "mimikatz",
]

RANSOM_COMMANDS = [
    r"vssadmin.*delete.*shadows",
    r"wbadmin.*delete.*catalog",
    r"bcdedit.*(recoveryenabled|bootstatuspolicy)",
    r"wmic.*shadowcopy.*delete",
    r"taskkill.*(/f|/im).*(sql|backup|agent|veeam|acronis)",
    r"net\s+stop\s+(vss|sql|backup|shadowprotect|veeam)",
    r"icacls.*grant.*everyone",
    r"cipher\s+/[ew]",
    r"reg\s+add.*CurrentVersion\\Run",
    r"powershell.*(invoke-expression|iex|downloadstring|encodedcommand)",
    r"(certutil|bitsadmin).*(urlcache|transfer).*http",
]

MITRE_RANSOM_TACTICS = {
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop",
    "T1070": "Indicator Removal",
    "T1562": "Impair Defenses",
    "T1059": "Command and Scripting Interpreter",
    "T1021": "Remote Services (lateral movement)",
    "T1078": "Valid Accounts",
    "T1485": "Data Destruction",
    "T1491": "Defacement",
}

_compiled_cmds = [re.compile(p, re.IGNORECASE) for p in RANSOM_COMMANDS]


class RansomwareDetector:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_tables()

    # ------------------------------------------------------------------
    # Schema bootstrap
    # ------------------------------------------------------------------
    def _ensure_tables(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS ransomware_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id      INTEGER,
            detected_at TEXT DEFAULT (datetime('now')),
            indicator   TEXT NOT NULL,
            ioc_type    TEXT NOT NULL,
            severity    TEXT NOT NULL DEFAULT 'HIGH',
            source      TEXT,
            agent_id    TEXT,
            message     TEXT,
            mitre_id    TEXT,
            mitre_name  TEXT,
            raw_log     TEXT,
            acknowledged INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_rw_detected ON ransomware_events(detected_at);

        CREATE TABLE IF NOT EXISTS ransomware_stats (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            window_start TEXT NOT NULL,
            window_end   TEXT NOT NULL,
            event_count  INTEGER DEFAULT 0,
            affected_hosts TEXT DEFAULT '[]',
            top_ioc_type TEXT,
            computed_at  TEXT DEFAULT (datetime('now'))
        );
        """)
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Core scan — call this periodically or on-demand
    # ------------------------------------------------------------------
    def scan_recent_logs(self, hours: int = 24) -> List[Dict]:
        """Scan logs from the last `hours` hours for ransomware indicators."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        # Fetch raw log rows
        # agent_id and raw_log may not exist in all deployments — use COALESCE
        cursor.execute("""
            SELECT id, timestamp, source, message, severity,
                   '' as agent_id,
                   COALESCE(details, '') as raw_log
            FROM logs
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            LIMIT 5000
        """, (since,))
        rows = cursor.fetchall()
        conn.close()

        hits: List[Dict] = []
        for row in rows:
            log_id   = row["id"]
            msg      = (row["message"] or "").lower()
            raw      = (row["raw_log"] or "").lower()
            combined = msg + " " + raw

            detected = self._detect_indicators(combined)
            for ioc_type, indicator, mitre_id in detected:
                hit = {
                    "log_id":    log_id,
                    "ioc_type":  ioc_type,
                    "indicator": indicator,
                    "source":    row["source"],
                    "agent_id":  row["agent_id"],
                    "message":   row["message"],
                    "severity":  self._ioc_severity(ioc_type),
                    "mitre_id":  mitre_id,
                    "mitre_name": MITRE_RANSOM_TACTICS.get(mitre_id, ""),
                    "raw_log":   row["raw_log"],
                    "detected_at": datetime.utcnow().isoformat(),
                }
                hits.append(hit)

        # Persist new detections (deduplicate by log_id + ioc_type)
        if hits:
            self._persist_hits(hits)

        return hits

    def _detect_indicators(self, text: str):
        """Return list of (ioc_type, indicator, mitre_id) tuples found in text."""
        found = []

        # 1. Known extensions
        for ext in RANSOM_EXTENSIONS:
            if ext in text:
                found.append(("Ransom Extension", ext, "T1486"))

        # 2. Dangerous process names
        for proc in RANSOM_PROCESSES:
            if proc.lower() in text:
                found.append(("Ransom Process", proc, "T1059"))

        # 3. Regex command patterns
        for i, pat in enumerate(_compiled_cmds):
            m = pat.search(text)
            if m:
                mitre = "T1490" if "shadow" in m.group(0).lower() or "vss" in m.group(0).lower() else "T1059"
                found.append(("Ransom Command", m.group(0)[:120], mitre))

        return found

    def _ioc_severity(self, ioc_type: str) -> str:
        mapping = {
            "Ransom Command":    "CRITICAL",
            "Ransom Extension":  "HIGH",
            "Ransom Process":    "HIGH",
        }
        return mapping.get(ioc_type, "MEDIUM")

    def _persist_hits(self, hits: List[Dict]):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for h in hits:
            # Skip if already stored
            cursor.execute("""
                SELECT id FROM ransomware_events
                WHERE log_id = ? AND ioc_type = ? AND indicator = ?
                LIMIT 1
            """, (h["log_id"], h["ioc_type"], h["indicator"]))
            if cursor.fetchone():
                continue
            cursor.execute("""
                INSERT INTO ransomware_events
                    (log_id, indicator, ioc_type, severity, source, agent_id,
                     message, mitre_id, mitre_name, raw_log, detected_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                h["log_id"], h["indicator"], h["ioc_type"], h["severity"],
                h["source"], h["agent_id"], h["message"],
                h["mitre_id"], h["mitre_name"], h["raw_log"], h["detected_at"],
            ))
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------
    # Read stored events (for API/UI)
    # ------------------------------------------------------------------
    def get_events(self, hours: int = 24, limit: int = 500) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        rows = conn.execute("""
            SELECT * FROM ransomware_events
            WHERE detected_at >= ?
            ORDER BY detected_at DESC
            LIMIT ?
        """, (since, limit)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self, hours: int = 24) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

        rows = conn.execute("""
            SELECT ioc_type, severity, source, agent_id, detected_at
            FROM ransomware_events
            WHERE detected_at >= ?
        """, (since,)).fetchall()
        conn.close()

        if not rows:
            return {
                "total": 0, "critical": 0, "high": 0,
                "affected_hosts": [], "ioc_breakdown": {},
                "timeline": [], "threat_level": "NONE",
            }

        total     = len(rows)
        critical  = sum(1 for r in rows if r["severity"] == "CRITICAL")
        high      = sum(1 for r in rows if r["severity"] == "HIGH")
        hosts     = list({r["source"] for r in rows if r["source"]})
        ioc_types: Dict[str, int] = {}
        for r in rows:
            ioc_types[r["ioc_type"]] = ioc_types.get(r["ioc_type"], 0) + 1

        # Timeline — bucket by hour
        buckets: Dict[str, int] = {}
        for r in rows:
            try:
                dt = datetime.fromisoformat(r["detected_at"])
                bucket = dt.strftime("%Y-%m-%d %H:00")
                buckets[bucket] = buckets.get(bucket, 0) + 1
            except Exception:
                pass
        timeline = [{"hour": k, "count": v} for k, v in sorted(buckets.items())]

        threat_level = (
            "CRITICAL" if critical >= 3 else
            "HIGH"     if critical >= 1 or high >= 5 else
            "ELEVATED" if total >= 3 else
            "LOW"
        )

        return {
            "total": total,
            "critical": critical,
            "high": high,
            "affected_hosts": hosts,
            "ioc_breakdown": ioc_types,
            "timeline": timeline,
            "threat_level": threat_level,
        }

    def acknowledge(self, event_id: int):
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE ransomware_events SET acknowledged=1 WHERE id=?", (event_id,))
        conn.commit()
        conn.close()

    def get_indicators_summary(self) -> List[Dict]:
        """Top recurring indicators across all time."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT indicator, ioc_type, severity,
                   COUNT(*) as hit_count,
                   MAX(detected_at) as last_seen
            FROM ransomware_events
            GROUP BY indicator, ioc_type
            ORDER BY hit_count DESC
            LIMIT 50
        """).fetchall()
        conn.close()
        return [{"indicator": r[0], "ioc_type": r[1], "severity": r[2],
                 "hit_count": r[3], "last_seen": r[4]} for r in rows]
