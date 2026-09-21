"""
User & Entity Behavior Analytics (UEBA)

Tracks per-user behavioral baselines:
  - Typical login hours (Welford mean/variance per hour-of-day)
  - Known source IPs
  - Session frequency baseline

Anomalies fire as HIGH/CRITICAL events stored in the correlations table.
"""
import logging
import math
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
_Z_THRESHOLD = 2.5
_MIN_SAMPLES = 5  # days before firing anomalies


class UEBAEngine:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_tables()

    # ── DB helpers ────────────────────────────────────────────────────────────

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_tables(self):
        with self._conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS ueba_user_hours (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                hour_of_day INTEGER NOT NULL,
                sample_count INTEGER DEFAULT 0,
                mean REAL DEFAULT 0.0,
                m2   REAL DEFAULT 0.0,
                UNIQUE(username, hour_of_day)
            );

            CREATE TABLE IF NOT EXISTS ueba_user_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                hit_count INTEGER DEFAULT 1,
                UNIQUE(username, ip_address)
            );

            CREATE TABLE IF NOT EXISTS ueba_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                anomaly_type TEXT,
                description TEXT,
                source_ip TEXT,
                hour_of_day INTEGER,
                z_score REAL,
                fired_at TEXT
            );

            CREATE TABLE IF NOT EXISTS ueba_user_risk (
                username TEXT PRIMARY KEY,
                risk_score REAL DEFAULT 0.0,
                last_updated TEXT
            );
            """)
            conn.commit()

    # ── Public API ────────────────────────────────────────────────────────────

    def record_event(self, event: Dict) -> Optional[Dict]:
        """
        Record a user event and return an anomaly dict if one is detected,
        or None if behaviour is normal.
        """
        username = (
            event.get("username")
            or event.get("parsed", {}).get("username")
            or event.get("details", {}).get("username")
        )
        if not username or username in ("-", "unknown", ""):
            return None

        source_ip = event.get("source_ip") or event.get("source", "")
        now = datetime.now()
        hour = now.hour
        severity = event.get("severity", "LOW").upper()

        anomalies = []

        # 1. Hour-of-day frequency baseline
        hour_anomaly = self._check_hour_baseline(username, hour, now)
        if hour_anomaly:
            anomalies.append(hour_anomaly)

        # 2. New/unknown source IP
        ip_anomaly = self._check_source_ip(username, source_ip, now)
        if ip_anomaly:
            anomalies.append(ip_anomaly)

        # 3. Update risk score
        weight = _SEVERITY_WEIGHTS.get(severity, 0)
        self._update_risk(username, weight, now)

        if not anomalies:
            return None

        # Return the highest-severity anomaly as a correlation-compatible dict
        anomaly = anomalies[0]
        return {
            "rule_id": "UEBA_ANOMALY",
            "rule_name": anomaly["anomaly_type"],
            "mitre_id": "T1078",  # Valid Accounts
            "source": source_ip or username,
            "severity": "HIGH",
            "description": anomaly["description"],
            "fired_at": now.isoformat(),
            "details": anomaly,
        }

    def get_user_risk_scores(self) -> List[Dict]:
        """Return all users sorted by risk score descending."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT username, risk_score, last_updated FROM ueba_user_risk "
                "ORDER BY risk_score DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_user_profile(self, username: str) -> Dict:
        """Return hour distribution + known IPs + recent anomalies for a user."""
        with self._conn() as conn:
            hours = conn.execute(
                "SELECT hour_of_day, sample_count, mean FROM ueba_user_hours "
                "WHERE username=? ORDER BY hour_of_day",
                (username,),
            ).fetchall()
            ips = conn.execute(
                "SELECT ip_address, first_seen, last_seen, hit_count FROM ueba_user_ips "
                "WHERE username=? ORDER BY hit_count DESC",
                (username,),
            ).fetchall()
            events = conn.execute(
                "SELECT anomaly_type, description, source_ip, fired_at, z_score "
                "FROM ueba_events WHERE username=? ORDER BY fired_at DESC LIMIT 20",
                (username,),
            ).fetchall()
            risk = conn.execute(
                "SELECT risk_score FROM ueba_user_risk WHERE username=?",
                (username,),
            ).fetchone()
        return {
            "username": username,
            "risk_score": risk["risk_score"] if risk else 0.0,
            "hour_distribution": [dict(r) for r in hours],
            "known_ips": [dict(r) for r in ips],
            "recent_anomalies": [dict(r) for r in events],
        }

    def get_anomaly_events(self, limit: int = 100) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ueba_events ORDER BY fired_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_users(self) -> List[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT username FROM ueba_user_risk ORDER BY username"
            ).fetchall()
        return [r["username"] for r in rows]

    # ── Private helpers ───────────────────────────────────────────────────────

    def _check_hour_baseline(self, username: str, hour: int, now: datetime) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT sample_count, mean, m2 FROM ueba_user_hours "
                "WHERE username=? AND hour_of_day=?",
                (username, hour),
            ).fetchone()

        n = row["sample_count"] if row else 0
        mean = row["mean"] if row else 0.0
        m2 = row["m2"] if row else 0.0

        # Welford update: treat each recorded login in this hour as count=1
        n += 1
        delta = 1.0 - mean
        mean += delta / n
        delta2 = 1.0 - mean
        m2 += delta * delta2

        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ueba_user_hours (username, hour_of_day, sample_count, mean, m2)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(username, hour_of_day) DO UPDATE SET
                     sample_count=excluded.sample_count,
                     mean=excluded.mean,
                     m2=excluded.m2""",
                (username, hour, n, mean, m2),
            )
            conn.commit()

        if n < _MIN_SAMPLES:
            return None

        variance = m2 / (n - 1) if n > 1 else 0.0
        std = math.sqrt(variance) if variance > 0 else 0.0
        if std == 0:
            return None

        # Current observed rate vs baseline mean activity for this hour
        # Flag if this hour has very LOW baseline (user never active here)
        if mean < 0.1 and n >= _MIN_SAMPLES:
            z = 3.0  # Effectively no prior activity this hour
        else:
            return None  # hour has normal traffic

        description = (
            f"User '{username}' active at hour {hour:02d}:xx — "
            f"baseline mean activity={mean:.2f} (very unusual time)"
        )
        self._store_ueba_event(username, "Unusual Login Hour", description, "", hour, z, now)
        return {"anomaly_type": "Unusual Login Hour", "description": description, "z_score": z}

    def _check_source_ip(self, username: str, ip: str, now: datetime) -> Optional[Dict]:
        if not ip or ip in ("unknown", ""):
            return None
        now_str = now.isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT hit_count FROM ueba_user_ips WHERE username=? AND ip_address=?",
                (username, ip),
            ).fetchone()

            if row:
                conn.execute(
                    "UPDATE ueba_user_ips SET last_seen=?, hit_count=hit_count+1 "
                    "WHERE username=? AND ip_address=?",
                    (now_str, username, ip),
                )
            else:
                conn.execute(
                    "INSERT INTO ueba_user_ips (username, ip_address, first_seen, last_seen, hit_count) "
                    "VALUES (?, ?, ?, ?, 1)",
                    (username, ip, now_str, now_str),
                )
                conn.commit()
                # New IP = anomaly (only after we've seen 3+ known IPs, meaning user is established)
                total_ips = conn.execute(
                    "SELECT COUNT(*) FROM ueba_user_ips WHERE username=?", (username,)
                ).fetchone()[0]
                conn.commit()
                if total_ips > 3:
                    desc = f"User '{username}' authenticated from new IP {ip} (not seen before)"
                    self._store_ueba_event(username, "New Source IP", desc, ip, None, None, now)
                    return {"anomaly_type": "New Source IP", "description": desc, "ip": ip}
                return None
            conn.commit()
        return None

    def _update_risk(self, username: str, weight: float, now: datetime):
        now_str = now.isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ueba_user_risk (username, risk_score, last_updated)
                   VALUES (?, ?, ?)
                   ON CONFLICT(username) DO UPDATE SET
                     risk_score = MIN(risk_score + ?, 1000.0),
                     last_updated = excluded.last_updated""",
                (username, weight, now_str, weight),
            )
            conn.commit()

    def _store_ueba_event(self, username, anomaly_type, description, ip, hour, z, now):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ueba_events
                   (username, anomaly_type, description, source_ip, hour_of_day, z_score, fired_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (username, anomaly_type, description, ip, hour,
                 round(z, 3) if z is not None else None, now.isoformat()),
            )
            conn.commit()
