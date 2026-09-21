"""
Statistical Volume Anomaly Detector.
Uses Welford's online algorithm to maintain a rolling mean/variance of
events-per-source per hour-of-day. Fires when the current hour's count
exceeds mean + Z_THRESHOLD * stdev (with MIN_SAMPLES baseline buckets).
"""
import logging
import math
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnomalyDetector:
    MIN_SAMPLES = 3      # baseline buckets before alerting
    Z_THRESHOLD = 2.5    # std-deviations above mean to trigger

    def __init__(self, db_path: str):
        self.db_path = db_path
        # In-memory: {source: {hour_key: count}}
        self._hourly: Dict[str, Dict[str, int]] = {}
        self._init_db()
        # Warm the Welford baseline from stored event history so the detector
        # can fire on day one instead of after MIN_SAMPLES baseline days.
        self.seed_baselines_from_history()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    hour_of_day INTEGER NOT NULL,
                    sample_count INTEGER DEFAULT 0,
                    mean REAL DEFAULT 0.0,
                    m2 REAL DEFAULT 0.0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(source, hour_of_day)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomaly_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    hour_of_day INTEGER NOT NULL,
                    observed_count INTEGER NOT NULL,
                    expected_mean REAL NOT NULL,
                    z_score REAL NOT NULL,
                    fired_at TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def seed_baselines_from_history(self, days: int = 7) -> int:
        """Backfill the Welford baseline from stored event history.

        Groups stored events by (source, hour_of_day) over the last `days`
        days and feeds each bucket count through the same Welford update used
        by live events.
        """
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT source,
                       CAST(strftime('%H', timestamp) AS INTEGER) AS hour_of_day,
                       COUNT(*) AS cnt
                FROM logs
                WHERE timestamp >= datetime('now', ? || ' days')
                GROUP BY source, hour_of_day
                """,
                (f"-{days}",),
            )
            rows = cursor.fetchall()
            for source, hour, cnt in rows:
                self._update_baseline(source, hour, cnt)
            return len(rows)
        finally:
            conn.close()

    def record_event(self, source: str) -> Optional[Dict]:
        """Record one event from source for the current hour.

        Returns an anomaly correlation dict if the z-threshold is exceeded,
        else None.
        """
        now = datetime.now()
        hour = now.hour
        hour_key = f"{now.year}-{now.month:02d}-{now.day:02d}-{hour:02d}"

        if source not in self._hourly:
            self._hourly[source] = {}

        for hkey in list(self._hourly.get(source, {}).keys()):
            if hkey != hour_key:
                self._flush_bucket(source, hkey)

        self._hourly[source][hour_key] = self._hourly[source].get(hour_key, 0) + 1
        count = self._hourly[source][hour_key]

        return self._check(source, hour, count, now)

    def _flush_bucket(self, source: str, hour_key: str):
        count = self._hourly.get(source, {}).pop(hour_key, 0)
        parts = hour_key.split("-")
        if len(parts) >= 4:
            self._update_baseline(source, int(parts[3]), count)

    def _check(self, source: str, hour: int, count: int, now: datetime) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT sample_count, mean, m2 FROM anomaly_baselines WHERE source=? AND hour_of_day=?",
                (source, hour),
            )
            row = cursor.fetchone()
            if not row or row[0] < self.MIN_SAMPLES:
                return None

            n, mean, m2 = row
            stdev = math.sqrt(m2 / n) if n > 1 else 0
            if stdev == 0:
                return None

            z = (count - mean) / stdev
            if z < self.Z_THRESHOLD:
                return None

            threshold_count = int(mean + self.Z_THRESHOLD * stdev)
            return {
                "rule_id": "ANOMALY_VOLUME",
                "rule_name": "Statistical Volume Anomaly",
                "mitre_id": "T1499",
                "mitre_tactic": "Impact",
                "mitre_url": "https://attack.mitre.org/techniques/T1499/",
                "description": (
                    f"Source '{source}' sent {count} events at hour {hour:02d}:00 "
                    f"(baseline ~{mean:.1f}, z-score={z:.1f})"
                ),
                "severity": "HIGH",
                "source": source,
                "matched_count": count,
                "threshold": threshold_count,
                "window_seconds": 3600,
                "fired_at": now.isoformat(),
                "sample_events": [],
            }
        finally:
            conn.close()

    def _update_baseline(self, source: str, hour: int, count: int):
        """Welford online mean/variance update."""
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.execute(
                "SELECT sample_count, mean, m2 FROM anomaly_baselines WHERE source=? AND hour_of_day=?",
                (source, hour),
            )
            row = cur.fetchone()
            if row:
                n, mean, m2 = row
                n += 1
                delta = count - mean
                mean += delta / n
                m2 += delta * (count - mean)
                conn.execute(
                    "UPDATE anomaly_baselines SET sample_count=?, mean=?, m2=?, updated_at=CURRENT_TIMESTAMP WHERE source=? AND hour_of_day=?",
                    (n, mean, m2, source, hour),
                )
                conn.commit()
            else:
                conn.execute(
                    "INSERT INTO anomaly_baselines (source, hour_of_day, sample_count, mean, m2) VALUES (?, ?, 1, ?, 0.0)",
                    (source, hour, float(count)),
                )
                conn.commit()
        finally:
            conn.close()

    def get_baselines(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM anomaly_baselines ORDER BY source, hour_of_day")
            return cursor.fetchall()
        finally:
            conn.close()

    def get_anomaly_events(self, limit: int = 100):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM anomaly_events ORDER BY fired_at DESC LIMIT ?", (limit,))
            return cursor.fetchall()
        finally:
            conn.close()
