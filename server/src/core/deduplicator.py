"""
Alert Deduplication & Noise Reduction

Groups repeated identical/similar events into a single aggregated alert
with a hit counter and last-seen timestamp.

Algorithm:
  - Signature = hash(source + severity + message[:80])
  - If the same signature arrives within the suppression window:
      → increment hit_count, update last_seen, return None (suppress)
  - Otherwise create/reopen the group and return it for normal processing.

Config (server/.env):
  DEDUP_WINDOW_SECONDS=600   (default 10 minutes)
  DEDUP_ENABLED=true
"""
import hashlib
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class Deduplicator:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.window = int(os.getenv("DEDUP_WINDOW_SECONDS", "600"))
        self.enabled = os.getenv("DEDUP_ENABLED", "true").lower() in ("true", "1", "yes")
        self._init_tables()

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
            conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signature TEXT UNIQUE NOT NULL,
                source TEXT,
                severity TEXT,
                message TEXT,
                first_seen TEXT,
                last_seen TEXT,
                hit_count INTEGER DEFAULT 1,
                suppressed_until TEXT
            )
            """)
            conn.commit()

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, event: Dict) -> bool:
        """
        Returns True  → event is a duplicate, suppress it.
        Returns False → event is new or the window expired, process normally.
        """
        if not self.enabled:
            return False

        sig = self._signature(event)
        now = datetime.now()
        now_str = now.isoformat()

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM alert_groups WHERE signature=?", (sig,)
            ).fetchone()

            if row:
                suppressed_until_str = row["suppressed_until"]
                try:
                    suppressed_until = datetime.fromisoformat(suppressed_until_str)
                except Exception:
                    suppressed_until = now

                if now < suppressed_until:
                    # Still within window — increment and suppress
                    conn.execute(
                        "UPDATE alert_groups SET hit_count=hit_count+1, last_seen=? WHERE signature=?",
                        (now_str, sig),
                    )
                    conn.commit()
                    logger.debug(f"Deduplicated event (sig={sig[:12]}…) hit_count={row['hit_count']+1}")
                    return True
                else:
                    # Window expired — reopen group with new window
                    new_until = (now + timedelta(seconds=self.window)).isoformat()
                    conn.execute(
                        """UPDATE alert_groups SET
                             hit_count=hit_count+1, last_seen=?,
                             suppressed_until=?
                           WHERE signature=?""",
                        (now_str, new_until, sig),
                    )
                    conn.commit()
                    return False  # Let it through as a "re-occurrence"
            else:
                # Brand new signature
                until = (now + timedelta(seconds=self.window)).isoformat()
                conn.execute(
                    """INSERT INTO alert_groups
                       (signature, source, severity, message, first_seen, last_seen, hit_count, suppressed_until)
                       VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
                    (
                        sig,
                        event.get("source", ""),
                        event.get("severity", ""),
                        event.get("message", "")[:200],
                        now_str, now_str, until,
                    ),
                )
                conn.commit()
                return False

    def get_groups(self, limit: int = 200) -> List[Dict]:
        """Return deduplicated alert groups sorted by hit_count descending."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alert_groups ORDER BY hit_count DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM alert_groups").fetchone()[0]
            suppressed = conn.execute(
                "SELECT SUM(hit_count - 1) FROM alert_groups WHERE hit_count > 1"
            ).fetchone()[0] or 0
            top = conn.execute(
                "SELECT source, severity, hit_count FROM alert_groups ORDER BY hit_count DESC LIMIT 5"
            ).fetchall()
        return {
            "total_groups": total,
            "total_suppressed": suppressed,
            "top_repeated": [dict(r) for r in top],
        }

    def clear_expired(self):
        """Clean up groups whose suppression window expired more than 24h ago."""
        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM alert_groups WHERE suppressed_until < ?", (cutoff,)
            )
            conn.commit()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _signature(event: Dict) -> str:
        source = event.get("source", "")
        severity = event.get("severity", "")
        msg = event.get("message", "")[:80]
        raw = f"{source}|{severity}|{msg}"
        return hashlib.sha256(raw.encode()).hexdigest()
