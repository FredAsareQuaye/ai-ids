"""
False Positive Whitelist Manager
Suppresses known-safe sources, IPs, usernames, and patterns from
triggering correlations or creating noise in the dashboard.
"""
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

WHITELIST_TYPES = ("ip", "hostname", "username", "source", "pattern")

_DEFAULTS = [
    ("ip",       "127.0.0.1",       "Localhost IPv4"),
    ("ip",       "::1",             "Localhost IPv6"),
    ("hostname", "localhost",       "Localhost hostname"),
    ("source",   "playbook_engine", "Internal SIEM automation"),
    ("source",   "siem_system",     "Internal SIEM system"),
]


class WhitelistManager:
    """
    Manages whitelist entries backed by SQLite.
    Results are cached in memory and invalidated on writes.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = str(
            db_path
            or Path(__file__).resolve().parent.parent.parent / "siem.db"
        )
        self._cache: Optional[List[Dict]] = None
        self._ensure_table()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def is_whitelisted(self, event: Dict[str, Any]) -> bool:
        """
        Return True if the event matches any active whitelist entry.
        Checks source, message, and agent_id fields.
        """
        source  = str(event.get("source", "")).lower()
        message = str(event.get("message", "")).lower()

        for entry in self._entries():
            wtype = entry["type"]
            value = entry["value"].lower()
            try:
                if wtype == "ip":
                    if value in source or value in message:
                        return True
                elif wtype in ("hostname", "source"):
                    if value == source or value in source:
                        return True
                elif wtype == "username":
                    if value in message:
                        return True
                elif wtype == "pattern":
                    if re.search(value, message, re.IGNORECASE):
                        return True
            except Exception:
                continue
        return False

    def add(
        self,
        wtype: str,
        value: str,
        reason: str = "",
        created_by: str = "admin",
    ) -> int:
        if wtype not in WHITELIST_TYPES:
            raise ValueError(f"type must be one of {WHITELIST_TYPES}")
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT OR REPLACE INTO whitelist
               (type, value, reason, created_by, is_active)
               VALUES (?, ?, ?, ?, 1)""",
            (wtype, value, reason, created_by),
        )
        conn.commit()
        row_id = cursor.lastrowid
        conn.close()
        self._invalidate()
        logger.info(f"Whitelist added: {wtype}={value!r} ({reason})")
        return row_id

    def remove(self, entry_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE whitelist SET is_active = 0 WHERE id = ?", (entry_id,)
        )
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        self._invalidate()
        return affected > 0

    def list_entries(self, include_inactive: bool = False) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        sql = "SELECT * FROM whitelist"
        if not include_inactive:
            sql += " WHERE is_active = 1"
        sql += " ORDER BY created_at DESC"
        cursor.execute(sql)
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _entries(self) -> List[Dict]:
        if self._cache is None:
            self._cache = self.list_entries()
        return self._cache

    def _invalidate(self):
        self._cache = None

    def _ensure_table(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                type       TEXT NOT NULL,
                value      TEXT NOT NULL,
                reason     TEXT DEFAULT '',
                created_by TEXT DEFAULT 'system',
                is_active  INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(type, value)
            )
        """)
        conn.commit()
        for wtype, value, reason in _DEFAULTS:
            conn.execute(
                "INSERT OR IGNORE INTO whitelist (type, value, reason, created_by) VALUES (?, ?, ?, 'system')",
                (wtype, value, reason),
            )
        conn.commit()
        conn.close()
