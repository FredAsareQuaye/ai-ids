"""
Custom Playbook Store — DB-backed user-defined automation rules.

Each custom playbook has:
  - trigger: { field, operator, value }  e.g. severity == CRITICAL
  - actions: list of { type, params }    e.g. log_event, block_ip, webhook
  - enabled flag

The PlaybookRunner evaluates custom playbooks against every processed event
and executes matching ones through the existing PlaybookEngine action handlers.
"""
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

TRIGGER_FIELDS = ["severity", "source", "source_ip", "event_type", "message"]
TRIGGER_OPS = ["==", "!=", "contains", "not_contains", "starts_with", "regex"]
ACTION_TYPES = ["log_event", "block_ip", "send_webhook", "create_case", "notify_email"]


class CustomPlaybookStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
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
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS custom_playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                trigger_field TEXT NOT NULL,
                trigger_operator TEXT NOT NULL,
                trigger_value TEXT NOT NULL,
                actions TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                created_by TEXT DEFAULT 'analyst'
            );

            CREATE TABLE IF NOT EXISTS custom_playbook_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_id INTEGER,
                playbook_name TEXT,
                source TEXT,
                triggered_by TEXT,
                actions TEXT,
                executed_at TEXT
            );
            """)
            conn.commit()

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def create(self, data: Dict) -> int:
        now = datetime.now().isoformat()
        actions = data.get("actions", [])
        with self._conn() as conn:
            cursor = conn.execute(
                """INSERT INTO custom_playbooks
                   (name, description, trigger_field, trigger_operator, trigger_value,
                    actions, enabled, created_at, updated_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    data.get("name", "Unnamed"),
                    data.get("description", ""),
                    data.get("trigger_field", "severity"),
                    data.get("trigger_operator", "=="),
                    data.get("trigger_value", "CRITICAL"),
                    json.dumps(actions),
                    int(data.get("enabled", True)),
                    now, now,
                    data.get("created_by", "analyst"),
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def list_all(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM custom_playbooks ORDER BY id"
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["actions"] = json.loads(d["actions"] or "[]")
            result.append(d)
        return result

    def get(self, pb_id: int) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM custom_playbooks WHERE id=?", (pb_id,)
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["actions"] = json.loads(d["actions"] or "[]")
        return d

    def update(self, pb_id: int, data: Dict) -> bool:
        now = datetime.now().isoformat()
        allowed = {"name", "description", "trigger_field", "trigger_operator",
                   "trigger_value", "actions", "enabled"}
        updates = {k: v for k, v in data.items() if k in allowed}
        if not updates:
            return False
        if "actions" in updates:
            updates["actions"] = json.dumps(updates["actions"])
        if "enabled" in updates:
            updates["enabled"] = int(updates["enabled"])
        updates["updated_at"] = now
        cols = ", ".join(f"{k}=?" for k in updates)
        vals = list(updates.values()) + [pb_id]
        with self._conn() as conn:
            cursor = conn.execute(
                f"UPDATE custom_playbooks SET {cols} WHERE id=?", vals
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete(self, pb_id: int) -> bool:
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM custom_playbooks WHERE id=?", (pb_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_executions(self, limit: int = 100) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM custom_playbook_executions ORDER BY executed_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["actions"] = json.loads(d["actions"] or "[]")
            result.append(d)
        return result

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, event: Dict) -> List[Dict]:
        """
        Return list of enabled playbooks whose trigger matches the event.
        """
        playbooks = self.list_all()
        matched = []
        for pb in playbooks:
            if not pb.get("enabled"):
                continue
            if self._matches(event, pb):
                matched.append(pb)
        return matched

    @staticmethod
    def _matches(event: Dict, pb: Dict) -> bool:
        field = pb["trigger_field"]
        op = pb["trigger_operator"]
        expected = pb["trigger_value"]

        val = str(event.get(field, "")).strip()
        expected = str(expected).strip()

        if op == "==":
            return val.upper() == expected.upper()
        if op == "!=":
            return val.upper() != expected.upper()
        if op == "contains":
            return expected.lower() in val.lower()
        if op == "not_contains":
            return expected.lower() not in val.lower()
        if op == "starts_with":
            return val.lower().startswith(expected.lower())
        if op == "regex":
            import re
            try:
                return bool(re.search(expected, val, re.IGNORECASE))
            except re.error:
                return False
        return False

    def record_execution(self, pb: Dict, event: Dict, actions_taken: List[str]):
        now = datetime.now().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO custom_playbook_executions
                   (playbook_id, playbook_name, source, triggered_by, actions, executed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    pb["id"],
                    pb["name"],
                    event.get("source", ""),
                    event.get("message", "")[:120],
                    json.dumps(actions_taken),
                    now,
                ),
            )
            conn.commit()
