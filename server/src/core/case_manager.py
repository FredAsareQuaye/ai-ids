"""
Incident Case Management.
Analysts can create cases from alerts, add notes, link log IDs,
track status, and close resolved incidents.
"""
import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class CaseManager:
    VALID_STATUSES = ("open", "investigating", "resolved", "closed", "false_positive")
    VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def __init__(self, db_path: Path):
        self.db_path = str(db_path)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'MEDIUM',
                    status TEXT NOT NULL DEFAULT 'open',
                    assigned_to TEXT DEFAULT '',
                    created_by TEXT DEFAULT 'analyst',
                    source TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    closed_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS case_log_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    log_id INTEGER NOT NULL,
                    added_at TEXT NOT NULL,
                    UNIQUE(case_id, log_id),
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                )
            """)
            conn.commit()
        finally:
            conn.close()

    # ── CRUD ──────────────────────────────────────────────────────────────

    def create_case(
        self,
        title: str,
        description: str = "",
        severity: str = "MEDIUM",
        assigned_to: str = "",
        created_by: str = "analyst",
        source: str = "",
        tags: List[str] = None,
        log_ids: List[int] = None,
    ) -> Dict:
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO cases
                (title, description, severity, status, assigned_to, created_by, source, tags, created_at, updated_at)
                VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
            """, (title, description, severity.upper(), assigned_to, created_by,
                  source, json.dumps(tags or []), now, now))
            case_id = cursor.lastrowid
            for lid in (log_ids or []):
                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO case_log_links (case_id, log_id, added_at) VALUES (?,?,?)",
                        (case_id, lid, now),
                    )
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()
        return self.get_case(case_id)

    def get_case(self, case_id: int) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM cases WHERE id=?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            case = dict(row)
            case["tags"] = json.loads(case.get("tags") or "[]")
            cursor.execute(
                "SELECT * FROM case_notes WHERE case_id=? ORDER BY created_at", (case_id,)
            )
            case["notes"] = [dict(r) for r in cursor.fetchall()]
            cursor.execute(
                "SELECT log_id FROM case_log_links WHERE case_id=?", (case_id,)
            )
            case["log_ids"] = [r["log_id"] for r in cursor.fetchall()]
            return case
        finally:
            conn.close()

    def list_cases(
        self,
        status: str = None,
        severity: str = None,
        limit: int = 200,
    ) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            conditions, params = [], []
            if status:
                conditions.append("status=?")
                params.append(status)
            if severity:
                conditions.append("severity=?")
                params.append(severity.upper())
            where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
            cursor.execute(
                f"SELECT * FROM cases{where} ORDER BY created_at DESC LIMIT ?",
                params + [limit],
            )
            cases = []
            for row in cursor.fetchall():
                c = dict(row)
                c["tags"] = json.loads(c.get("tags") or "[]")
                cases.append(c)
            return cases
        finally:
            conn.close()

    def update_case(self, case_id: int, updates: Dict) -> bool:
        allowed = {"title", "description", "severity", "status", "assigned_to", "tags"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        if "severity" in fields:
            fields["severity"] = fields["severity"].upper()
        now = datetime.now().isoformat()
        fields["updated_at"] = now
        if fields.get("status") in ("resolved", "closed", "false_positive"):
            fields["closed_at"] = now
        conn = sqlite3.connect(self.db_path)
        try:
            set_clause = ", ".join(f"{k}=?" for k in fields)
            conn.execute(
                f"UPDATE cases SET {set_clause} WHERE id=?",
                list(fields.values()) + [case_id],
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def add_note(self, case_id: int, author: str, note: str) -> Dict:
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO case_notes (case_id, author, note, created_at) VALUES (?,?,?,?)",
                (case_id, author, note, now),
            )
            note_id = cursor.lastrowid
            # bump updated_at
            conn.execute(
                "UPDATE cases SET updated_at=? WHERE id=?", (now, case_id)
            )
            conn.commit()
            return {"id": note_id, "case_id": case_id, "author": author,
                    "note": note, "created_at": now}
        finally:
            conn.close()

    def link_logs(self, case_id: int, log_ids: List[int]) -> int:
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        added = 0
        try:
            for lid in log_ids:
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO case_log_links (case_id, log_id, added_at) VALUES (?,?,?)",
                        (case_id, lid, now),
                    )
                    added += 1
                except Exception:
                    pass
            conn.commit()
        finally:
            conn.close()
        return added

    def get_stats(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT status, COUNT(*) FROM cases GROUP BY status")
            by_status = dict(cursor.fetchall())
            cursor.execute("SELECT severity, COUNT(*) FROM cases WHERE status NOT IN ('closed','false_positive') GROUP BY severity")
            by_severity = dict(cursor.fetchall())
            cursor.execute("SELECT COUNT(*) FROM cases")
            total = cursor.fetchone()[0]
            return {"total": total, "by_status": by_status, "open_by_severity": by_severity}
        finally:
            conn.close()
