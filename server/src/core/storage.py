import os
import sqlite3
import json
import logging
from datetime import datetime  # type: ignore
from pathlib import Path
from contextlib import contextmanager
from typing import List, Dict, Any, Optional

class Database:
    def __init__(self, db_name="siem.db"):
        # Get absolute path for database file
        env_db = os.getenv("DB_PATH")
        if env_db:
            self.db_path = Path(env_db)
        else:
            self.db_path = Path(__file__).resolve().parent.parent.parent / db_name
        self.logger = logging.getLogger(__name__)
        self._init_db()  # Initialize db on creation

    def _init_db(self):
        """Initialize the database and create tables if they don't exist"""
        self.logger.info(f"Initializing database at: {self.db_path}")

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT,
                    analysis TEXT,
                    threat_intel TEXT,
                    agent_id TEXT,
                    ai_analysis TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Migration: add ai_analysis column to existing DBs
            try:
                cursor.execute("ALTER TABLE logs ADD COLUMN ai_analysis TEXT")
            except Exception:
                pass  # Column already exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_vulnerability_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    machine_name TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    vulnerabilities_found INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    details TEXT NOT NULL,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    vulnerabilities TEXT NOT NULL,
                    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # MITRE ATT&CK Correlations
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    mitre_id TEXT NOT NULL,
                    mitre_tactic TEXT NOT NULL,
                    mitre_url TEXT,
                    description TEXT,
                    severity TEXT NOT NULL,
                    source TEXT NOT NULL,
                    matched_count INTEGER DEFAULT 1,
                    threshold INTEGER DEFAULT 1,
                    window_seconds INTEGER DEFAULT 60,
                    fired_at TEXT NOT NULL,
                    sample_events TEXT,
                    acknowledged INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Remote agent registry
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agent_registry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT UNIQUE NOT NULL,
                    hostname TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    ip_address TEXT,
                    token TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    version TEXT DEFAULT "1.0",
                    last_seen TIMESTAMP,
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Playbook execution audit log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS playbook_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    playbook_id TEXT NOT NULL,
                    playbook_name TEXT NOT NULL,
                    triggered_by TEXT NOT NULL,
                    source TEXT NOT NULL,
                    executed_at TEXT NOT NULL,
                    actions TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.commit()

    @contextmanager
    def get_connection(self):
        """Create a database connection context"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def store_event(self, log_data: Dict[str, Any]):
        """Store a log event in the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO logs (
                    timestamp, source, message, severity, details, analysis
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                log_data.get('timestamp'),
                log_data.get('source'),
                log_data.get('message'),
                log_data.get('severity'),
                json.dumps(log_data.get('details', {})),
                json.dumps(log_data.get('analysis', {}))
            ))
            conn.commit()
            message = log_data.get('message', '')
            self.logger.info(f"Stored log event: {message[:50] if message else 'Unknown'}...")

    def store_events_batch(self, entries):
        """Store multiple log events in a single transaction — fast bulk ingest."""
        if not entries:
            return 0
        with self.get_connection() as conn:
            cursor = conn.cursor()
            rows = []
            for e in entries:
                rows.append((
                    e.get('timestamp'),
                    e.get('source'),
                    e.get('message'),
                    e.get('severity'),
                    json.dumps(e.get('details', {})),
                    json.dumps(e.get('analysis', {})),
                ))
            cursor.executemany("""
                INSERT INTO logs (
                    timestamp, source, message, severity, details, analysis
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            return len(rows)

    def get_threats_by_source(self, source: str) -> List[Dict[str, Any]]:
        """Get threats filtered by source"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM logs 
                WHERE source = ? 
                ORDER BY timestamp DESC
            """, (source,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def store_ai_vulnerability_scan(self, scan_data: dict) -> int:
        """Store AI vulnerability scan results"""
        query = '''
            INSERT INTO ai_vulnerability_scans 
            (machine_name, scan_type, vulnerabilities_found, risk_score, details)
            VALUES (?, ?, ?, ?, ?)
        '''
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                scan_data['machine_name'],
                scan_data['scan_type'],
                scan_data['vulnerabilities_found'],
                scan_data['risk_score'],
                json.dumps(scan_data['details'])
            ))
            conn.commit()
            return cursor.lastrowid

    def store_vulnerability_scan(self, scan_data: dict) -> int:
        query = '''
            INSERT INTO vulnerability_scans 
            (target, scan_type, vulnerabilities, scan_date)
            VALUES (?, ?, ?, ?)
        '''
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                scan_data['target'],
                scan_data['scan_type'],
                json.dumps(scan_data['vulnerabilities']),
                scan_data['scan_date']
            ))
            conn.commit()
            return cursor.lastrowid

    def get_ai_vulnerability_scans(self) -> List[dict]:
        """Retrieve all AI vulnerability scans"""
        query = 'SELECT * FROM ai_vulnerability_scans ORDER BY scan_date DESC'
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def get_vulnerability_scans(self) -> list:
        query = 'SELECT * FROM vulnerability_scans ORDER BY scan_date DESC'
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def get_threats(self, limit=500) -> List[Dict]:
        """Retrieve recent threats from the database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [{
                'id': row['id'],
                'timestamp': row['timestamp'],
                'source': row['source'],
                'message': row['message'],
                'severity': row['severity'],
                'details': json.loads(row['details']) if row['details'] else {},
                'analysis': json.loads(row['analysis']) if row['analysis'] else {}
            } for row in rows]

    def get_threats_by_severity(self, severity: str) -> List[Dict]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM logs 
                WHERE LOWER(severity) = LOWER(?)
                ORDER BY timestamp DESC
            """, (severity,))
            rows = cursor.fetchall()
            return [{
                'id': row['id'],
                'timestamp': row['timestamp'],
                'source': row['source'],
                'message': row['message'],
                'severity': row['severity'],
                'details': json.loads(row['details']) if row['details'] else {},
                'analysis': json.loads(row['analysis']) if row['analysis'] else {}
            } for row in rows]

    def get_threat_stats(self) -> Dict[str, int]:
        """Get threat statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    severity,
                    COUNT(*) as count
                FROM logs
                GROUP BY severity
            """)
            stats = dict(cursor.fetchall())
            return {
                'total': sum(stats.values()),
                'high': stats.get('high', 0),
                'medium': stats.get('medium', 0),
                'low': stats.get('low', 0)
            }

    def get_threat_by_id(self, alert_id: int) -> Dict[str, Any] | None:
        """Get a specific threat by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM logs WHERE id = ?
            """, (alert_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            return {
                'id': row['id'],
                'timestamp': row['timestamp'],
                'source': row['source'],
                'message': row['message'],
                'severity': row['severity'],
                'details': json.loads(row['details']) if row['details'] else {},
                'analysis': json.loads(row['analysis']) if row['analysis'] else {}
            }

    def store_log(self, log_data: Dict[str, Any], analysis: Dict[str, Any]) -> None:
        """Async-compatible alias used by LogProcessor"""
        self.store_event({**log_data, "analysis": analysis})

    def store_correlation(self, data: Dict[str, Any]):
        """Store a fired MITRE ATT&CK correlation"""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO correlations
                (rule_id, rule_name, mitre_id, mitre_tactic, mitre_url,
                 description, severity, source, matched_count, threshold,
                 window_seconds, fired_at, sample_events)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.get("rule_id"),
                data.get("rule_name"),
                data.get("mitre_id"),
                data.get("mitre_tactic"),
                data.get("mitre_url"),
                data.get("description"),
                data.get("severity"),
                data.get("source"),
                data.get("matched_count", 1),
                data.get("threshold", 1),
                data.get("window_seconds", 60),
                data.get("fired_at"),
                json.dumps(data.get("sample_events", [])),
            ))
            conn.commit()

    def get_correlations(self, hours: int = 24) -> List[Dict]:
        """Return correlations fired in the last N hours"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM correlations
                WHERE fired_at >= datetime('now', ? || ' hours')
                ORDER BY fired_at DESC
            """, (f"-{hours}",))
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                if d.get("sample_events"):
                    try:
                        d["sample_events"] = json.loads(d["sample_events"])
                    except Exception:
                        pass
                result.append(d)
            return result

    def register_agent(self, agent_data: Dict[str, Any]) -> int:
        """Register or update a remote monitoring agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO agent_registry
                (agent_id, hostname, platform, ip_address, token, version)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    platform=excluded.platform,
                    ip_address=excluded.ip_address,
                    last_seen=CURRENT_TIMESTAMP,
                    version=excluded.version,
                    is_active=1
            """, (
                agent_data["agent_id"],
                agent_data["hostname"],
                agent_data["platform"],
                agent_data.get("ip_address", ""),
                agent_data["token"],
                agent_data.get("version", "1.0"),
            ))
            conn.commit()
            return cursor.lastrowid

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Look up a registered agent by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM agent_registry WHERE agent_id = ?", (agent_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_agents(self) -> List[Dict]:
        """Return all registered agents"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM agent_registry ORDER BY last_seen DESC"
            )
            return [dict(row) for row in cursor.fetchall()]

    def store_playbook_execution(self, report: Dict[str, Any]):
        """Store a playbook execution report"""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO playbook_executions
                (playbook_id, playbook_name, triggered_by, source, executed_at, actions)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                report.get("playbook_id"),
                report.get("playbook_name"),
                report.get("triggered_by"),
                report.get("source"),
                report.get("executed_at"),
                json.dumps(report.get("actions", [])),
            ))
            conn.commit()

    def get_playbook_executions(self, limit: int = 100) -> List[Dict]:
        """Return recent playbook execution reports"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM playbook_executions ORDER BY executed_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
            result = []
            for row in rows:
                d = dict(row)
                if d.get("actions"):
                    try:
                        d["actions"] = json.loads(d["actions"])
                    except Exception:
                        pass
                result.append(d)
            return result

    def update_agent_seen(self, agent_id: str):
        """Update last_seen timestamp for an agent"""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE agent_registry SET last_seen=CURRENT_TIMESTAMP WHERE agent_id=?",
                (agent_id,),
            )
            conn.commit()

    def clear_all_logs(self) -> bool:
        """Dangerous method to clear all security logs from the database"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Clear all log-related tables
                tables_to_clear = ['logs', 'security_logs']
                
                for table in tables_to_clear:
                    try:
                        cursor.execute(f"DELETE FROM {table}")
                        self.logger.info(f"Cleared table: {table}")
                    except Exception as e:
                        self.logger.warning(f"Could not clear table {table}: {e}")
                
                # Reset auto-increment counters
                for table in tables_to_clear:
                    try:
                        cursor.execute(f"DELETE FROM sqlite_sequence WHERE name='{table}'")
                    except Exception:
                        pass  # Table might not have auto-increment
                
                conn.commit()
                self.logger.warning("⚠️ ALL SECURITY LOGS HAVE BEEN PERMANENTLY DELETED!")
                return True
                
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return False