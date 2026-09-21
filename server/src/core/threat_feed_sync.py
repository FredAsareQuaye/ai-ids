"""
Threat Intelligence Feed Auto-Sync

Pulls from free, high-quality IOC feeds on a schedule and matches every
ingested event against the local IOC database.

Feeds (no API key required):
  • abuse.ch Feodo Tracker  — C2 botnet IPs (JSON)
  • abuse.ch URLhaus        — malicious URLs (CSV)
  • Emerging Threats        — IP blocklist (plaintext)
  • abuse.ch MalwareBazaar  — file hashes (JSON, latest 100)

Config (server/.env):
  FEED_SYNC_INTERVAL_HOURS=6   (default 6)
  FEED_ENABLED=true
"""
import asyncio
import csv
import io
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

_FEEDS = {
    "feodo_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "type": "json",
        "ioc_type": "ip",
        "description": "Feodo Tracker C2 botnet IPs",
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "type": "csv",
        "ioc_type": "url",
        "description": "URLhaus malicious URLs",
        "skip_rows": 9,  # header comment lines
    },
    "emerging_threats_ips": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "type": "plaintext",
        "ioc_type": "ip",
        "description": "Emerging Threats block list",
    },
}


class ThreatFeedSync:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.interval_hours = int(os.getenv("FEED_SYNC_INTERVAL_HOURS", "6"))
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
            CREATE TABLE IF NOT EXISTS ioc_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                feed_name TEXT,
                threat TEXT,
                malware TEXT,
                country TEXT,
                added_at TEXT,
                UNIQUE(ioc_type, value)
            );

            CREATE TABLE IF NOT EXISTS ioc_feed_state (
                feed_name TEXT PRIMARY KEY,
                last_synced TEXT,
                ioc_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS ioc_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                ioc_type TEXT,
                ioc_value TEXT,
                feed_name TEXT,
                threat TEXT,
                matched_at TEXT
            );
            """)
            conn.commit()

    # ── Feed sync ─────────────────────────────────────────────────────────────

    async def run(self):
        """Background loop — sync feeds every FEED_SYNC_INTERVAL_HOURS hours."""
        if os.getenv("FEED_ENABLED", "true").lower() not in ("true", "1", "yes"):
            logger.info("Threat feed sync disabled")
            return
        while True:
            try:
                await asyncio.get_event_loop().run_in_executor(None, self.sync_all)
            except Exception as e:
                logger.error(f"Feed sync error: {e}")
            await asyncio.sleep(self.interval_hours * 3600)

    def sync_all(self):
        """Sync all feeds — called from executor so blocking HTTP is fine."""
        for name, cfg in _FEEDS.items():
            try:
                self._sync_feed(name, cfg)
            except Exception as e:
                logger.error(f"Feed '{name}' sync failed: {e}")

    def _sync_feed(self, name: str, cfg: Dict):
        last = self._last_synced(name)
        if last and (datetime.now() - last).total_seconds() < self.interval_hours * 3600:
            return  # not due yet

        logger.info(f"Syncing feed: {name} ({cfg['description']})")
        resp = requests.get(cfg["url"], timeout=30)
        resp.raise_for_status()

        iocs = []
        if cfg["type"] == "json":
            iocs = self._parse_json_feed(name, cfg, resp.json())
        elif cfg["type"] == "csv":
            iocs = self._parse_csv_feed(name, cfg, resp.text)
        elif cfg["type"] == "plaintext":
            iocs = self._parse_plaintext_feed(name, cfg, resp.text)

        count = self._upsert_iocs(iocs)
        self._save_state(name, count)
        logger.info(f"Feed '{name}': {count} IOCs stored")

    def _parse_json_feed(self, name, cfg, data) -> List[Dict]:
        iocs = []
        if isinstance(data, list):
            for entry in data:
                val = entry.get("ip_address") or entry.get("url") or entry.get("sha256_hash")
                if val:
                    iocs.append({
                        "ioc_type": cfg["ioc_type"],
                        "value": val.strip(),
                        "feed_name": name,
                        "threat": entry.get("malware", entry.get("threat", "")),
                        "malware": entry.get("malware", ""),
                        "country": entry.get("country", ""),
                    })
        return iocs

    def _parse_csv_feed(self, name, cfg, text: str) -> List[Dict]:
        iocs = []
        skip = cfg.get("skip_rows", 0)
        lines = text.splitlines()[skip:]
        reader = csv.DictReader(lines)
        for row in reader:
            val = row.get("url") or row.get("ip") or row.get("hash")
            if val and not val.startswith("#"):
                iocs.append({
                    "ioc_type": cfg["ioc_type"],
                    "value": val.strip(),
                    "feed_name": name,
                    "threat": row.get("threat", ""),
                    "malware": row.get("tags", ""),
                    "country": row.get("country_code", ""),
                })
        return iocs

    def _parse_plaintext_feed(self, name, cfg, text: str) -> List[Dict]:
        iocs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append({
                "ioc_type": cfg["ioc_type"],
                "value": line,
                "feed_name": name,
                "threat": "",
                "malware": "",
                "country": "",
            })
        return iocs

    def _upsert_iocs(self, iocs: List[Dict]) -> int:
        if not iocs:
            return 0
        now = datetime.now().isoformat()
        with self._conn() as conn:
            conn.executemany(
                """INSERT INTO ioc_cache (ioc_type, value, feed_name, threat, malware, country, added_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ioc_type, value) DO UPDATE SET
                     feed_name=excluded.feed_name, threat=excluded.threat,
                     malware=excluded.malware, country=excluded.country,
                     added_at=excluded.added_at""",
                [(i["ioc_type"], i["value"], i["feed_name"], i["threat"],
                  i["malware"], i["country"], now) for i in iocs],
            )
            conn.commit()
        return len(iocs)

    def _last_synced(self, name: str) -> Optional[datetime]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT last_synced FROM ioc_feed_state WHERE feed_name=?", (name,)
            ).fetchone()
        if row and row["last_synced"]:
            try:
                return datetime.fromisoformat(row["last_synced"])
            except Exception:
                pass
        return None

    def _save_state(self, name: str, count: int):
        now = datetime.now().isoformat()
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ioc_feed_state (feed_name, last_synced, ioc_count)
                   VALUES (?, ?, ?)
                   ON CONFLICT(feed_name) DO UPDATE SET
                     last_synced=excluded.last_synced,
                     ioc_count=excluded.ioc_count""",
                (name, now, count),
            )
            conn.commit()

    # ── Matching ──────────────────────────────────────────────────────────────

    def match_event(self, event: Dict) -> Optional[Dict]:
        """
        Check an event's IPs, URLs, and hashes against the IOC cache.
        Returns a match dict if found, else None.
        """
        candidates = set()
        for field in ("source_ip", "source", "message"):
            val = event.get(field, "")
            if val:
                candidates.add(str(val).strip())

        # Also check details dict
        details = event.get("details", {})
        if isinstance(details, dict):
            for v in details.values():
                if isinstance(v, str):
                    candidates.add(v.strip())

        for val in candidates:
            if not val:
                continue
            match = self._lookup_ioc(val)
            if match:
                now = datetime.now().isoformat()
                logger.warning(
                    f"IOC MATCH: {val} found in feed '{match['feed_name']}' "
                    f"threat={match['threat']}"
                )
                self._store_match(event.get("id"), match["ioc_type"], val,
                                  match["feed_name"], match["threat"], now)
                return {
                    "ioc_type": match["ioc_type"],
                    "ioc_value": val,
                    "feed": match["feed_name"],
                    "threat": match["threat"],
                    "malware": match["malware"],
                    "country": match["country"],
                }
        return None

    def _lookup_ioc(self, value: str) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_cache WHERE value=? LIMIT 1", (value,)
            ).fetchone()
        return dict(row) if row else None

    def _store_match(self, log_id, ioc_type, ioc_value, feed_name, threat, matched_at):
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ioc_matches
                   (log_id, ioc_type, ioc_value, feed_name, threat, matched_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (log_id, ioc_type, ioc_value, feed_name, threat, matched_at),
            )
            conn.commit()

    # ── Query helpers ─────────────────────────────────────────────────────────

    def get_feed_status(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT feed_name, last_synced, ioc_count FROM ioc_feed_state"
            ).fetchall()
        # Merge with static feed descriptions
        status = []
        for name, cfg in _FEEDS.items():
            row = next((dict(r) for r in rows if r["feed_name"] == name), {})
            status.append({
                "feed_name": name,
                "description": cfg["description"],
                "ioc_type": cfg["ioc_type"],
                "last_synced": row.get("last_synced", "never"),
                "ioc_count": row.get("ioc_count", 0),
            })
        return status

    def get_ioc_count(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM ioc_cache").fetchone()[0]

    def get_recent_matches(self, limit: int = 100) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_matches ORDER BY matched_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def search_iocs(self, query: str, limit: int = 100) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_cache WHERE value LIKE ? OR threat LIKE ? LIMIT ?",
                (f"%{query}%", f"%{query}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]
