"""
Asset Inventory + Risk Scoring.
Tracks known hosts/IPs/CIDRs with owner and criticality metadata.
High/critical assets get automatic severity boosts in the pipeline.
Per-asset risk scores are computed from recent event history.
"""
import sqlite3
import json
import logging
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_BOOST = {"critical": 2, "high": 1, "medium": 0, "low": 0}
_RISK_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class AssetInventory:
    def __init__(self, db_path: Path):
        self.db_path = str(db_path)
        self._cache: Dict[str, Dict] = {}   # ip/hostname -> asset
        self._cidr_assets: List[Dict] = []  # assets with CIDR ranges
        self._init_db()
        self._refresh_cache()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT,
                    ip_address TEXT,
                    cidr_range TEXT,
                    owner TEXT DEFAULT '',
                    criticality TEXT DEFAULT 'low',
                    description TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS asset_risk_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _refresh_cache(self):
        self._cache = {}
        self._cidr_assets = []
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM assets")
            for row in cursor.fetchall():
                a = dict(row)
                a["tags"] = json.loads(a.get("tags") or "[]")
                if a.get("ip_address"):
                    self._cache[a["ip_address"]] = a
                if a.get("hostname"):
                    self._cache[a["hostname"].lower()] = a
                if a.get("cidr_range"):
                    self._cidr_assets.append(a)
        finally:
            conn.close()

    # ── Lookup ─────────────────────────────────────────────────────────────

    def lookup(self, identifier: str) -> Optional[Dict]:
        if not identifier:
            return None
        asset = self._cache.get(identifier) or self._cache.get(identifier.lower())
        if asset:
            return asset
        # CIDR match
        try:
            addr = ipaddress.ip_address(identifier)
            for a in self._cidr_assets:
                try:
                    if addr in ipaddress.ip_network(a["cidr_range"], strict=False):
                        return a
                except Exception:
                    pass
        except ValueError:
            pass
        return None

    def enrich_event(self, event: Dict) -> Dict:
        """
        Attach asset metadata to an event and optionally boost severity.
        Returns the (possibly modified) event dict.
        """
        candidates = filter(None, [
            event.get("source_ip"),
            event.get("source"),
            event.get("host_info", {}).get("hostname"),
        ])
        asset = None
        for key in candidates:
            asset = self.lookup(key)
            if asset:
                break

        if not asset:
            return event

        event["asset"] = {
            "id": asset["id"],
            "hostname": asset.get("hostname"),
            "ip_address": asset.get("ip_address"),
            "owner": asset.get("owner"),
            "criticality": asset.get("criticality"),
            "description": asset.get("description"),
        }

        boost = _BOOST.get(asset.get("criticality", "low").lower(), 0)
        if boost > 0:
            current = event.get("severity", "LOW").upper()
            try:
                idx = _SEVERITY_ORDER.index(current)
                new_idx = min(idx + boost, len(_SEVERITY_ORDER) - 1)
                new_sev = _SEVERITY_ORDER[new_idx]
                if new_sev != current:
                    event["severity"] = new_sev
                    logger.info(
                        f"Severity {current}->{new_sev} for "
                        f"{asset.get('criticality').upper()} asset "
                        f"{asset.get('hostname') or asset.get('ip_address')}"
                    )
            except ValueError:
                pass

        # Record for risk scoring
        self._record_risk(asset["id"], event.get("severity", "LOW"))
        return event

    def _record_risk(self, asset_id: int, severity: str):
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "INSERT INTO asset_risk_events (asset_id, severity, recorded_at) VALUES (?,?,?)",
                    (asset_id, severity.upper(), datetime.now().isoformat()),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass

    # ── CRUD ──────────────────────────────────────────────────────────────

    def add_asset(self, data: Dict) -> Optional[Dict]:
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO assets
                (hostname, ip_address, cidr_range, owner, criticality, description, tags, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                data.get("hostname"), data.get("ip_address"), data.get("cidr_range"),
                data.get("owner", ""), data.get("criticality", "low").lower(),
                data.get("description", ""), json.dumps(data.get("tags", [])), now, now,
            ))
            conn.commit()
            asset_id = cursor.lastrowid
        finally:
            conn.close()
        self._refresh_cache()
        return self.get_asset(asset_id)

    def update_asset(self, asset_id: int, updates: Dict) -> bool:
        allowed = {"hostname", "ip_address", "cidr_range", "owner",
                   "criticality", "description", "tags"}
        fields = {k: v for k, v in updates.items() if k in allowed}
        if not fields:
            return False
        if "tags" in fields:
            fields["tags"] = json.dumps(fields["tags"])
        if "criticality" in fields:
            fields["criticality"] = fields["criticality"].lower()
        fields["updated_at"] = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            set_clause = ", ".join(f"{k}=?" for k in fields)
            conn.execute(
                f"UPDATE assets SET {set_clause} WHERE id=?",
                list(fields.values()) + [asset_id],
            )
            conn.commit()
        finally:
            conn.close()
        self._refresh_cache()
        return True

    def delete_asset(self, asset_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM assets WHERE id=?", (asset_id,))
            conn.execute("DELETE FROM asset_risk_events WHERE asset_id=?", (asset_id,))
            conn.commit()
        finally:
            conn.close()
        self._refresh_cache()
        return True

    def get_asset(self, asset_id: int) -> Optional[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM assets WHERE id=?", (asset_id,))
            row = cursor.fetchone()
            if not row:
                return None
            a = dict(row)
            a["tags"] = json.loads(a.get("tags") or "[]")
            return a
        finally:
            conn.close()

    def list_assets(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM assets ORDER BY criticality DESC, hostname")
            assets = []
            for row in cursor.fetchall():
                a = dict(row)
                a["tags"] = json.loads(a.get("tags") or "[]")
                assets.append(a)
            return assets
        finally:
            conn.close()

    def get_risk_scores(self) -> List[Dict]:
        """Return per-asset risk scores based on events in the last 7 days."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM assets")
            assets = [dict(r) for r in cursor.fetchall()]
            scores = []
            for a in assets:
                cursor.execute("""
                    SELECT severity, COUNT(*) as cnt FROM asset_risk_events
                    WHERE asset_id=? AND recorded_at >= datetime('now', '-7 days')
                    GROUP BY severity
                """, (a["id"],))
                score, total = 0, 0
                for row in cursor.fetchall():
                    w = _RISK_WEIGHTS.get(row["severity"], 0)
                    score += w * row["cnt"]
                    total += row["cnt"]
                scores.append({
                    "asset_id": a["id"],
                    "hostname": a.get("hostname", ""),
                    "ip_address": a.get("ip_address", ""),
                    "owner": a.get("owner", ""),
                    "criticality": a.get("criticality", "low"),
                    "risk_score": score,
                    "events_7d": total,
                    "tags": json.loads(a.get("tags") or "[]"),
                })
            scores.sort(key=lambda x: x["risk_score"], reverse=True)
            return scores
        finally:
            conn.close()
