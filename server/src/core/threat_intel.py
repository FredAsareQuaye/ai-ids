"""
IP Reputation and Threat Intelligence Module.
Uses AbuseIPDB for IP reputation checks with SQLite caching
to stay within free-tier rate limits (1000 checks/day).
"""
import logging
import sqlite3
import json
import re
import os
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

# Cache TTL: 24 hours (refresh reputation once per day per IP)
CACHE_TTL_HOURS = 24

# Private/reserved IP ranges - skip enrichment for these
PRIVATE_RANGES = [
    r"^10\.",
    r"^172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^192\.168\.",
    r"^127\.",
    r"^::1$",
    r"^localhost$",
    r"^unknown$",
]


def _is_private(ip: str) -> bool:
    for pattern in PRIVATE_RANGES:
        if re.match(pattern, ip):
            return True
    return False


class ThreatIntelEnricher:
    """
    Enriches security events with IP reputation data from AbuseIPDB.
    Results are cached locally to minimize API calls.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        if db_path:
            self.cache_db = str(db_path)
        else:
            self.cache_db = str(
                Path(__file__).resolve().parent.parent.parent / "siem.db"
            )
        self._ensure_cache_table()

    def _ensure_cache_table(self):
        try:
            conn = sqlite3.connect(self.cache_db)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    ip TEXT PRIMARY KEY,
                    abuse_score INTEGER DEFAULT 0,
                    country_code TEXT,
                    isp TEXT,
                    usage_type TEXT,
                    domain TEXT,
                    total_reports INTEGER DEFAULT 0,
                    last_reported TEXT,
                    is_whitelisted INTEGER DEFAULT 0,
                    categories TEXT,
                    cached_at TEXT NOT NULL,
                    raw_response TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to create threat_intel_cache table: {e}")

    def enrich(self, source: str) -> Dict[str, Any]:
        """
        Return threat intel for the given source IP/hostname.
        Returns a dict with reputation info; uses cache when fresh.
        """
        if not source or _is_private(source):
            return {"enriched": False, "reason": "private_or_internal"}

        # Extract IP from strings like "sshd: Failed from 1.2.3.4"
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", source)
        ip = ip_match.group(1) if ip_match else source.strip()

        if _is_private(ip):
            return {"enriched": False, "reason": "private_ip", "ip": ip}

        # Check cache
        cached = self._get_cached(ip)
        if cached:
            cached["enriched"] = True
            cached["from_cache"] = True
            return cached

        # Live lookup
        if not self.api_key:
            return {
                "enriched": False,
                "reason": "no_api_key",
                "ip": ip,
                "note": "Set ABUSEIPDB_API_KEY in server/.env for IP reputation checks",
            }

        return self._live_lookup(ip)

    def _get_cached(self, ip: str) -> Optional[Dict]:
        try:
            conn = sqlite3.connect(self.cache_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM threat_intel_cache WHERE ip = ?", (ip,)
            )
            row = cur.fetchone()
            conn.close()

            if not row:
                return None

            # Check freshness
            cached_at = datetime.fromisoformat(row["cached_at"])
            if datetime.utcnow() - cached_at > timedelta(hours=CACHE_TTL_HOURS):
                return None  # Expired

            data = dict(row)
            if data.get("categories"):
                try:
                    data["categories"] = json.loads(data["categories"])
                except Exception:
                    pass
            return data
        except Exception as e:
            logger.debug(f"Cache lookup failed for {ip}: {e}")
            return None

    def _live_lookup(self, ip: str) -> Dict[str, Any]:
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": self.api_key,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": "",
                },
                timeout=5,
            )

            if resp.status_code == 429:
                logger.warning("AbuseIPDB rate limit reached")
                return {"enriched": False, "reason": "rate_limited", "ip": ip}

            if resp.status_code != 200:
                return {
                    "enriched": False,
                    "reason": f"api_error_{resp.status_code}",
                    "ip": ip,
                }

            d = resp.json().get("data", {})
            result = {
                "ip": ip,
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "country_code": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "usage_type": d.get("usageType", ""),
                "domain": d.get("domain", ""),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt", ""),
                "is_whitelisted": 1 if d.get("isWhitelisted") else 0,
                "categories": d.get("reports", []),
                "enriched": True,
                "from_cache": False,
            }

            self._save_cache(ip, result, resp.text)
            return result

        except Exception as e:
            logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
            return {"enriched": False, "reason": str(e), "ip": ip}

    def _save_cache(self, ip: str, data: Dict, raw: str):
        try:
            conn = sqlite3.connect(self.cache_db)
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_intel_cache
                (ip, abuse_score, country_code, isp, usage_type, domain,
                 total_reports, last_reported, is_whitelisted, categories,
                 cached_at, raw_response)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ip,
                    data.get("abuse_score", 0),
                    data.get("country_code", ""),
                    data.get("isp", ""),
                    data.get("usage_type", ""),
                    data.get("domain", ""),
                    data.get("total_reports", 0),
                    data.get("last_reported", ""),
                    data.get("is_whitelisted", 0),
                    json.dumps(data.get("categories", [])),
                    datetime.utcnow().isoformat(),
                    raw,
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to cache threat intel for {ip}: {e}")

    def get_threat_level(self, abuse_score: int) -> str:
        if abuse_score >= 75:
            return "CRITICAL"
        elif abuse_score >= 50:
            return "HIGH"
        elif abuse_score >= 25:
            return "MEDIUM"
        elif abuse_score > 0:
            return "LOW"
        return "CLEAN"
