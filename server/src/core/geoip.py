"""
GeoIP Enricher — uses ip-api.com (free, no API key, 45 req/min).
Results are cached in SQLite for 24 hours.
"""
import sqlite3
import logging
import ipaddress
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
]
CACHE_TTL_HOURS = 24


def _is_routable(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETS) and not addr.is_loopback
    except ValueError:
        return False


class GeoIPEnricher:
    def __init__(self, db_path: Path):
        self.db_path = str(db_path)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS geoip_cache (
                    ip TEXT PRIMARY KEY,
                    country TEXT,
                    country_code TEXT,
                    region TEXT,
                    city TEXT,
                    lat REAL,
                    lon REAL,
                    isp TEXT,
                    org TEXT,
                    cached_at TEXT NOT NULL
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def lookup(self, ip: str) -> Optional[Dict]:
        """Return GeoIP dict for a public IP, or None for private/invalid."""
        if not ip or not _is_routable(ip):
            return None

        # Check cache first
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM geoip_cache WHERE ip=?", (ip,))
            row = cursor.fetchone()
            if row:
                cached = dict(row)
                age = datetime.now() - datetime.fromisoformat(cached["cached_at"])
                if age < timedelta(hours=CACHE_TTL_HOURS):
                    return cached
        finally:
            conn.close()

        # Live lookup via ip-api.com
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org"},
                timeout=5,
            )
            data = resp.json()
            if data.get("status") != "success":
                return None

            result = {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "cached_at": datetime.now().isoformat(),
            }

            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO geoip_cache
                    (ip, country, country_code, region, city, lat, lon, isp, org, cached_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip, result["country"], result["country_code"], result["region"],
                    result["city"], result["lat"], result["lon"],
                    result["isp"], result["org"], result["cached_at"],
                ))
                conn.commit()
            finally:
                conn.close()

            return result
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            return None

    def bulk_lookup(self, ips):
        """Lookup a list of IPs, return list of non-None results."""
        results = []
        seen = set()
        for ip in ips:
            if ip and ip not in seen:
                seen.add(ip)
                geo = self.lookup(ip)
                if geo:
                    results.append(geo)
        return results

    def get_all_cached(self):
        """Return all cached GeoIP entries (for map rendering)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT * FROM geoip_cache")
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()
