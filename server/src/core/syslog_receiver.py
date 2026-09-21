"""
Syslog / CEF Receiver — UDP + TCP listener on port 514 (configurable).

Supports:
  • RFC-3164  (BSD syslog)
  • RFC-5424  (IETF syslog with structured data)
  • ArcSight CEF  (Common Event Format)

Parsed messages are fed directly into LogProcessor for full pipeline treatment.
Config (server/.env):
  SYSLOG_HOST=0.0.0.0
  SYSLOG_PORT=514
  SYSLOG_ENABLED=true
"""
import asyncio
import logging
import os
import re
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# ── Severity mapping (syslog priority → SIEM level) ──────────────────────────
_PRI_TO_SEV = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL",  # emerg, alert, crit
    3: "HIGH",                                       # err
    4: "MEDIUM",                                     # warning
    5: "MEDIUM", 6: "LOW",                           # notice, info
    7: "INFO",                                       # debug
}

# ── RFC-3164 pattern ──────────────────────────────────────────────────────────
_RFC3164 = re.compile(
    r"^<(\d+)>"                                       # priority
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\S+)\s+"  # timestamp
    r"(?P<host>\S+)\s+"                               # hostname
    r"(?P<tag>[^:\[]+)(?:\[\d+\])?:\s*"               # tag/process
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# ── RFC-5424 pattern ──────────────────────────────────────────────────────────
_RFC5424 = re.compile(
    r"^<(\d+)>1\s+"                                   # priority + version
    r"(?P<ts>\S+)\s+"                                 # timestamp
    r"(?P<host>\S+)\s+"                               # hostname
    r"(?P<app>\S+)\s+"                                # app-name
    r"(?P<pid>\S+)\s+"                                # procid
    r"(?P<msgid>\S+)\s+"                              # msgid
    r"(?P<sd>\S+|-)\s*"                               # structured-data
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# ── CEF pattern ───────────────────────────────────────────────────────────────
_CEF = re.compile(
    r"CEF:(?P<ver>\d+)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<prodver>[^|]*)\|"
    r"(?P<sig>[^|]*)\|"
    r"(?P<name>[^|]*)\|"
    r"(?P<sev>[^|]*)\|"
    r"(?P<ext>.*)",
    re.DOTALL,
)


def _parse_priority(pri_str: str):
    pri = int(pri_str)
    facility = pri >> 3
    severity = pri & 0x07
    return facility, severity


def parse_syslog(raw: str, source_ip: str = "unknown") -> Dict[str, Any]:
    """
    Parse a raw syslog/CEF line and return a normalised log dict
    compatible with LogProcessor.process_log().
    """
    raw = raw.strip()

    # -- CEF ------------------------------------------------------------------
    cef_m = _CEF.search(raw)
    if cef_m:
        cef_sev = cef_m.group("sev").strip()
        try:
            level = int(cef_sev)
            # CEF severity: 0-3 low, 4-6 medium, 7-8 high, 9-10 critical
            sev = ("LOW" if level <= 3 else "MEDIUM" if level <= 6
                   else "HIGH" if level <= 8 else "CRITICAL")
        except ValueError:
            sev = "MEDIUM"
        return {
            "timestamp": datetime.now().isoformat(),
            "source": source_ip,
            "source_ip": source_ip,
            "event_type": "cef",
            "message": f"{cef_m.group('name')} ({cef_m.group('sig')})",
            "severity": sev,
            "details": {
                "vendor": cef_m.group("vendor"),
                "product": cef_m.group("product"),
                "signature": cef_m.group("sig"),
                "extensions": cef_m.group("ext"),
                "raw": raw[:500],
            },
        }

    # -- RFC-5424 -------------------------------------------------------------
    m5 = _RFC5424.match(raw)
    if m5:
        _, sev_idx = _parse_priority(raw[1: raw.index(">")])
        return {
            "timestamp": m5.group("ts"),
            "source": m5.group("host"),
            "source_ip": source_ip,
            "event_type": "syslog",
            "message": m5.group("msg")[:1000],
            "severity": _PRI_TO_SEV.get(sev_idx, "LOW"),
            "details": {
                "app": m5.group("app"),
                "structured_data": m5.group("sd"),
                "raw": raw[:500],
            },
        }

    # -- RFC-3164 -------------------------------------------------------------
    m3 = _RFC3164.match(raw)
    if m3:
        pri_raw = raw[1: raw.index(">")]
        _, sev_idx = _parse_priority(pri_raw)
        ts = (f"{datetime.now().year} {m3.group('month')} {m3.group('day')} "
              f"{m3.group('time')}")
        try:
            ts = datetime.strptime(ts, "%Y %b %d %H:%M:%S").isoformat()
        except Exception:
            ts = datetime.now().isoformat()
        return {
            "timestamp": ts,
            "source": m3.group("host"),
            "source_ip": source_ip,
            "event_type": "syslog",
            "message": m3.group("msg")[:1000],
            "severity": _PRI_TO_SEV.get(sev_idx, "LOW"),
            "details": {
                "tag": m3.group("tag"),
                "raw": raw[:500],
            },
        }

    # -- Fallback: unstructured -----------------------------------------------
    return {
        "timestamp": datetime.now().isoformat(),
        "source": source_ip,
        "source_ip": source_ip,
        "event_type": "syslog",
        "message": raw[:1000],
        "severity": "LOW",
        "details": {"raw": raw[:500]},
    }


# ── asyncio protocol classes ──────────────────────────────────────────────────

class _UDPSyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self, processor):
        self.processor = processor

    def datagram_received(self, data: bytes, addr):
        raw = data.decode("utf-8", errors="replace")
        source_ip = addr[0]
        log = parse_syslog(raw, source_ip)
        asyncio.ensure_future(self.processor.process_log(log))

    def error_received(self, exc):
        logger.warning(f"Syslog UDP error: {exc}")


class _TCPSyslogProtocol(asyncio.Protocol):
    def __init__(self, processor):
        self.processor = processor
        self._buf = ""
        self._peer = "unknown"

    def connection_made(self, transport):
        peer = transport.get_extra_info("peername")
        self._peer = peer[0] if peer else "unknown"

    def data_received(self, data: bytes):
        self._buf += data.decode("utf-8", errors="replace")
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                log = parse_syslog(line, self._peer)
                asyncio.ensure_future(self.processor.process_log(log))

    def connection_lost(self, exc):
        pass


# ── Public entry point ────────────────────────────────────────────────────────

async def start_syslog_receiver(processor) -> None:
    """
    Start UDP + TCP syslog listeners.
    Call this from the FastAPI startup event.
    """
    if os.getenv("SYSLOG_ENABLED", "true").lower() not in ("true", "1", "yes"):
        logger.info("Syslog receiver disabled (SYSLOG_ENABLED != true)")
        return

    host = os.getenv("SYSLOG_HOST", "0.0.0.0")
    port = int(os.getenv("SYSLOG_PORT", "5140"))  # 5140 avoids needing root

    loop = asyncio.get_event_loop()

    try:
        # UDP
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPSyslogProtocol(processor),
            local_addr=(host, port),
        )
        logger.info(f"Syslog UDP listener on {host}:{port}")
    except Exception as e:
        logger.error(f"Failed to start syslog UDP listener: {e}")
        udp_transport = None

    try:
        # TCP
        tcp_server = await loop.create_server(
            lambda: _TCPSyslogProtocol(processor),
            host=host,
            port=port,
        )
        logger.info(f"Syslog TCP listener on {host}:{port}")
    except Exception as e:
        logger.error(f"Failed to start syslog TCP listener: {e}")
        tcp_server = None

    if udp_transport or tcp_server:
        logger.info(
            f"Syslog receiver ready — send logs to {host}:{port} "
            "(UDP or TCP, RFC-3164/5424/CEF)"
        )
