"""
Scheduled PDF Report Generator.
Runs as a background asyncio task. Generates a PDF summary and emails it
on the configured schedule.

Config (server/.env):
  REPORT_SCHEDULE=daily|weekly   (default: daily)
  REPORT_TIME=08:00              (HH:MM in 24h format, default 08:00)
  REPORT_DAY=Monday              (for weekly schedule, default Monday)
  ALERT_EMAIL_TO                 (recipient, reuses existing SMTP config)
"""
import asyncio
import json
import logging
import os
import smtplib
import sqlite3
from datetime import datetime, timedelta
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


class ReportScheduler:
    STATE_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "report_state.json"

    def __init__(self, db):
        self.db = db
        self.schedule = os.getenv("REPORT_SCHEDULE", "daily").lower()
        self.report_time = os.getenv("REPORT_TIME", "08:00")
        self.report_day = os.getenv("REPORT_DAY", "Monday")
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_from = os.getenv("SMTP_FROM", self.smtp_user)
        self.email_to = os.getenv("ALERT_EMAIL_TO", "")
        self.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)

    # ── Scheduling ─────────────────────────────────────────────────────────

    def _load_state(self):
        try:
            if self.STATE_FILE.exists():
                return json.loads(self.STATE_FILE.read_text())
        except Exception:
            pass
        return {}

    def _save_state(self, state):
        try:
            self.STATE_FILE.write_text(json.dumps(state))
        except Exception:
            pass

    def _should_send(self, now: datetime) -> bool:
        h, m = map(int, self.report_time.split(":"))
        if now.hour < h or (now.hour == h and now.minute < m):
            return False  # too early today

        if self.schedule == "weekly":
            target_day = _DAYS.index(self.report_day) if self.report_day in _DAYS else 0
            if now.weekday() != target_day:
                return False

        state = self._load_state()
        last_str = state.get("last_sent")
        if last_str:
            last = datetime.fromisoformat(last_str)
            if self.schedule == "daily" and last.date() >= now.date():
                return False
            if self.schedule == "weekly" and (now - last).days < 6:
                return False
        return True

    async def run(self):
        """Main loop - polls every 60s."""
        while True:
            try:
                now = datetime.now()
                if self._should_send(now):
                    logger.info("Generating scheduled SIEM report...")
                    await asyncio.get_event_loop().run_in_executor(None, self._generate_and_send)
                    self._save_state({"last_sent": now.isoformat()})
            except Exception as e:
                logger.error(f"Report scheduler error: {e}")
            await asyncio.sleep(60)

    # ── PDF generation ─────────────────────────────────────────────────────

    def generate_pdf(self, period_hours: int = 24) -> Optional[bytes]:
        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("fpdf2 not installed - cannot generate report")
            return None

        now = datetime.now()
        period_label = f"Last {period_hours}h" if period_hours <= 24 else f"Last {period_hours // 24} days"

        threats = self.db.get_threats()
        correlations = self.db.get_correlations(hours=period_hours)
        agents = self.db.get_all_agents()
        executions = self.db.get_playbook_executions(limit=20)

        total = len(threats)
        critical_n = sum(1 for t in threats if t.get("severity", "").upper() == "CRITICAL")
        high_n = sum(1 for t in threats if t.get("severity", "").upper() == "HIGH")

        def agent_online(a):
            ls = a.get("last_seen")
            if not ls:
                return False
            try:
                return (now - datetime.fromisoformat(str(ls))).total_seconds() < 300
            except Exception:
                return False

        online = sum(1 for a in agents if agent_online(a))

        pdf = FPDF()
        pdf.add_page()

        # Header
        pdf.set_fill_color(30, 30, 60)
        pdf.rect(0, 0, 210, 30, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_y(8)
        pdf.cell(0, 10, "AI-IDS Security Report", align="C", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Generated: {now.strftime('%Y-%m-%d %H:%M')}   Period: {period_label}", align="C", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(8)

        # Summary metrics
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 11)
        metrics = [
            ("Total events in DB", str(total)),
            ("Critical events", str(critical_n)),
            ("High events", str(high_n)),
            (f"ATT&CK correlations ({period_label})", str(len(correlations))),
            ("Online agents", f"{online} / {len(agents)}"),
            ("Playbook executions (last 20)", str(len(executions))),
        ]
        for label, value in metrics:
            pdf.cell(95, 7, label + ":", border="B")
            pdf.cell(0, 7, value, border="B", ln=True)
        pdf.ln(5)

        # Correlations
        if correlations:
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, f"ATT&CK Correlations ({len(correlations)})", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for c in correlations[:15]:
                line = (
                    f"[{c.get('severity','?')}] {c.get('rule_name','?')} "
                    f"({c.get('mitre_id','?')}) - {c.get('source','?')} "
                    f"@ {str(c.get('fired_at',''))[:16]}"
                )
                pdf.cell(0, 5, line[:110], ln=True)
            pdf.ln(4)

        # Agent Status
        if agents:
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, "Agent Status", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for a in agents:
                status = "ONLINE" if agent_online(a) else "OFFLINE"
                ls = str(a.get("last_seen", "never"))[:16]
                pdf.cell(0, 5,
                    f"[{status}] {a.get('hostname','?')} ({a.get('platform','?')}) - last seen: {ls}",
                    ln=True)
            pdf.ln(4)

        # Playbook executions
        if executions:
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 8, "Recent Playbook Executions", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for ex in executions:
                actions = ex.get("actions") or []
                if isinstance(actions, list):
                    action_str = ", ".join(a.get("type", "?") for a in actions)
                else:
                    action_str = str(actions)
                pdf.cell(0, 5,
                    f"{str(ex.get('executed_at',''))[:16]} - {ex.get('playbook_name','?')} - {action_str}",
                    ln=True)

        return bytes(pdf.output())

    # ── Delivery ───────────────────────────────────────────────────────────

    def _generate_and_send(self):
        period_hours = 24 if self.schedule == "daily" else 168
        pdf_bytes = self.generate_pdf(period_hours=period_hours)
        if not pdf_bytes:
            return
        if self.smtp_user and self.smtp_password and self.email_to:
            self._send_email(pdf_bytes)
        else:
            logger.warning("SMTP not configured - report generated but not emailed.")
            self._save_locally(pdf_bytes)

    def _save_locally(self, pdf_bytes: bytes):
        out_dir = Path(__file__).resolve().parent.parent.parent / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = out_dir / f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        fname.write_bytes(pdf_bytes)
        logger.info(f"Report saved locally: {fname}")

    def _send_email(self, pdf_bytes: bytes):
        subject = f"AI-IDS {self.schedule.title()} Report - {datetime.now().strftime('%Y-%m-%d')}"
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = self.smtp_from
        msg["To"] = self.email_to
        msg.attach(MIMEText(
            f"Please find your {self.schedule} AI-IDS security report attached.\n\n"
            "Generated automatically by the AI-IDS platform.",
            "plain",
        ))
        att = MIMEBase("application", "pdf")
        att.set_payload(pdf_bytes)
        encoders.encode_base64(att)
        att.add_header("Content-Disposition", "attachment",
                       filename=f"siem_report_{datetime.now().strftime('%Y%m%d')}.pdf")
        msg.attach(att)
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_from, self.email_to, msg.as_string())
            logger.info(f"Report emailed to {self.email_to}")
        except Exception as e:
            logger.error(f"Failed to email report: {e}")
            self._save_locally(pdf_bytes)


# ═════════════════════════════════════════════════════════════════════════════ #
#  AI Autonomous Agent Report                                                  #
#  Generates a dated PDF summary of the AI agent's analysis: threat counts by   #
#  severity, attack-type distribution, top sources, recent verdicts and the     #
#  recommended actions from each AI assessment.                                 #
# ═════════════════════════════════════════════════════════════════════════════ #

AI_AGENT_REPORT_DIR = Path(__file__).resolve().parent.parent.parent / "data"
AI_AGENT_REPORT_PATH = AI_AGENT_REPORT_DIR / "ai_agent_report_latest.pdf"


def _agent_report_data(db_path: Path) -> dict:
    """Aggregate everything the AI-agent PDF needs from the SIEM DB."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    now = datetime.utcnow()

    def parse_verdict(raw):
        try:
            return json.loads(raw) if raw else {}
        except Exception:
            return {}

    try:
        # ── 1. All logs with AI verdicts, last 24h window ──
        cur = conn.cursor()
        cur.execute("""
            SELECT id, timestamp, source, message, severity, ai_analysis
            FROM logs
            ORDER BY timestamp DESC
        """)
        rows = [dict(r) for r in cur.fetchall()]

        analysed = [r for r in rows if parse_verdict(r.get("ai_analysis"))]
        recent = [r for r in rows if not r.get("timestamp") or
                  (now - _safe_parse_ts(r.get("timestamp"))).total_seconds() < timedelta(hours=24).total_seconds()]

        def sev_key(s):
            return (s or "").upper()

        sev_counts = {}
        for r in rows:
            sev_counts[sev_key(r.get("severity", "UNKNOWN"))] = sev_counts.get(sev_key(r.get("severity", "UNKNOWN")), 0) + 1

        # ── 2. Attack-type distribution from AI verdicts ──
        attack_dist = {}
        for r in analysed:
            v = parse_verdict(r.get("ai_analysis"))
            atk = (v.get("attack_type") or "unknown").replace("_", " ").title()
            attack_dist[atk] = attack_dist.get(atk, 0) + 1

        # ── 3. Top sources ──
        source_counts = {}
        for r in rows:
            src = r.get("source") or "unknown"
            source_counts[src] = source_counts.get(src, 0) + 1
        top_sources = sorted(source_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]

        # ── 4. Auto-blocked IPs (from ai_autonomous_agent events) ──
        cur.execute(
            "SELECT details FROM logs WHERE source='ai_autonomous_agent' AND message LIKE '%block%' ORDER BY timestamp DESC LIMIT 20"
        )
        blocked = []
        for r in cur.fetchall():
            try:
                blocked.append((r["details"] or {}).get("blocked_ip", "?"))
            except Exception:
                pass

        # ── 5. Persisted agent stats ──
        stats = {}
        try:
            cur.execute(
                "SELECT s_key, s_value FROM ai_agent_stats ORDER BY s_key"
            )
            stats = {r["s_key"]: r["s_value"] for r in cur.fetchall()}
        except Exception:
            pass

        # ── 6. Recent correlations (source of MITRE context) ──
        cur.execute("""
            SELECT rule_name, mitre_id, severity, source, fired_at
            FROM correlations
            WHERE fired_at >= datetime('now', '-24 hours')
            ORDER BY fired_at DESC LIMIT 15
        """)
        correlations = [dict(r) for r in cur.fetchall()]

    finally:
        conn.close()

    return {
        "generated_at": now,
        "total_logs": len(rows),
        "analysed": len(analysed),
        "recent_24h": len(recent),
        "sev_counts": sev_counts,
        "attack_dist": attack_dist,
        "top_sources": top_sources,
        "blocked_ips": blocked,
        "stats": stats,
        "verdicts": analysed[:15],
        "correlations": correlations,
    }


def _safe_parse_ts(ts) -> datetime:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return datetime.utcnow()


def generate_ai_agent_report(db_path: Path) -> Optional[bytes]:
    """Build the AI-agent analysis summary PDF. Returns PDF bytes (or None)."""
    try:
        from fpdf import FPDF
    except ImportError:
        logger.error("fpdf2 not installed - cannot generate AI agent report")
        return None

    try:
        return _build_agent_pdf(db_path, FPDF)
    except Exception as e:
        logger.warning("AI agent PDF generation failed (non-critical): %s", e)
        return None


def _build_agent_pdf(db_path: Path, FPDF) -> Optional[bytes]:
    """Inner builder - separated so the outer function can catch all errors."""

    data = _agent_report_data(db_path)
    now = data["generated_at"]

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Header banner ──
    pdf.set_fill_color(13, 21, 38)
    pdf.rect(0, 0, 210, 34, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_y(7)
    pdf.cell(0, 9, "AI-IDS Autonomous Agent Report", align="C", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, f"AI security analysis summary  |  {now.strftime('%Y-%m-%d %H:%M')} UTC", align="C", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    stats = data["stats"]

    # ── Executive metrics ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Executive Summary", ln=True)
    pdf.set_font("Helvetica", "", 10)
    metrics = [
        ("Total events in database", str(data["total_logs"])),
        ("AI-analysed events", str(data["analysed"])),
        ("Events (last 24h)", str(data["recent_24h"])),
        ("Attack types identified", str(len(data["attack_dist"]))),
        ("IPs auto-blocked", str(len(data["blocked_ips"]))),
        ("Agent cycles run", str(stats.get("cycles", "-"))),
        ("Threats confirmed by AI", str(stats.get("threats_found", "-"))),
        ("AI alerts sent", str(stats.get("alerts_sent", "-"))),
    ]
    for label, value in metrics:
        pdf.cell(95, 6, label + ":", border="B")
        pdf.cell(0, 6, value, border="B", ln=True)
    pdf.ln(5)

    # ── Severity breakdown ──
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, "Threat Count by Severity", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = data["sev_counts"].get(sev, 0)
        pdf.cell(95, 6, sev.title() + ":", border="B")
        pdf.cell(0, 6, str(count), border="B", ln=True)
    pdf.ln(5)

    # ── Attack-type distribution ──
    if data["attack_dist"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "AI-Attributed Attack Distribution", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for atk, count in sorted(data["attack_dist"].items(), key=lambda kv: kv[1], reverse=True)[:12]:
            pdf.cell(0, 5, f"- {atk} ({count})", ln=True)
        pdf.ln(4)

    # ── Top sources ──
    if data["top_sources"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Top Event Sources", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for src, count in data["top_sources"]:
            pdf.cell(0, 5, f"- {src} - {count} events", ln=True)
        pdf.ln(4)

    # ── Auto-blocked IPs ──
    if data["blocked_ips"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, f"Auto-Blocked IPs ({len(data['blocked_ips'])})", ln=True)
        pdf.set_font("Helvetica", "", 9)
        line = ", ".join(dict.fromkeys(data["blocked_ips"]))
        pdf.multi_cell(0, 5, line)
        pdf.ln(3)

    # ── Recent AI verdicts ──
    if data["verdicts"]:
        pdf.add_page()
        pdf.set_fill_color(13, 21, 38)
        pdf.rect(0, 0, 210, 22, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_y(6)
        pdf.cell(0, 8, "Recent AI Verdicts", align="C", ln=True)
        pdf.set_text_color(0, 0, 0)

        for r in data["verdicts"]:
            v = r.get("ai_analysis")
            try:
                v = json.loads(v) if isinstance(v, str) else v
            except Exception:
                v = {}
            lvl = (v.get("threat_level") or "unknown").upper()
            colour = {"CRITICAL": (239, 68, 68), "HIGH": (249, 115, 22),
                      "MEDIUM": (234, 179, 8), "LOW": (34, 197, 94)}.get(lvl or "", (100, 116, 139))

            try:
                pdf.set_fill_color(*colour)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, f"[{lvl}] {v.get('attack_type','threat')} - conf {float(v.get('confidence',0)):.0%}", fill=True, ln=True)
            except Exception:
                pdf.ln(8)
                pdf.set_fill_color(*colour)
                pdf.set_text_color(255, 255, 255)
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, f"[{lvl}] {v.get('attack_type','threat')} - conf {float(v.get('confidence',0)):.0%}", fill=True, ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Helvetica", "", 8)
            pdf.multi_cell(0, 4, f"{r.get('message','')[:160]}")
            src = f"{r.get('source','?')} @ {str(r.get('timestamp',''))[:16]}"
            pdf.set_font("Helvetica", "I", 8)
            pdf.cell(0, 4, src, ln=True)
            if v.get("summary"):
                pdf.set_font("Helvetica", "", 8)
                pdf.multi_cell(0, 4, f"AI: {v.get('summary','')[:220]}")
            actions = v.get("immediate_actions") or []
            if actions:
                pdf.set_font("Helvetica", "", 8)
                for a in actions[:2]:
                    pdf.multi_cell(0, 4, f"   * {a}")
            pdf.ln(2)

    # ── Recent correlations ──
    if data["correlations"]:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 7, "Correlations (last 24h)", ln=True)
        pdf.set_font("Helvetica", "", 9)
        for c in data["correlations"][:12]:
            line = f"[{c.get('severity','?')}] {c.get('rule_name','?')} ({c.get('mitre_id','?')}) - {c.get('source','?')} @ {str(c.get('fired_at',''))[:16]}"
            pdf.cell(0, 5, line[:110], ln=True)
        pdf.ln(3)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(0, 5, f"Generated automatically by the AI-IDS autonomous agent - {now.strftime('%Y-%m-%d %H:%M UTC')}", ln=True)

    return bytes(pdf.output())


def save_ai_agent_report(db_path: Path) -> Optional[Path]:
    """Generate the AI-agent PDF and persist it to data/. Returns the path (or None)."""
    pdf_bytes = generate_ai_agent_report(db_path)
    if not pdf_bytes:
        return None
    AI_AGENT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
    dated = AI_AGENT_REPORT_DIR / f"ai_agent_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    dated.write_bytes(pdf_bytes)
    AI_AGENT_REPORT_PATH.write_bytes(pdf_bytes)
    logger.info(f"AI agent report saved: {dated}")
    return dated
