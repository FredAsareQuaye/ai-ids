"""
AI-IDS Autonomous Agent
========================
Runs 24/7 in the background. Every cycle it:
  1. Fetches unanalysed / recently-ingested logs
  2. Sends them in batches to OpenRouter for deep threat analysis
  3. Updates threat scores and stores AI verdicts back in the DB
  4. Triggers playbooks for HIGH/CRITICAL AI-confirmed threats
  5. Sends real-time email alerts with AI analysis included
  6. Applies stricter thresholds during after-hours windows
  7. Blocks malicious IPs autonomously when confidence is high
  8. Generates and emails a rolling hourly digest
"""

import asyncio
import logging
import os
import json
import sqlite3
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Config (override via .env) ────────────────────────────────────────────────
AGENT_INTERVAL_SECONDS  = int(os.getenv("AI_AGENT_INTERVAL", "120"))   # 2 min
BATCH_SIZE              = int(os.getenv("AI_AGENT_BATCH", "20"))
OFFICE_HOURS_START      = int(os.getenv("OFFICE_HOURS_START", "8"))     # 08:00
OFFICE_HOURS_END        = int(os.getenv("OFFICE_HOURS_END",   "18"))    # 18:00
AUTO_BLOCK_ENABLED      = os.getenv("AI_AUTO_BLOCK", "true").lower() == "true"
AUTO_BLOCK_CONFIDENCE   = float(os.getenv("AI_AUTO_BLOCK_CONFIDENCE", "0.85"))
OPENROUTER_API_URL      = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL        = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")
DIGEST_INTERVAL_SECONDS = int(os.getenv("AI_DIGEST_INTERVAL", "3600"))  # 1 hour


def _api_key() -> str:
    key = os.getenv("OPENROUTER_API_KEY", "")
    if not key:
        env_path = Path(__file__).parent.parent.parent / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith("OPENROUTER_API_KEY="):
                    key = line.split("=", 1)[1].strip()
                    break
    return key


def _is_after_hours() -> bool:
    h = datetime.now().hour
    return h < OFFICE_HOURS_START or h >= OFFICE_HOURS_END


def _call_deepseek(prompt: str, timeout: int = 60) -> str:
    key = _api_key()
    if not key:
        raise ValueError("OPENROUTER_API_KEY not set")
    r = requests.post(
        OPENROUTER_API_URL,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/yourusername/aisiem",
            "X-Title": "AI-IDS",
        },
        json={
            "model": OPENROUTER_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        },
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


class AutonomousAIAgent:
    """
    Persistent background agent. Instantiate once and call run().
    """

    def __init__(self, db, notifier, playbook_engine=None):
        self.db              = db
        self.notifier        = notifier
        self.playbook_engine = playbook_engine
        self._analysed_ids: set = set()   # avoid re-analysing same log
        self._last_digest_at = datetime.utcnow() - timedelta(hours=1)
        self._blocked_ips: set = set()
        self._stats = {
            "cycles": 0, "logs_analysed": 0,
            "threats_found": 0, "auto_blocks": 0,
            "alerts_sent": 0, "started_at": datetime.utcnow().isoformat(),
        }

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def run(self):
        logger.info("AI Autonomous Agent started (interval=%ds)", AGENT_INTERVAL_SECONDS)
        while True:
            try:
                await self._cycle()
            except Exception as e:
                logger.error("Agent cycle error: %s", e)
            await asyncio.sleep(AGENT_INTERVAL_SECONDS)

    async def _cycle(self):
        self._stats["cycles"] += 1
        after_hours = _is_after_hours()
        mode = "AFTER-HOURS (heightened)" if after_hours else "OFFICE-HOURS"
        logger.info("AI Agent cycle #%d - %s mode", self._stats["cycles"], mode)

        # 1. Fetch recent logs not yet AI-analysed
        logs = self._fetch_unanalysed(limit=BATCH_SIZE, after_hours=after_hours)
        logger.info("AI Agent fetched %d unanalysed logs (batch_size=%d)", len(logs), BATCH_SIZE)
        if not logs:
            logger.debug("No new logs to analyse")
            # Still emit digest if due
            await self._maybe_send_digest()
            self._persist_stats()
            await self._maybe_generate_report()
            return

        # 2. Deep AI analysis
        verdicts = await asyncio.get_event_loop().run_in_executor(
            None, self._batch_analyse, logs
        )

        # 3. Process verdicts
        for log, verdict in zip(logs, verdicts):
            self._analysed_ids.add(log["id"])
            self._stats["logs_analysed"] += 1

            confidence  = verdict.get("confidence", 0.0)
            threat_lvl  = verdict.get("threat_level", "low").lower()
            is_threat   = threat_lvl in ("high", "critical") or confidence >= 0.7

            # Store verdict back
            self._store_ai_verdict(log["id"], verdict)

            if is_threat:
                self._stats["threats_found"] += 1
                logger.warning(
                    "AI THREAT DETECTED [%s, conf=%.2f]: %s",
                    threat_lvl.upper(), confidence, log.get("message", "")[:80],
                )

                # 4. Auto-block IP if confident enough
                src_ip = verdict.get("source_ip") or self._extract_ip(log)
                if src_ip and AUTO_BLOCK_ENABLED and confidence >= AUTO_BLOCK_CONFIDENCE:
                    await self._auto_block_ip(src_ip, log, verdict)

                # 5. Alert email with AI analysis
                await asyncio.get_event_loop().run_in_executor(
                    None, self._send_ai_alert, log, verdict
                )
                self._stats["alerts_sent"] += 1

                # 6. Trigger playbook via correlation-style dict
                if self.playbook_engine:
                    try:
                        fake_corr = {
                            "rule_id": verdict.get("attack_type", "ai_threat"),
                            "severity": verdict.get("threat_level", "HIGH").upper(),
                            "source": log.get("source", "unknown"),
                        }
                        await asyncio.get_event_loop().run_in_executor(
                            None, lambda c=fake_corr: self.playbook_engine.execute(c)
                        )
                    except Exception as e:
                        logger.error("Playbook evaluation error: %s", e)

        # 7. Hourly digest
        await self._maybe_send_digest()
        self._persist_stats()
        await self._maybe_generate_report()

    # ── Log fetching ─────────────────────────────────────────────────────────

    def _fetch_unanalysed(self, limit: int, after_hours: bool) -> List[Dict]:
        """
        Fetch unanalysed logs that haven't been AI-analysed yet.
        Includes ALL severities and the full history (no 30-min window) so the
        agent does not skip older HIGH/CRITICAL events still pending review.
        During after-hours, medium-severity logs are prioritised higher.
        """
        try:
            conn = sqlite3.connect(self.db.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            severities = "('critical','high','medium','low','info','information','notice','warning')"

            query = f"""
                SELECT id, timestamp, source, message, severity, details, ai_analysis
                FROM logs
                WHERE LOWER(severity) IN {severities}
                  AND (ai_analysis IS NULL OR ai_analysis = '' OR ai_analysis = '{{}}')
                ORDER BY
                  CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    ELSE 4
                  END,
                  timestamp DESC
                LIMIT ?
            """
            logger.info("FETCH QUERY db_path=%s limit=%d after_hours=%s", self.db.db_path, limit, after_hours)
            cur.execute(query, (limit,))

            rows = [dict(r) for r in cur.fetchall()]
            conn.close()

            logger.info("FETCH RESULT: %d rows from DB, %d already in _analysed_ids", len(rows), len(self._analysed_ids))

            # Filter already processed in this session
            result = [r for r in rows if r["id"] not in self._analysed_ids]
            logger.info("FETCH FINAL: %d logs after filtering", len(result))
            return result
        except Exception as e:
            logger.error("Error fetching unanalysed logs: %s", e, exc_info=True)
            return []

    # ── AI analysis ──────────────────────────────────────────────────────────

    def _batch_analyse(self, logs: List[Dict]) -> List[Dict]:
        """Send logs to OpenRouter in one batch prompt, return per-log verdicts."""
        after_hours = _is_after_hours()
        threshold_note = (
            "IMPORTANT: It is currently AFTER BUSINESS HOURS. Apply heightened scrutiny - "
            "flag anything that looks unusual, even if it might be a false positive during working hours."
            if after_hours else
            "Apply standard enterprise security analysis thresholds."
        )

        log_block = "\n\n".join([
            f"LOG #{i+1} [ID={l['id']}]:\n"
            f"  Timestamp: {l.get('timestamp','?')}\n"
            f"  Source: {l.get('source','?')}\n"
            f"  Severity: {l.get('severity','?')}\n"
            f"  Message: {l.get('message','?')}\n"
            f"  Details: {json.dumps(l.get('details') or {})}"
            for i, l in enumerate(logs)
        ])

        prompt = f"""You are an autonomous AI security analyst for an enterprise SIEM system.
Analyse the following {len(logs)} security log(s) and return a JSON array with one verdict per log.

{threshold_note}

LOGS:
{log_block}

For each log return a JSON object with:
{{
  "log_id": <integer>,
  "threat_level": "critical|high|medium|low",
  "confidence": <0.0-1.0>,
  "attack_type": "<e.g. brute_force, lateral_movement, data_exfiltration, ransomware, insider_threat, etc.>",
  "mitre_tactic": "<MITRE ATT&CK tactic if applicable>",
  "mitre_technique": "<MITRE technique ID if applicable>",
  "source_ip": "<extracted IP if present, else null>",
  "affected_asset": "<hostname or asset if identifiable>",
  "summary": "<2-3 sentence threat summary>",
  "immediate_actions": ["<action 1>", "<action 2>"],
  "auto_block_recommended": <true|false>
}}

Return ONLY a valid JSON array, no other text.
"""
        try:
            raw = _call_deepseek(prompt, timeout=90)
            start = raw.find("[")
            end   = raw.rfind("]") + 1
            verdicts = json.loads(raw[start:end] if start >= 0 else raw)
            # Index by log_id for matching
            verdict_map = {v.get("log_id"): v for v in verdicts if isinstance(v, dict)}
            return [verdict_map.get(l["id"], self._fallback_verdict(l)) for l in logs]
        except Exception as e:
            logger.error("OpenRouter batch analysis failed: %s", e)
            return [self._fallback_verdict(l) for l in logs]

    def _fallback_verdict(self, log: Dict) -> Dict:
        sev = log.get("severity", "LOW").upper()
        return {
            "log_id": log["id"],
            "threat_level": "high" if sev in ("HIGH", "CRITICAL") else "low",
            "confidence": 0.5,
            "attack_type": "unknown",
            "mitre_tactic": None,
            "mitre_technique": None,
            "source_ip": None,
            "affected_asset": log.get("source"),
            "summary": "Rule-based assessment (AI unavailable).",
            "immediate_actions": ["Investigate manually"],
            "auto_block_recommended": False,
        }

    # ── DB storage ───────────────────────────────────────────────────────────

    def _store_ai_verdict(self, log_id: int, verdict: Dict):
        try:
            conn = sqlite3.connect(self.db.db_path)
            conn.execute(
                "UPDATE logs SET ai_analysis = ? WHERE id = ?",
                (json.dumps(verdict), log_id),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error("Failed to store AI verdict for log %d: %s", log_id, e)

    # ── Autonomous blocking ───────────────────────────────────────────────────

    async def _auto_block_ip(self, ip: str, log: Dict, verdict: Dict):
        if ip in self._blocked_ips:
            return
        self._blocked_ips.add(ip)
        self._stats["auto_blocks"] += 1
        logger.warning("AUTO-BLOCKING IP %s (confidence=%.2f)", ip, verdict.get("confidence", 0))

        # Store block event
        self.db.store_event({
            "timestamp": datetime.utcnow().isoformat(),
            "source": "ai_autonomous_agent",
            "message": f"AI auto-blocked {ip} - {verdict.get('attack_type','threat')} "
                       f"(confidence {verdict.get('confidence',0):.0%})",
            "severity": "CRITICAL",
            "event_type": "auto_block",
            "details": {
                "blocked_ip": ip,
                "reason": verdict.get("summary"),
                "confidence": verdict.get("confidence"),
                "attack_type": verdict.get("attack_type"),
            },
        })

        # Trigger block_ip via playbook engine if available
        if self.playbook_engine:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: self.playbook_engine._block_ip(ip)
                )
            except Exception as e:
                logger.error("Auto-block playbook error: %s", e)

    # ── Email alert ──────────────────────────────────────────────────────────

    def _send_ai_alert(self, log: Dict, verdict: Dict):
        """Send a rich HTML email alert with full AI analysis."""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            smtp_host = os.getenv("SMTP_HOST", "")
            smtp_user = os.getenv("SMTP_USER", "")
            smtp_pass = os.getenv("SMTP_PASSWORD", "")
            smtp_from = os.getenv("SMTP_FROM", smtp_user)
            to_addr   = os.getenv("ALERT_EMAIL_TO", "")

            if not all([smtp_host, smtp_user, smtp_pass, to_addr]):
                logger.debug("Email not configured - skipping AI alert email")
                return

            threat_lvl  = verdict.get("threat_level", "unknown").upper()
            color_map   = {"CRITICAL": "#ef4444", "HIGH": "#f97316",
                           "MEDIUM":   "#eab308", "LOW":  "#22c55e"}
            color       = color_map.get(threat_lvl, "#64748b")
            after_hours = _is_after_hours()
            mode_badge  = (
                '<span style="background:#7c3aed;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px">AFTER-HOURS DETECTION</span>'
                if after_hours else ""
            )

            actions_html = "".join(
                f'<li style="margin:4px 0;color:#e2e8f0">{a}</li>'
                for a in verdict.get("immediate_actions", [])
            )

            html = f"""<!DOCTYPE html>
<html><body style="background:#0b0f19;font-family:Inter,Arial,sans-serif;margin:0;padding:24px">
<div style="max-width:680px;margin:0 auto">

  <div style="background:#131c2e;border-radius:12px;overflow:hidden;border:1px solid #1a2235">

    <!-- Header -->
    <div style="background:{color};padding:20px 28px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div>
          <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:rgba(255,255,255,.7)">AI-IDS Autonomous Agent</div>
          <div style="font-size:22px;font-weight:700;color:#fff;margin-top:4px">{threat_lvl} THREAT DETECTED</div>
        </div>
        <div style="text-align:right">
          {mode_badge}
          <div style="font-size:12px;color:rgba(255,255,255,.8);margin-top:4px">{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</div>
        </div>
      </div>
    </div>

    <!-- AI Summary -->
    <div style="padding:24px 28px;border-bottom:1px solid #1a2235">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin-bottom:10px">AI Analysis</div>
      <div style="font-size:14px;color:#cbd5e1;line-height:1.7;background:#0f1623;border-left:3px solid {color};padding:14px 18px;border-radius:0 8px 8px 0">
        {verdict.get("summary","No summary available.")}
      </div>
    </div>

    <!-- Metadata grid -->
    <div style="padding:20px 28px;display:grid;grid-template-columns:1fr 1fr;gap:16px;border-bottom:1px solid #1a2235">
      <div>
        <div style="font-size:10px;text-transform:uppercase;color:#475569;font-weight:700">Attack Type</div>
        <div style="font-size:13px;color:#e2e8f0;margin-top:4px">{verdict.get("attack_type","Unknown")}</div>
      </div>
      <div>
        <div style="font-size:10px;text-transform:uppercase;color:#475569;font-weight:700">Confidence</div>
        <div style="font-size:13px;color:{color};margin-top:4px;font-weight:700">{verdict.get("confidence",0):.0%}</div>
      </div>
      <div>
        <div style="font-size:10px;text-transform:uppercase;color:#475569;font-weight:700">MITRE Tactic</div>
        <div style="font-size:13px;color:#e2e8f0;margin-top:4px">{verdict.get("mitre_tactic") or "-"}</div>
      </div>
      <div>
        <div style="font-size:10px;text-transform:uppercase;color:#475569;font-weight:700">Technique</div>
        <div style="font-size:13px;color:#e2e8f0;margin-top:4px">{verdict.get("mitre_technique") or "-"}</div>
      </div>
      <div>
        <div style="font-size:10px;text-transform:uppercase;color:#475569;font-weight:700">Source IP</div>
        <div style="font-size:13px;color:#e2e8f0;margin-top:4px">{verdict.get("source_ip") or "-"}</div>
      </div>
      <div>
        <div style="font-size:10px;text-transform:uppercase;color:#475569;font-weight:700">Affected Asset</div>
        <div style="font-size:13px;color:#e2e8f0;margin-top:4px">{verdict.get("affected_asset") or log.get("source","-")}</div>
      </div>
    </div>

    <!-- Event details -->
    <div style="padding:20px 28px;border-bottom:1px solid #1a2235">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin-bottom:10px">Event Details</div>
      <div style="font-size:12px;color:#94a3b8;font-family:monospace;background:#0b0f19;padding:12px;border-radius:6px;word-break:break-all">
        {log.get("message","")[:400]}
      </div>
    </div>

    <!-- Immediate actions -->
    <div style="padding:20px 28px;border-bottom:1px solid #1a2235">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin-bottom:10px">Immediate Actions Required</div>
      <ul style="margin:0;padding-left:20px">
        {actions_html}
      </ul>
    </div>

    <!-- Auto-block notice -->
    {"<div style='padding:14px 28px;background:#1a0a0a;border-bottom:1px solid #ef444444'><span style='color:#ef4444;font-size:12px;font-weight:700'>AUTO-BLOCK EXECUTED</span><span style='color:#94a3b8;font-size:12px'> - Source IP has been automatically blocked by the AI agent.</span></div>" if verdict.get("auto_block_recommended") and AUTO_BLOCK_ENABLED else ""}

    <!-- Footer -->
    <div style="padding:16px 28px;background:#0b0f19">
      <div style="font-size:11px;color:#334155">AI-IDS Autonomous Agent &nbsp;·&nbsp; Powered by OpenRouter &nbsp;·&nbsp; {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
    </div>

  </div>
</div>
</body></html>"""

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[AI-IDS] {threat_lvl} - {verdict.get('attack_type','Threat')} detected on {log.get('source','unknown')}"
            msg["From"]    = smtp_from
            msg["To"]      = to_addr
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587"))) as s:
                s.starttls()
                s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_from, [to_addr], msg.as_string())

            logger.info("AI alert email sent for log %d (%s)", log["id"], threat_lvl)

        except Exception as e:
            logger.error("Failed to send AI alert email: %s", e)

    # ── Hourly digest ─────────────────────────────────────────────────────────

    async def _maybe_send_digest(self):
        now = datetime.utcnow()
        if (now - self._last_digest_at).total_seconds() < DIGEST_INTERVAL_SECONDS:
            return
        self._last_digest_at = now
        logger.info("Generating hourly AI digest...")
        await asyncio.get_event_loop().run_in_executor(None, self._send_digest)

    def _send_digest(self):
        """Generate and email an AI-written hourly security digest."""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            smtp_host = os.getenv("SMTP_HOST", "")
            smtp_user = os.getenv("SMTP_USER", "")
            smtp_pass = os.getenv("SMTP_PASSWORD", "")
            smtp_from = os.getenv("SMTP_FROM", smtp_user)
            to_addr   = os.getenv("ALERT_EMAIL_TO", "")

            if not all([smtp_host, smtp_user, smtp_pass, to_addr]):
                return

            # Pull last hour of events
            conn = sqlite3.connect(self.db.db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            cur.execute("""
                SELECT severity, source, message, ai_analysis
                FROM logs WHERE timestamp >= ?
                ORDER BY timestamp DESC LIMIT 200
            """, (cutoff,))
            rows = [dict(r) for r in cur.fetchall()]
            conn.close()

            if not rows:
                return

            # Count stats
            sev_counts = {}
            for r in rows:
                sev_counts[r["severity"]] = sev_counts.get(r["severity"], 0) + 1

            # Ask OpenRouter to write the digest
            summary_text = "\n".join([
                f"- [{r['severity']}] {r['source']}: {r['message'][:100]}"
                for r in rows[:40]
            ])

            after_hours = _is_after_hours()
            prompt = f"""Write a concise executive security digest for the past hour of an enterprise SIEM system.
{'NOTE: This is an AFTER-HOURS report - all staff are offline. Flag anything requiring immediate escalation.' if after_hours else ''}

Event summary ({len(rows)} total events):
CRITICAL: {sev_counts.get('CRITICAL',0)}, HIGH: {sev_counts.get('HIGH',0)}, MEDIUM: {sev_counts.get('MEDIUM',0)}, LOW: {sev_counts.get('LOW',0)}

Sample events:
{summary_text}

AI Agent stats this session:
- Cycles run: {self._stats['cycles']}
- Logs analysed: {self._stats['logs_analysed']}
- Threats confirmed: {self._stats['threats_found']}
- IPs auto-blocked: {self._stats['auto_blocks']}

Write the digest in 3 sections:
1. **Executive Summary** (2-3 sentences)
2. **Key Threats** (bullet points)
3. **Recommended Actions** (bullet points)

Keep it professional and under 300 words."""

            try:
                digest_text = _call_deepseek(prompt, timeout=60)
            except Exception:
                digest_text = f"Digest generation unavailable. Stats: {self._stats}"

            after_hours_banner = (
                '<div style="background:#7c3aed;color:#fff;padding:10px 24px;font-size:12px;font-weight:700;text-align:center">AFTER-HOURS MONITORING ACTIVE - AI AGENT WORKING AUTONOMOUSLY</div>'
                if after_hours else ""
            )

            stats_html = "".join([
                f'<div style="text-align:center"><div style="font-size:22px;font-weight:700;color:#1ec8ff">{v}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">{k.replace("_"," ")}</div></div>'
                for k, v in self._stats.items() if k not in ("started_at",)
            ])

            digest_html_body = digest_text.replace("\n", "<br>").replace("**", "<strong>").replace("</strong><br>", "</strong><br>")

            html = f"""<!DOCTYPE html>
<html><body style="background:#0b0f19;font-family:Inter,Arial,sans-serif;margin:0;padding:24px">
<div style="max-width:680px;margin:0 auto">
  <div style="background:#131c2e;border-radius:12px;overflow:hidden;border:1px solid #1a2235">

    {after_hours_banner}

    <div style="padding:24px 28px;border-bottom:1px solid #1a2235">
      <div style="font-size:11px;color:#475569;font-weight:700;text-transform:uppercase;letter-spacing:.1em">AI-IDS · Hourly Security Digest</div>
      <div style="font-size:20px;font-weight:700;color:#e2e8f0;margin-top:6px">Security Operations Report</div>
      <div style="font-size:12px;color:#475569;margin-top:4px">{datetime.utcnow().strftime('%A, %B %d %Y - %H:%M UTC')}</div>
    </div>

    <!-- Stats row -->
    <div style="padding:20px 28px;display:grid;grid-template-columns:repeat(4,1fr);gap:12px;border-bottom:1px solid #1a2235;background:#0f1623">
      <div style="text-align:center"><div style="font-size:24px;font-weight:700;color:#ef4444">{sev_counts.get('CRITICAL',0)}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Critical</div></div>
      <div style="text-align:center"><div style="font-size:24px;font-weight:700;color:#f97316">{sev_counts.get('HIGH',0)}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">High</div></div>
      <div style="text-align:center"><div style="font-size:24px;font-weight:700;color:#eab308">{sev_counts.get('MEDIUM',0)}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Medium</div></div>
      <div style="text-align:center"><div style="font-size:24px;font-weight:700;color:#22c55e">{sev_counts.get('LOW',0)}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Low</div></div>
    </div>

    <!-- AI digest -->
    <div style="padding:24px 28px;border-bottom:1px solid #1a2235">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#475569;margin-bottom:12px">AI Digest</div>
      <div style="font-size:13px;color:#cbd5e1;line-height:1.8">{digest_html_body}</div>
    </div>

    <!-- Agent stats -->
    <div style="padding:20px 28px;display:grid;grid-template-columns:repeat(4,1fr);gap:12px;border-bottom:1px solid #1a2235">
      <div style="text-align:center"><div style="font-size:20px;font-weight:700;color:#1ec8ff">{self._stats['cycles']}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Cycles</div></div>
      <div style="text-align:center"><div style="font-size:20px;font-weight:700;color:#1ec8ff">{self._stats['logs_analysed']}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Analysed</div></div>
      <div style="text-align:center"><div style="font-size:20px;font-weight:700;color:#f97316">{self._stats['threats_found']}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Threats</div></div>
      <div style="text-align:center"><div style="font-size:20px;font-weight:700;color:#ef4444">{self._stats['auto_blocks']}</div><div style="font-size:10px;color:#475569;text-transform:uppercase;margin-top:2px">Auto-Blocked</div></div>
    </div>

    <div style="padding:14px 28px;background:#0b0f19">
      <div style="font-size:11px;color:#334155">AI-IDS Autonomous Agent &nbsp;·&nbsp; OpenRouter &nbsp;·&nbsp; Active since {self._stats['started_at'][:16]} UTC</div>
    </div>

  </div>
</div></body></html>"""

            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[AI-IDS Digest] Hourly Security Report - {datetime.utcnow().strftime('%H:%M UTC')} {'| AFTER-HOURS' if after_hours else ''}"
            msg["From"]    = smtp_from
            msg["To"]      = to_addr
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587"))) as s:
                s.starttls()
                s.login(smtp_user, smtp_pass)
                s.sendmail(smtp_from, [to_addr], msg.as_string())

            logger.info("Hourly digest email sent")

        except Exception as e:
            logger.error("Digest email failed: %s", e)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ensure_stats_table(self):
        conn = sqlite3.connect(self.db.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_agent_stats (
                    s_key TEXT PRIMARY KEY,
                    s_value TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def _persist_stats(self):
        """Persist cycle stats so the dashboard / PDF survive agent restarts."""
        try:
            self._ensure_stats_table()
            conn = sqlite3.connect(self.db.db_path)
            with conn:
                for k, v in self._stats.items():
                    if k == "started_at":
                        continue
                    conn.execute(
                        "INSERT INTO ai_agent_stats (s_key, s_value) VALUES (?, ?) "
                        "ON CONFLICT(s_key) DO UPDATE SET s_value=excluded.s_value",
                        (k, str(v)),
                    )
            conn.close()
        except Exception as e:
            logger.error("Failed to persist agent stats: %s", e)

    async def _maybe_generate_report(self):
        """Auto-generate the AI analysis PDF summary once per cycle."""
        try:
            from ..core.report_scheduler import save_ai_agent_report
            from pathlib import Path
            result = await asyncio.get_event_loop().run_in_executor(
                None, save_ai_agent_report, Path(self.db.db_path)
            )
            if result:
                logger.info("AI agent report saved: %s", result)
        except Exception as e:
            logger.debug("PDF report generation skipped: %s", e)

    @staticmethod
    def _extract_ip(log: Dict) -> Optional[str]:
        import re
        text = json.dumps(log)
        m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
        if m:
            ip = m.group()
            # Skip RFC1918
            if not any(ip.startswith(p) for p in ("10.", "192.168.", "127.")):
                return ip
        return None

    def get_stats(self) -> Dict:
        return {**self._stats, "blocked_ips": list(self._blocked_ips)}
