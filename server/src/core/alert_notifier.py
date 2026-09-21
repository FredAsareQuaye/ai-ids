"""
Alert Notification System.
Supports Email (SMTP), Slack webhooks, and generic webhooks.
Triggered for HIGH/CRITICAL events and correlation rule fires.
"""
import logging
import os
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class AlertNotifier:
    """
    Sends notifications through multiple channels when security
    events exceed the severity threshold.
    """

    def __init__(self):
        # Email config
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.smtp_from = os.getenv("SMTP_FROM", self.smtp_user)
        self.alert_email_to = os.getenv("ALERT_EMAIL_TO", "")

        # Webhook config
        self.slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.generic_webhook_url = os.getenv("WEBHOOK_URL", "")

        # Only notify for these severity levels
        self.notify_severities = {"HIGH", "CRITICAL"}

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def notify_event(self, log_data: Dict[str, Any], analysis: Dict[str, Any]):
        """
        Send notifications for a raw security event if it meets the threshold.
        """
        severity = (
            log_data.get("severity", "")
            or analysis.get("threat_level", "")
        ).upper()

        if severity not in self.notify_severities:
            return

        subject = f"[SIEM ALERT] {severity} event from {log_data.get('source', 'Unknown')}"
        body = self._format_event_body(log_data, analysis)
        self._dispatch(subject, body, severity, source_type="event")

    def notify_correlation(self, correlation: Dict[str, Any]):
        """
        Send notifications when a MITRE ATT&CK correlation rule fires.
        """
        severity = correlation.get("severity", "HIGH").upper()
        rule_name = correlation.get("rule_name", "Unknown Rule")
        mitre_id = correlation.get("mitre_id", "")
        source = correlation.get("source", "Unknown")

        subject = (
            f"[SIEM CORRELATION] {rule_name} [{mitre_id}] from {source}"
        )
        body = self._format_correlation_body(correlation)
        self._dispatch(subject, body, severity, source_type="correlation")

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _dispatch(
        self,
        subject: str,
        body: str,
        severity: str,
        source_type: str = "event",
    ):
        errors = []

        if self.smtp_user and self.smtp_password and self.alert_email_to:
            err = self._send_email(subject, body)
            if err:
                errors.append(f"email: {err}")

        if self.slack_webhook_url:
            err = self._send_slack(subject, body, severity)
            if err:
                errors.append(f"slack: {err}")

        if self.generic_webhook_url:
            err = self._send_webhook(subject, body, severity, source_type)
            if err:
                errors.append(f"webhook: {err}")

        if errors:
            logger.warning(f"Notification errors: {'; '.join(errors)}")
        else:
            logger.info(f"Alert dispatched: {subject}")

    def _send_email(self, subject: str, body: str) -> Optional[str]:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.smtp_from
            msg["To"] = self.alert_email_to

            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(self._wrap_html(subject, body), "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.smtp_from, self.alert_email_to, msg.as_string())

            return None
        except Exception as e:
            return str(e)

    def _send_slack(
        self, subject: str, body: str, severity: str
    ) -> Optional[str]:
        color_map = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff8800",
            "MEDIUM": "#ffcc00",
            "LOW": "#00cc44",
        }
        color = color_map.get(severity, "#888888")
        emoji = ":rotating_light:" if severity == "CRITICAL" else ":warning:"

        payload = {
            "text": f"{emoji} *{subject}*",
            "attachments": [
                {
                    "color": color,
                    "text": body,
                    "footer": f"AI-IDS | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    "mrkdwn_in": ["text"],
                }
            ],
        }
        try:
            resp = requests.post(
                self.slack_webhook_url,
                json=payload,
                timeout=5,
            )
            if resp.status_code != 200:
                return f"HTTP {resp.status_code}"
            return None
        except Exception as e:
            return str(e)

    def _send_webhook(
        self,
        subject: str,
        body: str,
        severity: str,
        source_type: str,
    ) -> Optional[str]:
        payload = {
            "title": subject,
            "body": body,
            "severity": severity,
            "type": source_type,
            "timestamp": datetime.utcnow().isoformat(),
            "source": "AI-IDS",
        }
        try:
            resp = requests.post(
                self.generic_webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if resp.status_code not in (200, 201, 204):
                return f"HTTP {resp.status_code}"
            return None
        except Exception as e:
            return str(e)

    def _format_event_body(
        self, log_data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        ts = log_data.get("timestamp", datetime.utcnow().isoformat())
        return (
            f"SECURITY EVENT ALERT\n"
            f"{'='*50}\n"
            f"Time      : {ts}\n"
            f"Source    : {log_data.get('source', 'Unknown')}\n"
            f"Severity  : {log_data.get('severity', 'Unknown').upper()}\n"
            f"Message   : {log_data.get('message', 'No message')}\n"
            f"\nAI ANALYSIS\n"
            f"{'='*50}\n"
            f"Threat    : {analysis.get('threat_level', 'N/A').upper()}\n"
            f"Confidence: {analysis.get('confidence', 0):.0%}\n"
            f"Explanation: {analysis.get('explanation', 'N/A')}\n"
            f"Actions   : {', '.join(analysis.get('recommended_actions', []))}\n"
            f"{'='*50}\n"
            f"This alert was generated by AI-IDS."
        )

    def _format_correlation_body(self, correlation: Dict[str, Any]) -> str:
        samples = "\n  - ".join(correlation.get("sample_events", []))
        return (
            f"THREAT CORRELATION DETECTED\n"
            f"{'='*50}\n"
            f"Rule      : {correlation.get('rule_name', 'N/A')}\n"
            f"MITRE ID  : {correlation.get('mitre_id', 'N/A')}\n"
            f"Tactic    : {correlation.get('mitre_tactic', 'N/A')}\n"
            f"Reference : {correlation.get('mitre_url', 'N/A')}\n"
            f"Source    : {correlation.get('source', 'Unknown')}\n"
            f"Severity  : {correlation.get('severity', 'N/A')}\n"
            f"Matched   : {correlation.get('matched_count', 0)} events\n"
            f"Fired At  : {correlation.get('fired_at', 'N/A')}\n"
            f"\nDESCRIPTION\n"
            f"{correlation.get('description', '')}\n"
            f"\nSAMPLE EVENTS\n"
            f"  - {samples}\n"
            f"{'='*50}\n"
            f"View details in AI-IDS dashboard."
        )

    def _wrap_html(self, title: str, body: str) -> str:
        body_html = body.replace("\n", "<br>").replace("=", "&#61;")
        return f"""
<html><body style="font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px;">
<div style="background: #16213e; border-radius: 8px; padding: 20px; max-width: 700px;">
<h2 style="color: #ff4444;">{title}</h2>
<pre style="white-space: pre-wrap; color: #e0e0e0;">{body_html}</pre>
<hr style="border-color: #444;">
<small style="color: #888;">Generated by AI-IDS Security Platform</small>
</div></body></html>"""
