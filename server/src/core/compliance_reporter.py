"""
Compliance Report Generator

Maps ingested SIEM events to control requirements for:
  • PCI-DSS v4.0
  • ISO/IEC 27001:2022
  • SOC 2 (Trust Service Criteria)

Generates a PDF compliance-gap report showing evidence, violations,
and uncovered controls for auditor hand-off.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Control framework definitions ─────────────────────────────────────────────

PCI_DSS_CONTROLS = [
    {"id": "PCI-1.1", "name": "Install and maintain network security controls",
     "keywords": ["firewall", "network", "acl", "packet filter"]},
    {"id": "PCI-2.1", "name": "Do not use vendor-supplied defaults",
     "keywords": ["default password", "default credential", "default config"]},
    {"id": "PCI-6.3", "name": "Protect all system components from known vulnerabilities",
     "keywords": ["vulnerability", "cve", "patch", "exploit", "vuln"]},
    {"id": "PCI-7.1", "name": "Limit access to system components",
     "keywords": ["access denied", "unauthorized", "privilege", "permission denied"]},
    {"id": "PCI-8.2", "name": "Uniquely identify each user",
     "keywords": ["login", "authentication", "logon", "user", "account"]},
    {"id": "PCI-10.2", "name": "Implement audit logs",
     "keywords": ["audit", "log", "event", "syslog"]},
    {"id": "PCI-10.3", "name": "Protect audit logs from destruction",
     "keywords": ["log tamper", "log delete", "audit clear"]},
    {"id": "PCI-11.3", "name": "Manage all other applicable vulnerabilities",
     "keywords": ["scan", "nmap", "nessus", "openvas", "vulnerability scan"]},
    {"id": "PCI-12.10", "name": "Respond to suspected or confirmed security incidents",
     "keywords": ["incident", "breach", "intrusion", "alert", "critical", "high"]},
]

ISO27001_CONTROLS = [
    {"id": "A.5.1", "name": "Information security policies",
     "keywords": ["policy", "procedure", "governance"]},
    {"id": "A.8.5", "name": "Secure authentication",
     "keywords": ["authentication", "login", "password", "mfa", "2fa", "totp"]},
    {"id": "A.8.15", "name": "Logging and monitoring",
     "keywords": ["log", "monitor", "event", "audit", "syslog"]},
    {"id": "A.8.16", "name": "Monitoring activities",
     "keywords": ["anomaly", "detection", "alert", "intrusion", "ids", "ips"]},
    {"id": "A.8.23", "name": "Web filtering",
     "keywords": ["url", "web", "http", "malicious url", "phishing"]},
    {"id": "A.8.22", "name": "Segregation of networks",
     "keywords": ["firewall", "vlan", "segment", "dmz"]},
    {"id": "A.6.8", "name": "Information security event reporting",
     "keywords": ["incident", "report", "case", "alert"]},
    {"id": "A.8.8", "name": "Management of technical vulnerabilities",
     "keywords": ["vulnerability", "cve", "patch", "exploit"]},
    {"id": "A.5.26", "name": "Response to information security incidents",
     "keywords": ["response", "playbook", "remediation", "block", "quarantine"]},
]

SOC2_CONTROLS = [
    {"id": "CC6.1", "name": "Logical and physical access controls",
     "keywords": ["access denied", "unauthorized", "login", "authentication", "permission"]},
    {"id": "CC6.2", "name": "New users, credentials, access removal",
     "keywords": ["new user", "account created", "user added", "account deleted"]},
    {"id": "CC6.3", "name": "Role-based access",
     "keywords": ["privilege", "role", "sudo", "admin", "root"]},
    {"id": "CC7.1", "name": "Vulnerability detection",
     "keywords": ["vulnerability", "scan", "cve", "exploit"]},
    {"id": "CC7.2", "name": "Monitor system components",
     "keywords": ["monitor", "heartbeat", "agent", "alive", "offline"]},
    {"id": "CC7.3", "name": "Evaluate security events",
     "keywords": ["alert", "event", "log", "correlation", "anomaly"]},
    {"id": "CC7.4", "name": "Respond to identified security incidents",
     "keywords": ["incident", "case", "playbook", "block", "response"]},
    {"id": "CC7.5", "name": "Identify and communicate breaches",
     "keywords": ["breach", "exfiltration", "data loss", "critical", "high"]},
    {"id": "CC9.1", "name": "Risk assessment",
     "keywords": ["risk", "threat", "intel", "feed", "ioc"]},
]

FRAMEWORKS = {
    "PCI-DSS": PCI_DSS_CONTROLS,
    "ISO 27001": ISO27001_CONTROLS,
    "SOC 2": SOC2_CONTROLS,
}


class ComplianceReporter:
    def __init__(self, db):
        self.db = db

    # ── Analysis ──────────────────────────────────────────────────────────────

    def analyse(self, framework: str, days: int = 30) -> Dict:
        """
        Analyse events against the chosen framework's controls.
        Returns a structured report dict.
        """
        controls = FRAMEWORKS.get(framework, [])
        if not controls:
            return {"error": f"Unknown framework: {framework}"}

        threats = self.db.get_threats()
        # Use all logs when days >= 365, otherwise apply cutoff
        if days >= 365:
            recent = threats
        else:
            cutoff = datetime.now() - timedelta(days=days)
            recent = []
            for t in threats:
                try:
                    ts = datetime.fromisoformat(str(t.get("timestamp", "")))
                    if ts >= cutoff:
                        recent.append(t)
                except Exception:
                    recent.append(t)  # include if timestamp unparseable

        report_controls = []
        for ctrl in controls:
            evidence = self._find_evidence(ctrl, recent)
            violations = self._find_violations(ctrl, recent)
            status = self._assess_status(evidence, violations)
            report_controls.append({
                "id": ctrl["id"],
                "name": ctrl["name"],
                "status": status,
                "evidence_count": len(evidence),
                "violation_count": len(violations),
                "evidence_samples": evidence[:3],
                "violation_samples": violations[:3],
            })

        covered = sum(1 for c in report_controls if c["status"] != "no_coverage")
        violations_total = sum(c["violation_count"] for c in report_controls)
        evidence_total = sum(c["evidence_count"] for c in report_controls)
        coverage_pct = round(covered / len(controls) * 100, 1) if controls else 0

        return {
            "framework": framework,
            "period_days": days,
            "generated_at": datetime.now().isoformat(),
            "total_controls": len(controls),
            "covered": covered,
            "coverage_pct": coverage_pct,
            "total_evidence": evidence_total,
            "total_violations": violations_total,
            "controls": report_controls,
        }

    def _find_evidence(self, ctrl: Dict, events: List[Dict]) -> List[Dict]:
        evidence = []
        for evt in events:
            msg = (evt.get("message", "") or "").lower()
            src = (evt.get("source", "") or "").lower()
            combined = msg + " " + src
            if any(kw in combined for kw in ctrl["keywords"]):
                sev = (evt.get("severity", "") or "").upper()
                if sev not in ("CRITICAL", "HIGH"):
                    evidence.append({
                        "timestamp": str(evt.get("timestamp", ""))[:16],
                        "source": evt.get("source", ""),
                        "message": str(evt.get("message", ""))[:100],
                        "severity": sev,
                    })
        return evidence

    def _find_violations(self, ctrl: Dict, events: List[Dict]) -> List[Dict]:
        violations = []
        for evt in events:
            msg = (evt.get("message", "") or "").lower()
            src = (evt.get("source", "") or "").lower()
            combined = msg + " " + src
            sev = (evt.get("severity", "") or "").upper()
            if any(kw in combined for kw in ctrl["keywords"]) and sev in ("CRITICAL", "HIGH"):
                violations.append({
                    "timestamp": str(evt.get("timestamp", ""))[:16],
                    "source": evt.get("source", ""),
                    "message": str(evt.get("message", ""))[:100],
                    "severity": sev,
                })
        return violations

    @staticmethod
    def _assess_status(evidence: List, violations: List) -> str:
        if violations:
            return "violations"
        if evidence:
            return "compliant"
        return "no_coverage"

    # ── PDF generation ────────────────────────────────────────────────────────

    def generate_pdf(self, framework: str, days: int = 30) -> Optional[bytes]:
        try:
            from fpdf import FPDF
        except ImportError:
            logger.error("fpdf2 not installed — cannot generate compliance PDF")
            return None

        data = self.analyse(framework, days)
        now = datetime.now()

        pdf = FPDF()
        pdf.add_page()

        # ── Header ────────────────────────────────────────────────────────────
        pdf.set_fill_color(20, 40, 80)
        pdf.rect(0, 0, 210, 32, "F")
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_y(8)
        pdf.cell(0, 10, f"{framework} Compliance Report", align="C", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6,
                 f"Generated: {now.strftime('%Y-%m-%d %H:%M')}   "
                 f"Period: Last {days} days",
                 align="C", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(8)

        # ── Summary ───────────────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 11)
        rows = [
            ("Framework", framework),
            ("Total Controls", str(data["total_controls"])),
            ("Controls with Coverage", str(data["covered"])),
            ("Coverage %", f"{data['coverage_pct']}%"),
            ("Evidence Events", str(data["total_evidence"])),
            ("Violation Events", str(data["total_violations"])),
        ]
        for label, value in rows:
            pdf.cell(90, 7, label + ":", border="B")
            pdf.cell(0, 7, value, border="B", ln=True)
        pdf.ln(6)

        # ── Controls table ────────────────────────────────────────────────────
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Control Assessment", ln=True)

        # Colour legend
        pdf.set_font("Helvetica", "I", 9)
        pdf.cell(0, 5, "GREEN = compliant   RED = violations   GREY = no coverage", ln=True)
        pdf.ln(2)

        for ctrl in data["controls"]:
            status = ctrl["status"]
            if status == "compliant":
                pdf.set_fill_color(200, 240, 200)
                status_label = "COMPLIANT"
            elif status == "violations":
                pdf.set_fill_color(255, 200, 200)
                status_label = f"VIOLATIONS ({ctrl['violation_count']})"
            else:
                pdf.set_fill_color(220, 220, 220)
                status_label = "NO COVERAGE"

            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(22, 6, ctrl["id"], border=1, fill=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(120, 6, ctrl["name"][:60], border=1, fill=True)
            pdf.cell(30, 6, status_label, border=1, fill=True)
            pdf.cell(0, 6, f"Evid:{ctrl['evidence_count']}", border=1, fill=True, ln=True)

            # Violation samples
            for v in ctrl.get("violation_samples", []):
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(180, 0, 0)
                line = f"  [{v['severity']}] {v['source']} @ {v['timestamp']}: {v['message'][:60]}"
                pdf.cell(0, 4, line[:100], ln=True)
            pdf.set_text_color(0, 0, 0)

        return bytes(pdf.output())
