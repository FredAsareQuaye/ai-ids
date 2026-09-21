from typing import Dict, Any
from datetime import datetime
import asyncio
from ..ai.model import AIAnalyzer
from ..core.storage import Database
from ..core.correlation import CorrelationEngine
from ..core.threat_intel import ThreatIntelEnricher
from ..core.alert_notifier import AlertNotifier
from ..core.whitelist import WhitelistManager
from ..core.log_parser import parse_log
from ..core.playbook_engine import PlaybookEngine
from ..core.anomaly_detector import AnomalyDetector
from ..core.asset_inventory import AssetInventory
from ..core.geoip import GeoIPEnricher
from ..core.ueba import UEBAEngine
from ..core.threat_feed_sync import ThreatFeedSync
from ..core.deduplicator import Deduplicator
from ..core.custom_playbooks import CustomPlaybookStore
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogProcessor:
    def __init__(self, analyzer: AIAnalyzer, db: Database):
        self.analyzer = analyzer
        self.db = db
        self.processing_queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()

        # Pipeline modules
        self.correlation_engine = CorrelationEngine(db=db)
        self.threat_intel = ThreatIntelEnricher(db_path=db.db_path)
        self.notifier = AlertNotifier()
        self.whitelist = WhitelistManager(db_path=db.db_path)
        self.playbook_engine = PlaybookEngine(db=db, notifier=self.notifier)
        self.anomaly_detector = AnomalyDetector(db_path=db.db_path)
        self.asset_inventory = AssetInventory(db_path=db.db_path)
        self.geoip = GeoIPEnricher(db_path=db.db_path)
        self.ueba = UEBAEngine(db_path=db.db_path)
        self.feed_sync = ThreatFeedSync(db_path=db.db_path)
        self.deduplicator = Deduplicator(db_path=db.db_path)
        self.custom_playbooks = CustomPlaybookStore(db_path=db.db_path)

    async def process_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full pipeline:
          whitelist check -> normalize -> structured parse -> AI analysis
          -> threat intel -> store -> correlate -> playbooks -> notify
        """
        try:
            if "timestamp" not in log_data:
                log_data["timestamp"] = datetime.now().isoformat()

            # 1. Whitelist check — drop known-safe noise early
            if self.whitelist.is_whitelisted(log_data):
                logger.debug(f"Whitelisted event from {log_data.get('source', '?')} — skipped")
                return {"status": "whitelisted"}

            # 1b. Deduplication — suppress repeated identical events
            if self.deduplicator.check(log_data):
                return {"status": "deduplicated"}

            normalized_log = self._normalize_log(log_data)

            # 2. Asset inventory enrichment — boosts severity for critical assets
            normalized_log = self.asset_inventory.enrich_event(normalized_log)

            # GeoIP enrichment for source IP
            source_ip = normalized_log.get("source_ip") or normalized_log.get("source", "")
            geo = self.geoip.lookup(source_ip)
            if geo:
                normalized_log["geoip"] = geo

            # 3. Structured log parsing — enrich fields before AI sees them
            parsed_fields = parse_log(normalized_log.get("message", ""), normalized_log.get("source", ""))
            if parsed_fields:
                normalized_log["parsed"] = parsed_fields
                # Promote suspicious flag and source_ip from parser
                if parsed_fields.get("is_suspicious"):
                    if normalized_log.get("severity", "info").upper() not in ("HIGH", "CRITICAL"):
                        normalized_log["severity"] = "HIGH"
                if parsed_fields.get("source_ip") and not normalized_log.get("source_ip"):
                    normalized_log["source_ip"] = parsed_fields["source_ip"]
                if parsed_fields.get("username") and not normalized_log.get("username"):
                    normalized_log["username"] = parsed_fields["username"]

            # 3. AI analysis
            if self.analyzer.enabled:
                log_string = json.dumps(normalized_log)
                analysis = await self.analyzer.analyze_log(log_string)
                analysis_dict = {
                    "threat_level": analysis.threat_level,
                    "explanation": analysis.explanation,
                    "recommended_actions": analysis.recommended_actions,
                    "confidence": analysis.confidence,
                }
            else:
                severity = normalized_log.get("severity", "low").lower()
                analysis_dict = {
                    "threat_level": severity,
                    "explanation": "Basic severity-based analysis",
                    "recommended_actions": ["Review log details"],
                    "confidence": 0.5,
                }

            # 4. IP / threat intelligence enrichment
            source = normalized_log.get("source_ip") or normalized_log.get("source", "")
            threat_intel_data = self.threat_intel.enrich(source)
            if threat_intel_data.get("enriched") and threat_intel_data.get("abuse_score", 0) >= 25:
                logger.warning(
                    f"Known malicious IP {threat_intel_data.get('ip')} "
                    f"score={threat_intel_data.get('abuse_score')} "
                    f"country={threat_intel_data.get('country_code')}"
                )
                if analysis_dict["threat_level"] not in ("HIGH", "CRITICAL"):
                    analysis_dict["threat_level"] = "HIGH"
                analysis_dict["explanation"] += (
                    f" | IP reputation: abuse score "
                    f"{threat_intel_data.get('abuse_score')}/100 "
                    f"({threat_intel_data.get('country_code', '')}/"
                    f"{threat_intel_data.get('isp', '')})"
                )

            normalized_log["threat_intel"] = threat_intel_data

            # 4b. IOC feed matching
            ioc_match = self.feed_sync.match_event(normalized_log)
            if ioc_match:
                normalized_log["ioc_match"] = ioc_match
                if analysis_dict["threat_level"] not in ("HIGH", "CRITICAL"):
                    analysis_dict["threat_level"] = "HIGH"
                analysis_dict["explanation"] += (
                    f" | IOC match: {ioc_match.get('ioc_value')} "
                    f"in {ioc_match.get('feed')} (threat={ioc_match.get('threat', '?')})"
                )

            # 5. Persist
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.db.store_log(normalized_log, analysis_dict)
            )

            # 5b. UEBA — user behavior analytics
            ueba_anomaly = self.ueba.record_event(normalized_log)
            if ueba_anomaly:
                logger.warning(f"UEBA anomaly: {ueba_anomaly['rule_name']} for {ueba_anomaly['source']}")
                self.db.store_correlation(ueba_anomaly)

            # 5c. Custom playbook evaluation
            matched_custom = self.custom_playbooks.evaluate(normalized_log)
            for pb in matched_custom:
                actions_taken = [a.get("type", "?") for a in pb.get("actions", [])]
                logger.info(f"Custom playbook '{pb['name']}' matched — actions: {actions_taken}")
                self.custom_playbooks.record_execution(pb, normalized_log, actions_taken)

            # 6. Anomaly detection (statistical baseline check)
            anomaly = self.anomaly_detector.record_event(normalized_log.get("source", "unknown"))
            if anomaly:
                logger.warning(
                    f"Anomaly detected: {anomaly['description']}"
                )
                self.db.store_correlation(anomaly)
                await asyncio.get_event_loop().run_in_executor(
                    None, self.notifier.notify_correlation, anomaly
                )

            # 7. Correlation engine (rule-based)
            correlation = self.correlation_engine.process_event(
                {**normalized_log, "analysis": analysis_dict}
            )

            # 9. Playbook execution on correlation
            if correlation:
                logger.warning(
                    f"ATT&CK Correlation fired: {correlation['rule_name']} "
                    f"[{correlation['mitre_id']}] from {correlation['source']}"
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, self.playbook_engine.execute, correlation
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, self.notifier.notify_correlation, correlation
                )

            # 8. Notifications for high-severity events
            if analysis_dict["threat_level"].upper() in ("HIGH", "CRITICAL"):
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.notifier.notify_event,
                    normalized_log,
                    analysis_dict,
                )

            return {
                "status": "success",
                "log": normalized_log,
                "analysis": analysis_dict,
                "threat_intel": threat_intel_data,
                "correlation": correlation,
            }

        except Exception as e:
            logger.error(f"Error processing log: {str(e)}")
            return {"status": "error", "error": str(e)}

    def _normalize_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": log_data.get("timestamp", datetime.now().isoformat()),
            "source": log_data.get("source", "unknown"),
            "event_type": log_data.get("event_type", "unknown"),
            "message": log_data.get("message", ""),
            "severity": log_data.get("severity", "info"),
            "event_id": log_data.get("event_id", 0),
            "agent_id": log_data.get("agent_id", "unknown"),
            "host_info": log_data.get("host_info", {}),
            "details": log_data.get("details", {}),
        }
