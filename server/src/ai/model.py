import datetime
import requests
import logging
from typing import Dict, Any
import os
from dataclasses import dataclass, asdict
import json

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")


@dataclass
class AIAnalysis:
    threat_level: str
    explanation: str
    recommended_actions: list[str]
    confidence: float


class AIAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.enabled = bool(self.api_key) and os.getenv("AI_ENABLED", "false").lower() == "true"
        self.logger = logging.getLogger(__name__)

    async def test_connection(self) -> bool:
        if not self.enabled:
            return True
        try:
            r = requests.post(
                OPENROUTER_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/yourusername/aisiem",
                    "X-Title": "AI-IDS",
                },
                json={"model": OPENROUTER_MODEL, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
                timeout=10,
            )
            r.raise_for_status()
            self.logger.info("OpenRouter connection OK")
            return True
        except Exception as e:
            self.logger.warning(f"OpenRouter connection failed: {e}")
            return False

    def analyze_log(self, log_data: str) -> Dict[str, Any]:
        if not self.enabled:
            return self._get_basic_analysis(log_data)
        try:
            prompt = self._create_analysis_prompt(log_data)
            r = requests.post(
                OPENROUTER_API_URL,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://github.com/yourusername/aisiem",
                    "X-Title": "AI-IDS",
                },
                json={"model": OPENROUTER_MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False},
                timeout=30,
            )
            r.raise_for_status()
            ai_text = r.json()["choices"][0]["message"]["content"]
            analysis = self._parse_ai_response(ai_text)
            return {"analysis": asdict(analysis), "ai_enabled": True, "timestamp": datetime.datetime.utcnow().isoformat()}
        except Exception as e:
            self.logger.error(f"OpenRouter analysis failed: {e}")
            return self._get_basic_analysis(log_data)

    def _get_basic_analysis(self, log_data: str) -> Dict[str, Any]:
        log_lower = log_data.lower()
        threat_level = "low"
        if any(k in log_lower for k in ["attack", "breach", "unauthorized", "malware", "exploit"]):
            threat_level = "high"
        elif any(k in log_lower for k in ["warning", "failed", "error", "suspicious"]):
            threat_level = "medium"
        analysis = AIAnalysis(
            threat_level=threat_level,
            explanation="Rule-based analysis (AI disabled or key not set)",
            recommended_actions=["Manual review recommended"],
            confidence=0.5,
        )
        return {"analysis": asdict(analysis), "ai_enabled": False, "timestamp": datetime.datetime.utcnow().isoformat()}

    def _create_analysis_prompt(self, log_data: str) -> str:
        return (
            "Analyze this security log and provide:\n"
            "1. Threat level (high/medium/low)\n"
            "2. Brief explanation\n"
            "3. List of recommended actions\n"
            "4. Confidence score (0.0-1.0)\n\n"
            f"Log: {log_data}\n\n"
            "Respond ONLY with valid JSON:\n"
            '{"threat_level": "...", "explanation": "...", "recommended_actions": ["..."], "confidence": 0.0}'
        )

    def _parse_ai_response(self, response: str) -> AIAnalysis:
        try:
            j_start = response.find("{")
            j_end   = response.rfind("}") + 1
            data = json.loads(response[j_start:j_end] if j_start >= 0 else response)
            return AIAnalysis(
                threat_level=data.get("threat_level", "unknown"),
                explanation=data.get("explanation", "Analysis failed"),
                recommended_actions=data.get("recommended_actions", []),
                confidence=float(data.get("confidence", 0.0)),
            )
        except (json.JSONDecodeError, ValueError):
            self.logger.error("Failed to parse OpenRouter response")
            return AIAnalysis("unknown", "Analysis failed", ["Manual review required"], 0.0)
