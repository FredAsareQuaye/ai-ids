"""
OpenRouter AI integration for AI-IDS.
Drop-in replacement for the former Gemini/DeepSeek API module — all function
signatures are identical so existing callers require no changes.
"""
import warnings
warnings.filterwarnings("ignore")

import os
import requests
import json
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL   = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")


def _get_api_key() -> str:
    """Resolve OPENROUTER_API_KEY from env → server/.env → session state."""
    key = os.getenv("OPENROUTER_API_KEY", "")
    if not key:
        try:
            from pathlib import Path
            env_path = Path(__file__).parent.parent.parent.parent / "server" / ".env"
            if env_path.exists():
                for line in env_path.read_text().splitlines():
                    if line.startswith("OPENROUTER_API_KEY="):
                        key = line.split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    if not key and hasattr(st, "session_state"):
        key = st.session_state.get("ai_config", {}).get("api_key", "")
    return key


def _call_deepseek(prompt: str, timeout: int = 45) -> str:
    """
    Send a prompt to OpenRouter and return the response text.
    Raises on HTTP or connection errors.
    """
    api_key = _get_api_key()
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY not configured.")

    response = requests.post(
        OPENROUTER_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
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
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


# ─────────────────────────────────────────────────────────────────────────────
# Public API (identical signatures to the former Gemini module)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_scan_with_deepseek(scan_output: str, update_progress_callback=None) -> dict:
    """Analyse nmap scan output with DeepSeek and return structured findings."""
    if update_progress_callback:
        update_progress_callback(0.1)

    max_len = 32000
    if len(scan_output) > max_len:
        scan_output = scan_output[:max_len] + "\n[Output truncated]"

    prompt = (
        "Analyze this nmap scan output and identify vulnerabilities, open ports, and security risks. "
        "Provide detailed information about each vulnerability including severity, affected port, and remediation steps. "
        "For any CVEs detected, include the CVE ID and a brief description.\n\n"
        f"Scan Output:\n{scan_output}\n\n"
        "Respond ONLY with valid JSON matching this structure:\n"
        "{\n"
        "  \"total_vulnerabilities\": <number>,\n"
        "  \"vulnerabilities\": [{\"name\": \"\", \"severity\": \"\", \"port\": \"\", \"service\": \"\", \"description\": \"\"}],\n"
        "  \"open_ports\": [{\"port\": \"\", \"service\": \"\", \"details\": \"\"}],\n"
        "  \"summary\": \"\",\n"
        "  \"risk_level\": \"Critical|High|Medium|Low\",\n"
        "  \"recommendations\": [\"\"]\n"
        "}"
    )

    if update_progress_callback:
        update_progress_callback(0.3)

    try:
        if update_progress_callback:
            update_progress_callback(0.5)

        raw = _call_deepseek(prompt)

        if update_progress_callback:
            update_progress_callback(0.8)

        j_start = raw.find("{")
        j_end   = raw.rfind("}") + 1
        insights = json.loads(raw[j_start:j_end] if j_start >= 0 else raw)
        insights["raw_response"] = raw

        if update_progress_callback:
            update_progress_callback(1.0)
        return insights

    except json.JSONDecodeError:
        if update_progress_callback:
            update_progress_callback(1.0)
        return {
            "error": "Failed to parse OpenRouter response as JSON",
            "raw_response": raw if "raw" in dir() else "",
            "vulnerabilities": [], "ports": [],
            "summary": "", "risk_level": "Unknown", "recommendations": [],
        }
    except ValueError as e:
        if update_progress_callback:
            update_progress_callback(1.0)
        return {
            "error": str(e),
            "vulnerabilities": [], "ports": [],
            "summary": "", "risk_level": "Unknown", "recommendations": [],
        }
    except requests.exceptions.Timeout:
        if update_progress_callback:
            update_progress_callback(1.0)
        return {
            "error": "Request to OpenRouter API timed out.",
            "vulnerabilities": [], "ports": [],
            "summary": "", "risk_level": "Unknown", "recommendations": [],
        }
    except Exception as e:
        if update_progress_callback:
            update_progress_callback(1.0)
        return {
            "error": str(e),
            "vulnerabilities": [], "ports": [],
            "summary": "", "risk_level": "Unknown", "recommendations": [],
        }


# Alias used by legacy callers that still import the Gemini name
def analyze_scan_with_gemini(scan_output, update_progress_callback=None):
    return analyze_scan_with_deepseek(scan_output, update_progress_callback)


def analyze_alert_with_deepseek(alert_data: dict) -> str:
    """Analyse a single security alert with DeepSeek and return analysis text."""
    try:
        api_key = _get_api_key()
        if not api_key:
            return "OpenRouter API key not configured. Please set OPENROUTER_API_KEY in Settings → AI Settings."
    except Exception:
        return "OpenRouter API key not configured."

    prompt = (
        "Analyze this security alert and provide insights about the threat, potential impact, "
        "and recommended actions:\n\n"
        f"Source:    {alert_data.get('source', 'Unknown')}\n"
        f"Severity:  {alert_data.get('severity', 'Unknown')}\n"
        f"Message:   {alert_data.get('message', 'No message')}\n"
        f"Timestamp: {alert_data.get('timestamp', 'Unknown')}\n"
        f"Details:   {json.dumps(alert_data.get('details', {}), indent=2)}\n\n"
        "Provide:\n"
        "1. Analysis of the security threat\n"
        "2. Potential impact and risk assessment\n"
        "3. Recommended immediate actions\n"
        "4. Suggested follow-up measures\n"
        "5. Relevant security best practices\n\n"
        "Format in clear, actionable sections."
    )

    try:
        return _call_deepseek(prompt)
    except requests.exceptions.Timeout:
        return "Request to OpenRouter API timed out. Please try again."
    except requests.exceptions.ConnectionError as e:
        return f"Connection error when calling OpenRouter API: {e}"
    except Exception as e:
        return f"Error generating AI analysis: {e}"


def analyze_alert_with_gemini(alert_data):
    return analyze_alert_with_deepseek(alert_data)


def analyze_logs_with_deepseek(logs_data: list, analysis_type: str = "comprehensive") -> str:
    """Analyse a batch of log entries with DeepSeek."""
    try:
        api_key = _get_api_key()
        if not api_key:
            return "OpenRouter API key not configured. Please set OPENROUTER_API_KEY in Settings → AI Settings."
    except Exception:
        return "OpenRouter API key not configured."

    if not logs_data:
        return "No logs provided for analysis."

    limited = logs_data[:50]
    lines = []
    for i, log in enumerate(limited):
        entry = (
            f"Log {i+1}:\n"
            f"  Time:     {log.get('timestamp', 'Unknown')}\n"
            f"  Source:   {log.get('source', 'Unknown')}\n"
            f"  Severity: {log.get('severity', 'Unknown')}\n"
            f"  Message:  {log.get('message', 'No message')}\n"
        )
        if log.get("details"):
            entry += f"  Details:  {json.dumps(log['details'], indent=2)}\n"
        lines.append(entry)
    logs_text = "\n".join(lines)

    prompts = {
        "comprehensive": (
            f"Analyze these security logs and provide a comprehensive security assessment:\n\n{logs_text}\n\n"
            "Provide:\n"
            "1. Overall security posture assessment\n"
            "2. Key threats and vulnerabilities identified\n"
            "3. Attack patterns or suspicious activities\n"
            "4. Risk level assessment (Critical/High/Medium/Low)\n"
            "5. Immediate action items and recommendations\n"
            "6. Long-term security improvements\n"
            "7. Summary of findings\n\n"
            "Format in clear, actionable sections with specific recommendations."
        ),
        "patterns": (
            f"Analyze these security logs for patterns, anomalies, and potential security issues:\n\n{logs_text}\n\n"
            "Identify:\n"
            "1. Common attack patterns\n"
            "2. Unusual or anomalous behavior\n"
            "3. Potential security incidents\n"
            "4. Correlation between events\n"
            "5. Recommendations for investigation\n\n"
            "Focus on actionable insights and security implications."
        ),
        "vulnerability_assessment": (
            f"Analyze this AI model vulnerability assessment data and provide expert security insights:\n\n{logs_text}\n\n"
            "Provide:\n"
            "1. Overall AI Model Security Assessment (Excellent/Good/Fair/Poor)\n"
            "2. Key Vulnerability Findings and Risk Analysis\n"
            "3. Jailbreak Technique Effectiveness Assessment\n"
            "4. Security Score Interpretation and Benchmarking\n"
            "5. Critical Issues Requiring Immediate Attention\n"
            "6. Model-Specific Security Recommendations\n"
            "7. Long-term AI Safety Improvements\n"
            "8. Deployment Risk Assessment\n\n"
            "Focus on actionable security recommendations specific to AI model deployment."
        ),
    }
    prompt = prompts.get(analysis_type, f"Analyze these security logs and provide insights:\n\n{logs_text}\n\nProvide key security insights and recommendations.")

    try:
        return _call_deepseek(prompt)
    except requests.exceptions.Timeout:
        return "Request to OpenRouter API timed out. Please try again."
    except requests.exceptions.ConnectionError as e:
        return f"Connection error when calling OpenRouter API: {e}"
    except Exception as e:
        return f"Error generating logs analysis: {e}"


def analyze_logs_with_gemini(logs_data, analysis_type="comprehensive"):
    return analyze_logs_with_deepseek(logs_data, analysis_type)
