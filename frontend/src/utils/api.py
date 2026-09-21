import requests  # type: ignore
from requests.adapters import HTTPAdapter  # type: ignore
from urllib3.util.retry import Retry
from datetime import datetime, timedelta

from config import BACKEND
BACKEND_URL = BACKEND
VERIFY_SSL = False

def create_session():
    """Create a session with retry logic"""
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "DELETE"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('https://', adapter)
    session.verify = False
    return session

def get_alert_details(session, alert_id):
    """Fetch alert details from the API"""
    try:
        response = session.get(
            f"{BACKEND_URL}/threats/{alert_id}",
            verify=False,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise Exception(f"Failed to fetch alert details: {e}")

def get_ai_insights():
    """Get AI-powered insights for logs"""
    session = create_session()
    try:
        # In a real implementation, this would call your AI service
        # For now, we'll return mock data
        return {
            "critical_anomalies": 8,
            "suspicious_patterns": 15,
            "security_incidents": 3,
            "high_risk_indicators": 12,
            "trend_data": [
                {"date": (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d"), 
                 "alerts": max(0, 10 - i) * 2 + 3}
                for i in range(7, -1, -1)
            ],
            "threat_intel": [
                {"type": "Brute Force Attempts", "severity": "High", "count": 12, "source": "External"},
                {"type": "Suspicious Login", "severity": "Medium", "count": 5, "source": "Internal"},
                {"type": "Data Exfiltration", "severity": "Critical", "count": 2, "source": "External"}
            ],
            "recommendations": [
                {"title": "Enable MFA for Admin Accounts", "priority": "High", "impact": "High"},
                {"title": "Update Firewall Rules", "priority": "Medium", "impact": "Medium"},
                {"title": "Review Suspicious IPs", "priority": "High", "impact": "High"}
            ]
        }
    except Exception as e:
        raise Exception(f"Failed to get AI insights: {e}")