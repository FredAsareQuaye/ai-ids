"""Shared backend configuration — reads SIEM_BACKEND_URL once."""
import os

BACKEND_BASE = os.environ.get("SIEM_BACKEND_URL", "https://backend:8000").rstrip("/")
BACKEND = f"{BACKEND_BASE}/api/v1"
