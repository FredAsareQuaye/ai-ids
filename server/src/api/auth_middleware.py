"""
API Authentication Middleware.
Provides a FastAPI dependency that validates X-API-Key header
for protected (write/delete) endpoints.
Also validates agent tokens for agent event submission.
"""
import os
import secrets
import logging
from fastapi import Header, HTTPException, status
from typing import Optional

logger = logging.getLogger(__name__)

# Master API key — set SIEM_API_KEY in server/.env
_SIEM_API_KEY: Optional[str] = None


def _get_api_key() -> str:
    global _SIEM_API_KEY
    if _SIEM_API_KEY is None:
        _SIEM_API_KEY = os.getenv("SIEM_API_KEY", "")
    return _SIEM_API_KEY


async def require_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    """
    FastAPI dependency — validates the X-API-Key header.
    Add as a dependency to any route that should be protected:
        @router.delete("/logs", dependencies=[Depends(require_api_key)])
    """
    expected = _get_api_key()
    if not expected:
        # SIEM_API_KEY not set — refuse all access to protected routes
        logger.error(
            "SIEM_API_KEY is not configured. "
            "Set it in server/.env to enable protected endpoints."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server API key not configured. Contact administrator.",
        )

    if not secrets.compare_digest(x_api_key, expected):
        logger.warning("Invalid API key attempt on protected endpoint")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


async def require_agent_token(
    x_agent_token: str = Header(..., alias="X-Agent-Token"),
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
):
    """
    FastAPI dependency — validates agent tokens.
    Agents must include both X-Agent-Token and X-Agent-Id headers.
    Returns (agent_id, token) tuple or raises 401.
    """
    if not x_agent_token or not x_agent_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent authentication headers",
        )

    # Validate via database — imported here to avoid circular deps
    from ..core.storage import Database
    db = Database("siem.db")
    agent = db.get_agent(x_agent_id)

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unknown agent ID: {x_agent_id}",
        )

    if not secrets.compare_digest(x_agent_token, agent.get("token", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent token",
        )

    if not agent.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent is disabled",
        )

    return {"agent_id": x_agent_id, "agent": agent}
