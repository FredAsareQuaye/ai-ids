import requests  # type: ignore
import sys
import time
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def verify_database():
    db_path = Path(__file__).parent.parent / "siem.db"
    if not db_path.exists():
        logger.error("Database file not found")
        return False
    return True

def verify_server(max_attempts=5):
    url = "http://localhost:8000/api/v1/threats"
    
    for attempt in range(max_attempts):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            logger.info("Server connection verified")
            return True
        except requests.exceptions.RequestException as e:
            logger.warning(f"Attempt {attempt + 1}/{max_attempts} failed: {e}")
            if attempt < max_attempts - 1:
                time.sleep(2)
            continue
    
    logger.error("Server verification failed")
    return False

if __name__ == "__main__":
    if not verify_database():
        sys.exit(1)
    if not verify_server():
        sys.exit(1)
    logger.info("System verification completed successfully")