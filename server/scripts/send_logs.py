import requests  # type: ignore
import json
import time
from pathlib import Path
from requests  # type: ignore.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import sys
import logging
from datetime import datetime

# Configure logging with timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_session():
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504]
    )
    session.mount('http://', HTTPAdapter(max_retries=retries))
    return session

def verify_server():
    try:
        session = create_session()
        response = session.get(
            "http://localhost:8000/api/v1/threats",
            timeout=30  # Increased timeout
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error: Server is not running or not accessible: {e}")
        return False

def load_dummy_logs():
    logs_path = Path(__file__).parent.parent / "data" / "dummy_logs.json"
    try:
        with open(logs_path) as f:
            logs = json.load(f)
        logger.info(f"Successfully loaded {len(logs)} logs from {logs_path}")
        return logs
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error reading logs file: {e}")
        return None

def send_logs():
    if not verify_server():
        logger.error("Server verification failed. Make sure the SIEM server is running.")
        sys.exit(1)

    logs = load_dummy_logs()
    if not logs:
        logger.error("Failed to load dummy logs. Check if dummy_logs.json exists.")
        sys.exit(1)

    session = create_session()
    
    logger.info("Starting to send logs to server...")
    for log in logs:
        try:
            # Add timestamp if not present
            if 'timestamp' not in log:
                log['timestamp'] = datetime.now().isoformat()

            # Ensure all required fields are present
            required_fields = ['source', 'message', 'severity']
            for field in required_fields:
                if field not in log:
                    logger.warning(f"Missing required field '{field}' in log entry")
                    continue

            response = session.post(
                "http://localhost:8000/api/v1/logs",
                json=log,
                timeout=30  # Increased timeout
            )
            response.raise_for_status()
            
            # Verify response content
            response_data = response.json()
            if 'status' in response_data and response_data['status'] == 'success':
                logger.info(f"✓ Processed log: {log['message']}")
                logger.debug(f"Server response: {response_data}")
            else:
                logger.warning(f"Unexpected response format: {response_data}")
            
            time.sleep(2)  # Rate limiting
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Error sending log: {e}")
            logger.info("Retrying in 5 seconds...")
            time.sleep(5)
            continue

if __name__ == "__main__":
    try:
        send_logs()
    except KeyboardInterrupt:
        logger.info("Log sending interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)