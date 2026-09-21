import sqlite3
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def init_database():
    db_path = Path(__file__).parent.parent.parent / "siem.db"
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Create tables if they don't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            analysis TEXT,
            processed_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        conn.commit()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_database()