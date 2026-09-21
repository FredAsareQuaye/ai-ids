from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .routes import router
import uvicorn
import os
from dotenv import load_dotenv
import logging
import asyncio
from ..core.storage import Database
from ..ai.model import AIAnalyzer
import socketio
import ssl
import random
from datetime import datetime  # type: ignore
from typing import Dict, Any
from ..core.log_processor import LogProcessor
from pathlib import Path
import json

# Global AI agent instance (set during startup)
_ai_agent = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize components
app = FastAPI(title="AI-IDS System", version="1.0.0")
db = Database("siem.db")
ai_analyzer = AIAnalyzer()
processor = LogProcessor(ai_analyzer, db)
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*')
socket_app = socketio.ASGIApp(sio, app)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes with API prefix
app.include_router(router, prefix="/api/v1")

# Also include routes without prefix for backward compatibility
app.include_router(router)

async def load_dummy_logs():
    """Load and process dummy logs during startup"""
    # DATA_DIR env var lets Docker override; otherwise fall back to repo layout
    data_dir = os.getenv("DATA_DIR", "")
    if data_dir:
        dummy_logs_path = Path(data_dir) / "dummy_logs.json"
    else:
        root_dir = Path(__file__).resolve().parent.parent.parent.parent
        dummy_logs_path = root_dir / "server" / "data" / "dummy_logs.json"
    
    try:
        logger.info(f"Loading dummy logs from {dummy_logs_path}")
        if not dummy_logs_path.exists():
            logger.error(f"dummy_logs.json not found at: {dummy_logs_path}")
            return
            
        with open(dummy_logs_path) as f:
            logs = json.load(f)
        
        logger.info(f"Found {len(logs)} logs to process")
        
        # Get current logs in DB to avoid duplicates
        existing_logs = db.get_threats()
        existing_messages = {log['message'] for log in existing_logs}
        
        new_logs_count = 0
        for log in logs:
            try:
                # Skip if log already exists (simple check by message)
                if log['message'] in existing_messages:
                    continue
                    
                # Store log in database
                db.store_event(log)
                new_logs_count += 1
                logger.info(f"Stored new log: {log['message'][:50]}...")
                
                # Emit WebSocket event for real-time updates
                await sio.emit('new_log', {
                    'timestamp': log.get('timestamp'),
                    'source': log.get('source'),
                    'message': log.get('message'),
                    'severity': log.get('severity'),
                    'details': log.get('details', {}),
                })
                
            except Exception as e:
                logger.error(f"Failed to process log: {str(e)}")
                continue
                
        logger.info(f"Successfully loaded {new_logs_count} new dummy logs")
    except Exception as e:
        logger.error(f"Failed to load dummy logs: {str(e)}")
        logger.error(f"Error details: {str(e)}")

# File watcher for dummy_logs.json
last_dummy_logs_mtime = 0

async def watch_dummy_logs():
    """Watch dummy_logs.json for changes and process new entries"""
    global last_dummy_logs_mtime

    data_dir = os.getenv("DATA_DIR", "")
    if data_dir:
        dummy_logs_path = Path(data_dir) / "dummy_logs.json"
    else:
        root_dir = Path(__file__).resolve().parent.parent.parent.parent
        dummy_logs_path = root_dir / "server" / "data" / "dummy_logs.json"
    
    while True:
        try:
            if dummy_logs_path.exists():
                current_mtime = dummy_logs_path.stat().st_mtime
                
                if current_mtime > last_dummy_logs_mtime:
                    logger.info("🔍 dummy_logs.json changed, processing new entries...")
                    await load_dummy_logs()
                    last_dummy_logs_mtime = current_mtime
                    
            await asyncio.sleep(2)  # Check every 2 seconds
            
        except Exception as e:
            logger.error(f"Error watching dummy_logs.json: {e}")
            await asyncio.sleep(5)

AGENT_OFFLINE_THRESHOLD_SECONDS = 300  # 5 minutes


async def monitor_agent_heartbeats():
    """Background task: alert when an agent hasn't checked in for 5 minutes."""
    from ..core.alert_notifier import AlertNotifier
    notifier = AlertNotifier()
    alerted: set = set()

    while True:
        try:
            agents = db.get_all_agents()
            now = datetime.now()
            for agent in agents:
                if not agent.get("is_active"):
                    continue
                last_seen_str = agent.get("last_seen")
                if not last_seen_str:
                    continue
                try:
                    last_seen = datetime.fromisoformat(str(last_seen_str))
                except Exception:
                    continue
                delta = (now - last_seen).total_seconds()
                aid = agent["agent_id"]
                if delta > AGENT_OFFLINE_THRESHOLD_SECONDS:
                    if aid not in alerted:
                        alerted.add(aid)
                        logger.warning(
                            f"AGENT OFFLINE: {aid} ({agent.get('hostname')}) "
                            f"last seen {int(delta)}s ago"
                        )
                        db.store_event({
                            "timestamp": now.isoformat(),
                            "source": "siem_system",
                            "message": (
                                f"Agent {aid} ({agent.get('hostname', '?')}) "
                                f"has not checked in for {int(delta // 60)} minutes."
                            ),
                            "severity": "HIGH",
                            "event_type": "agent_offline",
                            "details": {"agent_id": aid, "last_seen": last_seen_str},
                            "analysis": {},
                        })
                else:
                    alerted.discard(aid)
        except Exception as e:
            logger.error(f"Heartbeat monitor error: {e}")
        await asyncio.sleep(60)


@app.on_event("startup")
async def startup_event():
    logger.info("Initializing SIEM server...")
    try:
        # Ensure database exists and is initialized
        db._init_db()
        logger.info(f"Database initialized at: {db.db_path}")

        # NOTE: dummy log loading disabled — real data is managed via upload/agent
        # await load_dummy_logs()

        # Start background tasks
        asyncio.create_task(watch_dummy_logs())
        asyncio.create_task(monitor_agent_heartbeats())

        from ..core.report_scheduler import ReportScheduler
        _report_sched = ReportScheduler(db=db)
        asyncio.create_task(_report_sched.run())

        from ..core.threat_feed_sync import ThreatFeedSync
        _feed_sync = ThreatFeedSync(db_path=db.db_path)
        asyncio.create_task(_feed_sync.run())

        from ..core.syslog_receiver import start_syslog_receiver
        asyncio.create_task(start_syslog_receiver(processor))

        from ..core.ai_autonomous_agent import AutonomousAIAgent
        from ..core.alert_notifier import AlertNotifier
        from ..core.playbook_engine import PlaybookEngine
        _notifier = AlertNotifier()
        _playbook = PlaybookEngine(db=db, notifier=_notifier)
        global _ai_agent
        _ai_agent = AutonomousAIAgent(db=db, notifier=_notifier, playbook_engine=_playbook)
        asyncio.create_task(_ai_agent.run())

        logger.info("Started file watcher, heartbeat monitor, report scheduler, "
                    "threat feed sync, syslog receiver, and AI autonomous agent")

        # Verify logs were stored
        threats = await get_threats()
        logger.info(f"Current number of logs in database: {len(threats)}")

    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise

@app.post("/api/v1/logs")
async def receive_log(log_data: Dict[str, Any]):
    try:
        # Process and store the log
        analysis = await processor.process_log(log_data)
        
        # Emit WebSocket event for real-time updates
        await sio.emit('new_log', {
            'timestamp': log_data.get('timestamp'),
            'source': log_data.get('source'),
            'message': log_data.get('message'),
            'severity': log_data.get('severity'),
            'details': log_data.get('details', {}),
            'analysis': analysis
        })
        
        logger.info(f"📡 Emitted new_log event: {log_data.get('message', 'Unknown')[:50]}...")
        
        return {"status": "success", "analysis": analysis}
    except Exception as e:
        logger.error(f"Error processing log: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/threats")
async def get_threats():
    try:
        threats = db.get_threats()
        return threats
    except Exception as e:
        logger.error(f"Error fetching threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/stats")
async def get_stats():
    try:
        return db.get_threat_stats()
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ai-vulnerability/scans")
async def get_ai_vulnerability_scans():
    """Get all AI vulnerability scans"""
    try:
        scans = db.get_ai_vulnerability_scans()
        return scans
    except Exception as e:
        logger.error(f"Error fetching AI vulnerability scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/ai-vulnerability/scans")
async def save_ai_vulnerability_scan(scan_data: dict):
    """Save AI vulnerability scan results"""
    try:
        scan_id = db.store_ai_vulnerability_scan(scan_data)
        return {"id": scan_id, "status": "success"}
    except Exception as e:
        logger.error(f"Error storing AI vulnerability scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/vulnerability/scans")
async def get_vulnerability_scans():
    """Get all vulnerability scans"""
    try:
        scans = db.get_vulnerability_scans()
        return scans
    except Exception as e:
        logger.error(f"Error fetching vulnerability scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/vulnerability/scans")
async def save_vulnerability_scan(scan_data: dict):
    """Save vulnerability scan results"""
    try:
        scan_id = db.store_vulnerability_scan(scan_data)
        return {"id": scan_id, "status": "success"}
    except Exception as e:
        logger.error(f"Error storing vulnerability scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ai-agent/status")
async def get_ai_agent_status():
    """Return current AI autonomous agent stats."""
    if _ai_agent is None:
        return {"running": False, "stats": {}}
    return {"running": True, "stats": _ai_agent.get_stats()}

@app.post("/api/v1/ai-agent/trigger")
async def trigger_ai_agent_cycle():
    """Manually trigger an AI agent analysis cycle."""
    if _ai_agent is None:
        raise HTTPException(status_code=503, detail="AI agent not running")
    try:
        asyncio.create_task(_ai_agent._cycle())
        return {"status": "triggered", "message": "AI agent cycle started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ai-agent/verdicts")
async def get_ai_verdicts(limit: int = 50):
    """Fetch recent logs that have been AI-analysed."""
    try:
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT id, timestamp, source, message, severity, ai_analysis
            FROM logs
            WHERE ai_analysis IS NOT NULL AND ai_analysis != '' AND ai_analysis != '{}'
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        import json
        for row in rows:
            try:
                row["ai_analysis"] = json.loads(row["ai_analysis"])
            except Exception:
                pass
        return rows
    except Exception as e:
        logger.error(f"Error fetching AI verdicts: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/ai-agent/report")
async def get_ai_agent_report():
    """
    Return the AI-agent analysis summary as a PDF download.
    Regenerates the report on demand so it is always fresh.
    """
    from fastapi.responses import Response
    from ..core.report_scheduler import generate_ai_agent_report

    try:
        pdf_bytes = await asyncio.get_event_loop().run_in_executor(
            None, generate_ai_agent_report, db.db_path
        )
        if not pdf_bytes:
            raise HTTPException(status_code=500, detail="PDF generation failed (fpdf2 installed?)")
        from email.utils import formatdate
        filename = f"ai_agent_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Last-Modified": formatdate(usegmt=True),
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating AI agent report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# WebSocket connection handling
@sio.event
async def connect(sid, environ):
    # Start sending mock log data
    asyncio.create_task(send_mock_logs(sid))

async def send_mock_logs(sid):
    threat_levels = ["LOW", "MEDIUM", "HIGH"]
    sources = ["firewall", "ids", "auth", "system"]
    
    while True:
        mock_log = {
            "timestamp": datetime.now().timestamp() * 1000,
            "source": random.choice(sources),
            "message": f"Test event from {random.choice(sources)}",
            "threat_level": random.choice(threat_levels)
        }
        await sio.emit('log', mock_log, room=sid)
        await asyncio.sleep(2)  # Send a new log every 2 seconds

def start_server():
    try:
        port = int(os.getenv("SERVER_PORT", "8000"))
        workers = int(os.getenv("WORKERS", "4"))
        timeout = int(os.getenv("TIMEOUT", "300"))
        
        config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=port,
            workers=workers,
            timeout_keep_alive=timeout,
            log_level="info",
            ssl_keyfile=os.getenv("SSL_KEYFILE"),
            ssl_certfile=os.getenv("SSL_CERTFILE")
        )
        
        server = uvicorn.Server(config)
        server.run()
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        raise

if __name__ == "__main__":
    try:
        uvicorn.run(
            "src.api.server:app",
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=os.getenv("SSL_KEYFILE", "certs/key.pem"),
            ssl_certfile=os.getenv("SSL_CERTFILE", "certs/cert.pem"),
            reload=True
        )
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        raise