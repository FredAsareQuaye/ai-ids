from fastapi import APIRouter, HTTPException, WebSocket, Depends, status, File, UploadFile
from typing import List, Dict, Optional
from datetime import datetime  # type: ignore
from ..core.storage import Database  # Changed from DatabaseManager
from ..ai.model import AIAnalyzer   # Changed from OllamaModel
from ..api.auth_middleware import require_api_key, require_agent_token
from ..core.whitelist import WhitelistManager
from ..core.playbook_engine import PlaybookEngine
from ..core.case_manager import CaseManager
from ..core.asset_inventory import AssetInventory
from ..core.geoip import GeoIPEnricher
from ..core.anomaly_detector import AnomalyDetector
from ..core.report_scheduler import ReportScheduler
from ..core.ueba import UEBAEngine
from ..core.threat_feed_sync import ThreatFeedSync
from ..core.deduplicator import Deduplicator
from ..core.custom_playbooks import CustomPlaybookStore
from ..core.compliance_reporter import ComplianceReporter
from ..core.ransomware_detector import RansomwareDetector
from ..core.network_ids import NetworkThreatSensor
from ..core.log_processor import LogProcessor
import asyncio
import json
import secrets
import sqlite3
import xml.etree.ElementTree as ET
import uuid
import os

router = APIRouter()
db = Database("siem.db")
ai_model = AIAnalyzer()
processor = LogProcessor(analyzer=ai_model, db=db)
whitelist_mgr = WhitelistManager(db_path=db.db_path)
playbook_engine = PlaybookEngine(db=db)
case_mgr = CaseManager(db_path=db.db_path)
asset_inv = AssetInventory(db_path=db.db_path)
geoip_enricher = GeoIPEnricher(db_path=db.db_path)
anomaly_det = AnomalyDetector(db_path=db.db_path)
report_sched = ReportScheduler(db=db)
ueba_engine = UEBAEngine(db_path=db.db_path)
feed_sync = ThreatFeedSync(db_path=db.db_path)
deduplicator = Deduplicator(db_path=db.db_path)
custom_pb_store = CustomPlaybookStore(db_path=db.db_path)
compliance_rep = ComplianceReporter(db=db)
ransomware_det = RansomwareDetector(db_path=db.db_path)
nids_sensor    = NetworkThreatSensor(db_path=db.db_path)
nids_sensor.start()   # begin tailing EVE log in background

@router.post("/logs")
async def receive_log(log_data: Dict):
    try:
        # Run the full detection pipeline (whitelist, dedup, AI, threat intel,
        # anomaly, UEBA, correlation, playbook, ransomware, deduplicator)
        await processor.process_log(log_data)
        return {"status": "success", "message": "Log received and analyzed"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/logs/upload")
async def upload_log_file(file: UploadFile = File(...)):
    """Upload a JSON log file for batch ingestion.

    Accepts a JSON file containing either:
      - A single log object  {"timestamp": ..., "source": ..., ...}
      - An array of log objects  [{...}, {...}, ...]
    Each entry is run through the AI analysis pipeline and stored.
    """
    raw = await file.read()

    # ── AI-IDS: widened ingest — accept .log and .csv in addition to .json ──
    fname = (file.filename or "").lower()

    if fname.endswith(".csv"):
        entries = []
        try:
            text = raw.decode("utf-8", errors="replace")
            import csv as _csv, io as _io

            lines = _io.StringIO(text)
            header_line = lines.readline()
            if not header_line:
                raise HTTPException(status_code=400, detail="CSV file is empty")

            # Find column indices for the fields we care about
            headers = next(_csv.reader([header_line]))
            hdr_map = {h.strip().lower(): i for i, h in enumerate(headers)}

            ts_idx    = next((hdr_map[k] for k in ("timestamp", "time", "approxlogtime", "raw_log_time") if k in hdr_map), None)
            src_idx   = next((hdr_map[k] for k in ("source", "host", "device", "device_name", "devid") if k in hdr_map), None)
            msg_idx   = next((hdr_map[k] for k in ("message", "log", "msg", "event_name", "rawlogs", "raw_logs") if k in hdr_map), None)
            sev_idx   = next((hdr_map[k] for k in ("severity", "level", "log_severity") if k in hdr_map), None)

            reader = _csv.reader(lines)
            for row in reader:
                if not row or all(c.strip() == "" for c in row):
                    continue
                def _get(idx):
                    return row[idx].strip() if idx is not None and idx < len(row) else ""
                entries.append({
                    "timestamp": _get(ts_idx) or datetime.now().isoformat(),
                    "source":    _get(src_idx) or "uploaded",
                    "message":   _get(msg_idx) or ",".join(c for c in row[:10] if c.strip())[:200],
                    "severity":  _get(sev_idx) or "info",
                })
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse CSV file: {e}")
    elif fname.endswith((".log", ".txt")):
        entries = []
        try:
            text = raw.decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("{") and line.endswith("}"):
                    try:
                        entries.append(json.loads(line))
                        continue
                    except json.JSONDecodeError:
                        pass
                entries.append({"message": line,
                               "source": fname,
                               "timestamp": datetime.now().isoformat(),
                               "severity": "info"})
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse log file: {e}")
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON file")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")
        entries = data if isinstance(data, list) else [data]

    ingested = 0
    skipped = 0
    errors = []

    # Normalize all entries first
    valid = []
    for i, entry in enumerate(entries):
        try:
            if not isinstance(entry, dict):
                skipped += 1
                continue
            entry.setdefault("timestamp", datetime.now().isoformat())
            entry.setdefault("source", entry.get("host", entry.get("device", "uploaded")))
            entry.setdefault("message", entry.get("log", entry.get("msg", json.dumps(entry)[:200])))
            entry.setdefault("severity", entry.get("level", "info"))
            valid.append(entry)
        except Exception as e:
            errors.append({"index": i, "error": str(e)})
            skipped += 1

    # Bulk batch insert — single transaction, skip heavy per-entry AI pipeline
    if valid:
        try:
            ingested = db.store_events_batch(valid)
        except Exception as e:
            errors.append({"index": -1, "error": str(e)})

    return {
        "status": "success",
        "file": file.filename,
        "total_entries": len(entries),
        "ingested": ingested,
        "skipped": skipped,
        "errors": errors[:10],
    }

@router.get("/threats")
async def get_threats(limit: int = 500):
    try:
        threats = db.get_threats(limit=limit)
        return threats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threats/severity/{severity}")
async def get_threats_by_severity(severity: str):
    """Get threats filtered by severity"""
    try:
        threats = db.get_threats_by_severity(severity.lower())
        return threats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/logs", dependencies=[Depends(require_api_key)])
async def clear_all_logs():
    """Dangerous endpoint to clear all security logs — requires X-API-Key"""
    try:
        # Clear all logs from the database
        success = db.clear_all_logs()
        if success:
            return {"status": "success", "message": "All logs have been cleared"}
        else:
            raise HTTPException(status_code=500, detail="Failed to clear logs")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threats/source/{source}")
async def get_threats_by_source(source: str):
    """Get threats filtered by source"""
    try:
        threats = db.get_threats_by_source(source.lower())
        return threats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/threats/{alert_id}")
async def get_threat_details(alert_id: int):
    """Get detailed information for a specific threat"""
    try:
        threat = db.get_threat_by_id(alert_id)
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        return threat
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/logs")
async def get_logs(limit: int = 1000):
    """Get recent log entries (threats) for AI analysis"""
    try:
        # Use the existing threats endpoint but with logs format for compatibility
        threats = db.get_threats()
        
        # Limit the results
        if limit and limit > 0:
            threats = threats[:limit]
        
        # Convert threats to log format if needed
        logs = []
        for threat in threats:
            log_entry = {
                'id': threat.get('id', ''),
                'timestamp': threat.get('timestamp', datetime.now().isoformat()),
                'severity': threat.get('severity', 'info'),
                'type': threat.get('type', 'Unknown'),
                'message': threat.get('message', 'No message'),
                'source': threat.get('source', 'Unknown'),
                'category': threat.get('type', 'Unknown'),  # Alias for type
                'host': threat.get('source', 'Unknown')  # Alias for source
            }
            logs.append(log_entry)
        
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_stats():
    """Get statistics about threats/logs for dashboard and AI analysis — queries DB directly for accuracy."""
    try:
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cur = conn.cursor()

        total = cur.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

        severity_rows = cur.execute(
            "SELECT LOWER(severity), COUNT(*) FROM logs GROUP BY LOWER(severity)"
        ).fetchall()
        sev_map = {row[0]: row[1] for row in severity_rows}

        critical_count = sev_map.get("critical", 0)
        high_count = sev_map.get("high", 0) + sev_map.get("error", 0)
        medium_count = sev_map.get("medium", 0) + sev_map.get("warning", 0) + sev_map.get("warn", 0)
        low_count = sev_map.get("low", 0) + sev_map.get("info", 0) + sev_map.get("information", 0) + sev_map.get("notice", 0)

        conn.close()

        return {
            "total": total,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "severity_breakdown": sev_map,
            "last_updated": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            analysis = ai_model.analyze_log(data)
            await websocket.send_json(analysis)
    except Exception:
        await websocket.close()

@router.post("/gemini/analyze")
async def gemini_analyze(request_data: Dict):
    """
    Process a security alert with AI for enhanced analysis.
    Uses OpenRouter API.
    
    Request body should contain:
    - alert_data: The alert information to analyze
    - api_key: OpenRouter API key
    """
    try:
        # Extract data from request
        alert_data = request_data.get("alert_data")
        api_key = request_data.get("api_key")
        
        if not alert_data:
            raise HTTPException(status_code=400, detail="Missing alert data")
        
        if not api_key:
            raise HTTPException(status_code=400, detail="Missing API key")
        
        # Create the prompt for analysis
        prompt = (
            "Explain this log alert in detail. "
            "Show me the port or service that was affected, how to check it and if there are past vulnerabilities. "
            "Show me how to remediate them.\n\n"
            f"Alert Data: {alert_data}"
        )
        
        # Make request to OpenRouter API
        import requests  # type: ignore
        
        endpoint = "https://openrouter.ai/api/v1/chat/completions"
        
        request_payload = {
            "model": os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat"),
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        
        response = requests.post(
            endpoint,
            json=request_payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/yourusername/aisiem",
                "X-Title": "AI-IDS",
            }
        )
        
        if response.status_code != 200:
            return {
                "success": False, 
                "error": f"API error: {response.status_code}", 
                "details": response.text
            }
            
        # Process the response (OpenRouter uses OpenAI-compatible format)
        data = response.json()
        response_text = data.get('choices', [{}])[0].get('message', {}).get('content', '')
        
        # Store the analysis in the database (optional)
        try:
            # Add timestamp
            timestamp = datetime.now().isoformat()
            
            # Create analysis record
            analysis_record = {
                "alert_id": alert_data.get("id"),
                "timestamp": timestamp,
                "analysis_text": response_text,
                "source": "openrouter"
            }
            
            # Store in the database if you have a table for AI analyses
            # db.store_ai_analysis(analysis_record)
            
            # Update the original alert with a flag indicating it has Gemini analysis
            # db.update_alert_analysis_status(alert_data.get("id"), has_gemini_analysis=True)
        except Exception as db_error:
            # Don't fail the request if storing fails, just log it
            print(f"Warning: Failed to store analysis: {str(db_error)}")
        
        # Return the analysis
        return {
            "success": True,
            "analysis": response_text,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/v1/vulnerability/scan")
@router.post("/vulnerability/scan")  # Keep for backward compatibility
async def save_vulnerability_scan(scan_data: dict):
    """Save vulnerability scan results to database"""
    try:
        # Extract required fields
        target = scan_data.get('target', 'Unknown target')
        scan_name = scan_data.get('scan_name', f"Scan of {target}")
        scan_type = scan_data.get('scan_type', 'Unknown type')
        scan_date = scan_data.get('scan_date', datetime.now().isoformat())
        output_file = scan_data.get('output_file', '')
        
        # Extract vulnerability summary information
        ports = scan_data.get('ports', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])
        summary = scan_data.get('summary', {})
        
        # Calculate vulnerability counts by severity
        total_ports = len(ports)
        total_vulnerabilities = len(vulnerabilities)
        critical_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
        high_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        medium_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
        low_vulns = sum(1 for v in vulnerabilities if v.get('severity') == 'Low')
        
        # Store the entire scan data as JSON
        results_json = json.dumps(scan_data)
        
        # Connect to database
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        
        # Create table if it doesn't exist with expanded fields
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_name TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            total_ports INTEGER,
            total_vulnerabilities INTEGER,
            critical_vulns INTEGER,
            high_vulns INTEGER,
            medium_vulns INTEGER,
            low_vulns INTEGER,
            output_file TEXT,
            results TEXT NOT NULL
        )
        ''')
        
        # Insert scan data with expanded fields
        cursor.execute('''
        INSERT INTO vulnerability_scans (
            target, scan_name, scan_type, scan_date, 
            total_ports, total_vulnerabilities, 
            critical_vulns, high_vulns, medium_vulns, low_vulns,
            output_file, results
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            target, scan_name, scan_type, scan_date,
            total_ports, total_vulnerabilities,
            critical_vulns, high_vulns, medium_vulns, low_vulns,
            output_file, results_json
        ))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "status": "success", 
            "message": "Scan saved successfully", 
            "id": scan_id,
            "summary": {
                "target": target,
                "scan_name": scan_name,
                "scan_date": scan_date,
                "total_ports": total_ports,
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulns": critical_vulns,
                "high_vulns": high_vulns,
                "medium_vulns": medium_vulns,
                "low_vulns": low_vulns
            }
        }
    
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving scan: {str(e)}")

@router.get("/api/v1/vulnerability/scans")
@router.get("/vulnerability/scans")  # Keep for backward compatibility
async def get_vulnerability_scans():
    """Get all vulnerability scans"""
    try:
        # Connect to database
        conn = sqlite3.connect('siem.db')
        conn.row_factory = sqlite3.Row  # To access columns by name
        cursor = conn.cursor()
        
        # Create table if it doesn't exist with expanded fields
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerability_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_name TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            total_ports INTEGER,
            total_vulnerabilities INTEGER,
            critical_vulns INTEGER,
            high_vulns INTEGER,
            medium_vulns INTEGER,
            low_vulns INTEGER,
            output_file TEXT,
            results TEXT NOT NULL
        )
        ''')
        
        # Get all vulnerability scans with new fields
        cursor.execute('''
        SELECT id, target, scan_name, scan_type, scan_date, 
               total_ports, total_vulnerabilities, 
               critical_vulns, high_vulns, medium_vulns, low_vulns,
               results, ai_analyzed, ai_summary, vulnerability_scan 
        FROM vulnerability_scans ORDER BY id DESC
        ''')
        
        rows = cursor.fetchall()
        
        # Convert rows to dictionaries with parsed JSON
        scans = []
        column_names = ["id", "target", "scan_name", "scan_type", "scan_date", 
                      "total_ports", "total_vulnerabilities", 
                      "critical_vulns", "high_vulns", "medium_vulns", "low_vulns",
                      "results", "ai_analyzed", "ai_summary", "vulnerability_scan"]
        
        for row in rows:
            try:
                # Create dictionary from row using column names
                scan = {column_names[i]: row[i] for i in range(len(row))}
                
                # Parse JSON results
                results = json.loads(scan['results'])
                
                # Extract key fields for the overview
                scan['vulnerabilities'] = results.get('vulnerabilities', [])
                scan['ports'] = results.get('ports', [])
                
                # Include AI analysis information
                if 'summary' in results and 'ai_summary' in results['summary']:
                    scan['ai_summary'] = results['summary']['ai_summary']
                
                # Keep full results
                scan['results'] = results
                
                scans.append(scan)
            except json.JSONDecodeError:
                # Handle corrupt JSON
                scan = {column_names[i]: row[i] for i in range(len(row))}
                scan['vulnerabilities'] = []
                scan['ports'] = []
                scan['results'] = {}
                scan['ai_summary'] = ""
                
                scans.append(scan)
        
        conn.close()
        return scans
    
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scans: {str(e)}")

@router.get("/api/v1/vulnerability/scans/{scan_id}")
@router.get("/vulnerability/scans/{scan_id}")  # Keep for backward compatibility
async def get_vulnerability_scan(scan_id: int):
    """Get a specific vulnerability scan by ID"""
    try:
        conn = sqlite3.connect('siem.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get the scan
        cursor.execute('SELECT * FROM vulnerability_scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Convert to dictionary
        scan_data = dict(scan)
        
        # Parse the JSON results
        if 'results' in scan_data:
            scan_data['results'] = json.loads(scan_data['results'])
            # Extract key information
            scan_data['vulnerabilities'] = scan_data['results'].get('vulnerabilities', [])
            scan_data['ports'] = scan_data['results'].get('ports', [])
        
        conn.close()
        return scan_data
        
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid JSON data in scan results")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")

@router.get("/api/v1/vulnerability/scan/{scan_id}")
@router.get("/vulnerability/scan/{scan_id}")  # Keep for backward compatibility
async def get_vulnerability_scan_detailed(scan_id: int):
    """Get a specific vulnerability scan by ID with detailed results"""
    try:
        # Connect to database
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        
        # Get scan data with all fields including new AI fields
        cursor.execute('''
        SELECT id, target, scan_name, scan_type, scan_date, 
               total_ports, total_vulnerabilities, 
               critical_vulns, high_vulns, medium_vulns, low_vulns,
               output_file, results, ai_analyzed, ai_summary, vulnerability_scan
        FROM vulnerability_scans WHERE id = ?
        ''', (scan_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
        
        # Create structured response with new fields
        column_names = ["id", "target", "scan_name", "scan_type", "scan_date", 
                       "total_ports", "total_vulnerabilities", 
                       "critical_vulns", "high_vulns", "medium_vulns", "low_vulns",
                       "output_file", "results", "ai_analyzed", "ai_summary", "vulnerability_scan"]
        scan_summary = {column_names[i]: result[i] for i in range(len(column_names)-1)}
        
        # Parse JSON results for full details
        scan_data = json.loads(result[-1])
        
        # Combine summary and detailed data
        response = {
            "summary": scan_summary,
            "details": scan_data
        }
        
        return response
    
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Error parsing scan results")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")

@router.delete("/api/v1/vulnerability/scans/{scan_id}")
@router.delete("/vulnerability/scans/{scan_id}")  # Keep for backward compatibility
async def delete_vulnerability_scan(scan_id: int):
    """Delete a vulnerability scan from the database"""
    try:
        # Connect to database
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        
        # Check if scan exists
        cursor.execute('SELECT id FROM vulnerability_scans WHERE id = ?', (scan_id,))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
        
        # Delete the scan
        cursor.execute('DELETE FROM vulnerability_scans WHERE id = ?', (scan_id,))
        conn.commit()
        conn.close()
        
        return {'message': f'Scan {scan_id} deleted successfully'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting scan: {str(e)}")

@router.delete("/api/v1/vulnerability/scans/all", dependencies=[Depends(require_api_key)])
@router.delete("/vulnerability/scans/all", dependencies=[Depends(require_api_key)])
async def clear_all_vulnerability_scans():
    """Clear all vulnerability scans — requires X-API-Key"""
    try:
        # Connect to database
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        
        # Get count of scans before deletion
        cursor.execute('SELECT COUNT(*) FROM vulnerability_scans')
        count = cursor.fetchone()[0]
        
        # Delete all scans
        cursor.execute('DELETE FROM vulnerability_scans')
        conn.commit()
        conn.close()
        
        return {'message': f'Successfully cleared {count} vulnerability scans from the database'}
        
        if not (target and xml_data):
            raise HTTPException(status_code=400, detail="Missing required data")
            
        # Parse XML data
        root = ET.fromstring(xml_data)
        
        # Process scan results based on scan type
        if scan_type == 'vulnerability':
            parsed_results = parse_vulnerability_scan(root)
        else:
            parsed_results = parse_standard_scan(root)
        
        # Create scan results object
        scan_id = str(uuid.uuid4())
        
        if scan_type == 'vulnerability':
            scan_results = {
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'scan_date': scan_date,
                'port_range': port_range,
                'vulnerabilities': parsed_results,
                'raw_output': text_output
            }
        else:
            scan_results = {
                'scan_id': scan_id,
                'target': target,
                'scan_type': scan_type,
                'scan_date': scan_date,
                'port_range': port_range,
                'host_info': parsed_results.get('host_info', {}),
                'services': parsed_results.get('services', []),
                'raw_output': text_output
            }
        
        # Store in database
        store_scan_in_database(scan_results)
        
        return scan_results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/vulnerability/network_scan")
async def process_network_scan(request_data: Dict):
    """Process network scan results from nmap XML"""
    try:
        data = request_data
        
        # Extract data from request
        target_range = data.get('target_range')
        scan_date = data.get('scan_date')
        port_range = data.get('port_range')
        xml_data = data.get('xml_data')
        text_output = data.get('text_output')
        
        if not (target_range and xml_data):
            raise HTTPException(status_code=400, detail="Missing required data")
            
        # Parse XML data
        root = ET.fromstring(xml_data)
        
        # Process network scan results
        parsed_results = parse_network_scan(root)
        
        # Create scan results object
        scan_id = str(uuid.uuid4())
        
        scan_results = {
            'scan_id': scan_id,
            'target': target_range,
            'scan_type': 'network',
            'scan_date': scan_date,
            'port_range': port_range,
            'hosts': parsed_results.get('hosts', []),
            'summary': parsed_results.get('summary', {}),
            'raw_output': text_output
        }
        
        # Store in database
        store_scan_in_database(scan_results)
        
        return scan_results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def parse_vulnerability_scan(root):
    """Parse vulnerability scan XML to extract vulnerabilities"""
    vulnerabilities = []
    
    # Process host information
    for host in root.findall('.//host'):
        # Get address information
        addr = host.find('.//address').get('addr')
        
        # Find all ports with open state
        for port_elem in host.findall('.//port'):
            port_id = port_elem.get('portid')
            protocol = port_elem.get('protocol')
            
            # Check if port is open
            state_elem = port_elem.find('state')
            if state_elem is not None and state_elem.get('state') == 'open':
                # Get service information
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    service = service_elem.get('name', 'unknown')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                    
                    # Build service details
                    service_details = f"{service}"
                    if product:
                        service_details += f" {product}"
                    if version:
                        service_details += f" {version}"
                    
                    # Look for script results related to vulnerabilities
                    script_elems = port_elem.findall('script')
                    found_vulns = False
                    
                    for script in script_elems:
                        script_id = script.get('id', '')
                        output = script.get('output', '')
                        
                        # Look for vulnerability scripts
                        if 'vuln' in script_id or 'cve' in script_id:
                            found_vulns = True
                            
                            # Look for tables with vulnerability information
                            tables = script.findall('table')
                            for table in tables:
                                # Look for CVE IDs
                                cve_elem = table.find(".//elem[@key='id']")
                                if cve_elem is not None:
                                    cve_id = cve_elem.text
                                    
                                    # Get description
                                    desc_elem = table.find(".//elem[@key='title']") or table.find(".//elem[@key='description']")
                                    description = desc_elem.text if desc_elem is not None else "No description available"
                                    
                                    # Get CVSS score
                                    cvss_elem = table.find(".//elem[@key='cvss']")
                                    cvss = cvss_elem.text if cvss_elem is not None else "N/A"
                                    
                                    # Determine severity based on CVSS
                                    severity = "medium"  # Default
                                    if cvss != "N/A":
                                        try:
                                            cvss_float = float(cvss)
                                            if cvss_float >= 9.0:
                                                severity = "critical"
                                            elif cvss_float >= 7.0:
                                                severity = "high"
                                            elif cvss_float >= 4.0:
                                                severity = "medium"
                                            else:
                                                severity = "low"
                                        except ValueError:
                                            pass
                                    
                                    # Add vulnerability
                                    vulnerabilities.append({
                                        'port': port_id,
                                        'service': service_details,
                                        'name': description,
                                        'cve': cve_id,
                                        'cvss': cvss,
                                        'severity': severity,
                                        'confirmed': True
                                    })
                    
                    # If no vulnerabilities were found through scripts, add potential issues based on service
                    if not found_vulns:
                        # Check for common services that often have vulnerabilities
                        if service.lower() in ['http', 'https']:
                            vulnerabilities.append({
                                'port': port_id,
                                'service': service_details,
                                'name': "Potential web server vulnerabilities",
                                'cve': "N/A",
                                'severity': "medium",
                                'confirmed': False,
                                'details': "Web servers may contain vulnerabilities. Consider running targeted web application scans."
                            })
                        elif service.lower() in ['ftp']:
                            vulnerabilities.append({
                                'port': port_id,
                                'service': service_details,
                                'name': "FTP service exposed",
                                'cve': "N/A",
                                'severity': "medium",
                                'confirmed': False,
                                'details': "FTP services may allow anonymous access or contain vulnerabilities in the implementation."
                            })
                        elif service.lower() in ['ssh']:
                            vulnerabilities.append({
                                'port': port_id,
                                'service': service_details,
                                'name': "SSH service exposed",
                                'cve': "N/A",
                                'severity': "low",
                                'confirmed': False,
                                'details': "SSH service is exposed. Ensure it's configured with strong authentication and updated regularly."
                            })
                        elif service.lower() in ['telnet']:
                            vulnerabilities.append({
                                'port': port_id,
                                'service': service_details,
                                'name': "Telnet service (cleartext protocol)",
                                'cve': "N/A",
                                'severity': "high",
                                'confirmed': False,
                                'details': "Telnet transmits data in cleartext, including passwords. Consider replacing with SSH."
                            })
    
    return vulnerabilities

def parse_standard_scan(root):
    """Parse standard nmap scan XML to extract host info and services"""
    # Extract host information
    host_info = {"status": "unknown"}
    services = []
    
    # Process host information
    for host in root.findall('.//host'):
        # Get status
        status_elem = host.find('status')
        if status_elem is not None:
            host_info["status"] = status_elem.get('state')
            
            # Get latency if available
            latency = status_elem.get('reason_ttl')
            if latency:
                host_info["latency"] = latency
        
        # Get address information
        addr_elem = host.find('.//address[@addrtype="mac"]')
        if addr_elem is not None:
            host_info["mac"] = addr_elem.get('addr')
            host_info["vendor"] = addr_elem.get('vendor', 'Unknown')
            
        # Get OS information if available
        os_elem = host.find('.//osclass')
        if os_elem is not None:
            os_type = os_elem.get('osfamily', '')
            os_vendor = os_elem.get('vendor', '')
            os_gen = os_elem.get('osgen', '')
            
            os_details = []
            if os_vendor:
                os_details.append(os_vendor)
            if os_type:
                os_details.append(os_type)
            if os_gen:
                os_details.append(os_gen)
                
            if os_details:
                host_info["os"] = " ".join(os_details)
        
        # Find all ports with open state
        for port_elem in host.findall('.//port'):
            port_id = port_elem.get('portid')
            protocol = port_elem.get('protocol')
            
            # Check if port is open
            state_elem = port_elem.find('state')
            if state_elem is not None and state_elem.get('state') == 'open':
                # Get service information
                service_elem = port_elem.find('service')
                if service_elem is not None:
                    service = service_elem.get('name', 'unknown')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                    
                    # Build service details
                    service_details = ""
                    if product:
                        service_details += f"{product}"
                    if version:
                        service_details += f" {version}"
                    
                    service_info = {
                        "port": port_id,
                        "protocol": protocol,
                        "service": service,
                        "details": service_details.strip() if service_details else ""
                    }
                    
                    services.append(service_info)
    
    return {
        "host_info": host_info,
        "services": services
    }

def parse_network_scan(root):
    """Parse network scan XML to extract information about multiple hosts"""
    hosts = []
    summary = {
        "total_hosts": 0,
        "up_hosts": 0,
        "down_hosts": 0,
        "total_ports": 0,
        "open_ports": 0
    }
    
    # Count total hosts and hosts that are up
    host_elems = root.findall('.//host')
    summary["total_hosts"] = len(host_elems)
    
    # Process each host
    for host in host_elems:
        host_data = {}
        
        # Get status
        status_elem = host.find('status')
        if status_elem is not None:
            host_status = status_elem.get('state')
            host_data["status"] = host_status
            
            if host_status == "up":
                summary["up_hosts"] += 1
            else:
                summary["down_hosts"] += 1
        
        # Get address
        addr_elem = host.find('.//address[@addrtype="ipv4"]')
        if addr_elem is not None:
            host_data["ip"] = addr_elem.get('addr')
        
        # Get hostname if available
        hostname_elem = host.find('.//hostname')
        if hostname_elem is not None:
            host_data["hostname"] = hostname_elem.get('name')
        
        # Get MAC address if available
        mac_elem = host.find('.//address[@addrtype="mac"]')
        if mac_elem is not None:
            host_data["mac"] = mac_elem.get('addr')
            host_data["vendor"] = mac_elem.get('vendor', '')
        
        # Process ports
        ports = []
        port_elems = host.findall('.//port')
        
        for port_elem in port_elems:
            port_id = port_elem.get('portid')
            protocol = port_elem.get('protocol')
            
            summary["total_ports"] += 1
            
            # Get state
            state_elem = port_elem.find('state')
            if state_elem is not None:
                port_state = state_elem.get('state')
                
                # Get service info
                service_elem = port_elem.find('service')
                service_name = service_elem.get('name', '') if service_elem is not None else ''
                
                port_info = {
                    "port": port_id,
                    "protocol": protocol,
                    "state": port_state,
                    "service": service_name
                }
                
                ports.append(port_info)
                
                if port_state == "open":
                    summary["open_ports"] += 1
        
        host_data["ports"] = ports
        hosts.append(host_data)
    
    return {
        "hosts": hosts,
        "summary": summary
    }

# ------------------------------------------------------------------ #
#  Agent Registration & Event Ingestion                               #
# ------------------------------------------------------------------ #

@router.post("/agents/register")
async def register_agent(agent_data: Dict):
    """
    Register a new monitoring agent (Windows/Linux/macOS).
    Returns a token the agent must include in subsequent requests.
    """
    required = {"agent_id", "hostname", "platform"}
    missing = required - set(agent_data.keys())
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing fields: {missing}")

    # Check if agent already exists and return its token
    existing = db.get_agent(agent_data["agent_id"])
    if existing:
        db.update_agent_seen(agent_data["agent_id"])
        return {
            "status": "ok",
            "message": "Agent re-registered",
            "agent_id": agent_data["agent_id"],
            "token": existing["token"],
        }

    # Generate a secure token for this agent
    token = secrets.token_urlsafe(32)
    db.register_agent({**agent_data, "token": token})
    return {
        "status": "registered",
        "agent_id": agent_data["agent_id"],
        "token": token,
        "message": "Save this token — it will not be shown again.",
    }


@router.post("/agents/events")
async def receive_agent_events(
    payload: Dict,
    agent_ctx: Dict = Depends(require_agent_token),
):
    """
    Batch event endpoint for remote agents.
    Body: { "events": [ {...}, {...} ] }
    """
    events = payload.get("events", [])
    if not events:
        raise HTTPException(status_code=400, detail="No events provided")

    agent_id = agent_ctx["agent_id"]
    db.update_agent_seen(agent_id)

    stored = 0
    for event in events:
        try:
            event["agent_id"] = agent_id
            if "timestamp" not in event:
                event["timestamp"] = datetime.now().isoformat()
            # Run the full detection pipeline on each agent event
            await processor.process_log(event)
            db.store_event(event)
            stored += 1
        except Exception as e:
            pass  # Don't fail the whole batch for one bad event

    return {"status": "ok", "stored": stored, "received": len(events)}


@router.get("/agents")
async def list_agents():
    """List all registered monitoring agents"""
    try:
        return db.get_all_agents()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/agents/{agent_id}", dependencies=[Depends(require_api_key)])
async def deregister_agent(agent_id: str):
    """Deactivate a registered agent — requires X-API-Key"""
    agent = db.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    with db.get_connection() as conn:
        conn.execute(
            "UPDATE agent_registry SET is_active=0 WHERE agent_id=?", (agent_id,)
        )
        conn.commit()
    return {"status": "ok", "message": f"Agent {agent_id} deactivated"}


# ------------------------------------------------------------------ #
#  Correlation / ATT&CK Endpoints                                     #
# ------------------------------------------------------------------ #

@router.get("/correlations")
async def get_correlations(hours: int = 24):
    """Get MITRE ATT&CK correlations fired in the last N hours"""
    try:
        return db.get_correlations(hours=hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/correlations/{correlation_id}/acknowledge", dependencies=[Depends(require_api_key)])
async def acknowledge_correlation(correlation_id: int):
    """Mark a correlation as acknowledged — requires X-API-Key"""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE correlations SET acknowledged=1 WHERE id=?", (correlation_id,)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Correlation not found")
        conn.commit()
    return {"status": "acknowledged"}


# ------------------------------------------------------------------ #
#  Agent Heartbeat                                                    #
# ------------------------------------------------------------------ #

@router.post("/agents/heartbeat")
async def agent_heartbeat(agent_ctx: Dict = Depends(require_agent_token)):
    """Lightweight heartbeat to track agent liveness"""
    db.update_agent_seen(agent_ctx["agent_id"])
    return {"status": "ok", "ts": datetime.now().isoformat()}


# ------------------------------------------------------------------ #
#  False-Positive Whitelist                                           #
# ------------------------------------------------------------------ #

@router.get("/whitelist")
async def get_whitelist():
    """List all active whitelist entries"""
    return whitelist_mgr.list_entries()


@router.post("/whitelist", dependencies=[Depends(require_api_key)])
async def add_whitelist_entry(entry: Dict):
    """Add a whitelist entry — requires X-API-Key"""
    try:
        wtype = entry.get("type", "")
        value = entry.get("value", "")
        reason = entry.get("reason", "")
        created_by = entry.get("created_by", "admin")
        if not wtype or not value:
            raise HTTPException(status_code=400, detail="type and value are required")
        row_id = whitelist_mgr.add(wtype, value, reason, created_by)
        return {"status": "ok", "id": row_id}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/whitelist/{entry_id}", dependencies=[Depends(require_api_key)])
async def remove_whitelist_entry(entry_id: int):
    """Deactivate a whitelist entry — requires X-API-Key"""
    removed = whitelist_mgr.remove(entry_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Entry not found")
    return {"status": "ok"}


# ------------------------------------------------------------------ #
#  Playbook Engine                                                    #
# ------------------------------------------------------------------ #

@router.get("/playbooks")
async def get_playbooks():
    """List all playbooks"""
    return playbook_engine.get_playbooks()


@router.put("/playbooks/{playbook_id}", dependencies=[Depends(require_api_key)])
async def update_playbook(playbook_id: str, updates: Dict):
    """Enable/disable or modify a playbook — requires X-API-Key"""
    updated = playbook_engine.update_playbook(playbook_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"status": "ok"}


@router.get("/playbooks/executions")
async def get_playbook_executions(limit: int = 100):
    """Return recent playbook execution reports"""
    try:
        return db.get_playbook_executions(limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/playbooks/blocked-ips")
async def get_blocked_ips():
    """List IPs currently blocked by the playbook engine"""
    return {"blocked_ips": playbook_engine.get_blocked_ips()}


# ------------------------------------------------------------------ #
#  Case Management                                                    #
# ------------------------------------------------------------------ #

@router.get("/cases")
async def list_cases(status: Optional[str] = None, severity: Optional[str] = None, limit: int = 200):
    return case_mgr.list_cases(status=status, severity=severity, limit=limit)


@router.post("/cases")
async def create_case(body: Dict):
    return case_mgr.create_case(
        title=body.get("title", "Untitled Case"),
        description=body.get("description", ""),
        severity=body.get("severity", "MEDIUM"),
        assigned_to=body.get("assigned_to", ""),
        created_by=body.get("created_by", "analyst"),
        source=body.get("source", ""),
        tags=body.get("tags", []),
        log_ids=body.get("log_ids", []),
    )


@router.get("/cases/stats")
async def get_case_stats():
    return case_mgr.get_stats()


@router.get("/cases/{case_id}")
async def get_case(case_id: int):
    c = case_mgr.get_case(case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return c


@router.put("/cases/{case_id}", dependencies=[Depends(require_api_key)])
async def update_case(case_id: int, updates: Dict):
    if not case_mgr.update_case(case_id, updates):
        raise HTTPException(status_code=404, detail="Case not found or no valid fields")
    return {"status": "ok"}


@router.post("/cases/{case_id}/notes")
async def add_case_note(case_id: int, body: Dict):
    author = body.get("author", "analyst")
    note = body.get("note", "")
    if not note:
        raise HTTPException(status_code=400, detail="note is required")
    return case_mgr.add_note(case_id, author, note)


@router.post("/cases/{case_id}/logs")
async def link_case_logs(case_id: int, body: Dict):
    log_ids = body.get("log_ids", [])
    added = case_mgr.link_logs(case_id, log_ids)
    return {"status": "ok", "added": added}


# ------------------------------------------------------------------ #
#  Asset Inventory                                                    #
# ------------------------------------------------------------------ #

@router.get("/assets")
async def list_assets():
    return asset_inv.list_assets()


@router.post("/assets", dependencies=[Depends(require_api_key)])
async def add_asset(body: Dict):
    return asset_inv.add_asset(body)


@router.get("/assets/risk-scores")
async def get_risk_scores():
    return asset_inv.get_risk_scores()


@router.get("/assets/{asset_id}")
async def get_asset(asset_id: int):
    a = asset_inv.get_asset(asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    return a


@router.put("/assets/{asset_id}", dependencies=[Depends(require_api_key)])
async def update_asset(asset_id: int, updates: Dict):
    if not asset_inv.update_asset(asset_id, updates):
        raise HTTPException(status_code=404, detail="Asset not found or no valid fields")
    return {"status": "ok"}


@router.delete("/assets/{asset_id}", dependencies=[Depends(require_api_key)])
async def delete_asset(asset_id: int):
    asset_inv.delete_asset(asset_id)
    return {"status": "ok"}


# ------------------------------------------------------------------ #
#  GeoIP                                                              #
# ------------------------------------------------------------------ #

@router.get("/geoip/{ip}")
async def geoip_lookup(ip: str):
    result = geoip_enricher.lookup(ip)
    if not result:
        raise HTTPException(status_code=404, detail="No GeoIP data for that IP")
    return result


@router.get("/geoip")
async def geoip_all_cached():
    """Return all cached GeoIP entries for map rendering."""
    return geoip_enricher.get_all_cached()


# ------------------------------------------------------------------ #
#  Anomaly Detection                                                  #
# ------------------------------------------------------------------ #

@router.get("/anomalies")
async def get_anomaly_events(limit: int = 100):
    return anomaly_det.get_anomaly_events(limit=limit)


@router.get("/anomalies/baselines")
async def get_anomaly_baselines():
    return anomaly_det.get_baselines()


# ------------------------------------------------------------------ #
#  On-Demand Report                                                   #
# ------------------------------------------------------------------ #

@router.post("/reports/generate", dependencies=[Depends(require_api_key)])
async def generate_report(body: Dict = {}):
    """Generate and return a PDF report (or email it). Requires X-API-Key."""
    period_hours = body.get("period_hours", 24)
    try:
        pdf_bytes = report_sched.generate_pdf(period_hours=period_hours)
        if not pdf_bytes:
            raise HTTPException(status_code=500, detail="Failed to generate PDF (fpdf2 installed?)")
        from fastapi.responses import Response
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=siem_report_{datetime.now().strftime('%Y%m%d')}.pdf"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ------------------------------------------------------------------ #
#  UEBA                                                               #
# ------------------------------------------------------------------ #

@router.get("/ueba/users")
async def ueba_list_users():
    return ueba_engine.list_users()


@router.get("/ueba/risk-scores")
async def ueba_risk_scores():
    return ueba_engine.get_user_risk_scores()


@router.get("/ueba/anomalies")
async def ueba_anomalies(limit: int = 100):
    return ueba_engine.get_anomaly_events(limit=limit)


@router.get("/ueba/users/{username}")
async def ueba_user_profile(username: str):
    return ueba_engine.get_user_profile(username)


# ------------------------------------------------------------------ #
#  Threat Feed Sync                                                   #
# ------------------------------------------------------------------ #

@router.get("/feeds/status")
async def get_feed_status():
    return feed_sync.get_feed_status()


@router.get("/feeds/ioc-count")
async def get_ioc_count():
    return {"ioc_count": feed_sync.get_ioc_count()}


@router.get("/feeds/matches")
async def get_ioc_matches(limit: int = 100):
    return feed_sync.get_recent_matches(limit=limit)


@router.get("/feeds/search")
async def search_iocs(q: str = "", limit: int = 100):
    return feed_sync.search_iocs(q, limit=limit)


@router.post("/feeds/sync", dependencies=[Depends(require_api_key)])
async def trigger_feed_sync():
    """Manually trigger a feed sync — requires X-API-Key."""
    await asyncio.get_event_loop().run_in_executor(None, feed_sync.sync_all)
    return {"status": "ok", "feeds": feed_sync.get_feed_status()}


# ------------------------------------------------------------------ #
#  Deduplication                                                      #
# ------------------------------------------------------------------ #

@router.get("/dedup/groups")
async def get_dedup_groups(limit: int = 200):
    return deduplicator.get_groups(limit=limit)


@router.get("/dedup/stats")
async def get_dedup_stats():
    return deduplicator.get_stats()


# ------------------------------------------------------------------ #
#  Custom Playbooks (Playbook Builder)                                #
# ------------------------------------------------------------------ #

@router.get("/custom-playbooks")
async def list_custom_playbooks():
    return custom_pb_store.list_all()


@router.post("/custom-playbooks", dependencies=[Depends(require_api_key)])
async def create_custom_playbook(body: Dict):
    pb_id = custom_pb_store.create(body)
    return {"id": pb_id, "status": "created"}


@router.get("/custom-playbooks/executions")
async def get_custom_pb_executions(limit: int = 100):
    return custom_pb_store.get_executions(limit=limit)


@router.get("/custom-playbooks/{pb_id}")
async def get_custom_playbook(pb_id: int):
    pb = custom_pb_store.get(pb_id)
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.put("/custom-playbooks/{pb_id}", dependencies=[Depends(require_api_key)])
async def update_custom_playbook(pb_id: int, updates: Dict):
    if not custom_pb_store.update(pb_id, updates):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"status": "ok"}


@router.delete("/custom-playbooks/{pb_id}", dependencies=[Depends(require_api_key)])
async def delete_custom_playbook(pb_id: int):
    if not custom_pb_store.delete(pb_id):
        raise HTTPException(status_code=404, detail="Playbook not found")
    return {"status": "deleted"}


# ------------------------------------------------------------------ #
#  Compliance Reports                                                 #
# ------------------------------------------------------------------ #

@router.get("/compliance/analyse")
async def compliance_analyse(framework: str = "PCI-DSS", days: int = 30):
    """Analyse events against a compliance framework. Returns JSON report."""
    return compliance_rep.analyse(framework, days)


@router.get("/compliance/frameworks")
async def list_frameworks():
    return {"frameworks": ["PCI-DSS", "ISO 27001", "SOC 2"]}


@router.get("/compliance/pdf")
async def compliance_pdf(framework: str = "PCI-DSS", days: int = 30):
    """Generate and download a compliance PDF report."""
    try:
        pdf_bytes = compliance_rep.generate_pdf(framework, days)
        if not pdf_bytes:
            raise HTTPException(status_code=500, detail="fpdf2 not installed")
        from fastapi.responses import Response
        fname = f"compliance_{framework.replace(' ','_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={fname}"},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def store_scan_in_database(scan_results):
    """Store scan results in the database"""
    try:
        conn = sqlite3.connect('siem.db')
        cursor = conn.cursor()
        
        # Check if table exists and has the correct structure
        cursor.execute("PRAGMA table_info(vulnerability_scans)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        # If table doesn't exist or doesn't have the right structure, create it
        if not columns or 'results' not in column_names:
            # Drop table if it exists but with wrong structure
            if columns:
                cursor.execute('DROP TABLE vulnerability_scans')
                
            # Create table with correct structure
            cursor.execute('''
            CREATE TABLE vulnerability_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                port_range TEXT,
                results TEXT NOT NULL,
                raw_output TEXT
            )
            ''')
        
        # Insert data
        cursor.execute('''
        INSERT INTO vulnerability_scans (scan_id, target, scan_type, scan_date, port_range, results, raw_output)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_results['scan_id'],
            scan_results['target'],
            scan_results['scan_type'],
            scan_results['scan_date'],
            scan_results.get('port_range'),
            json.dumps(scan_results),
            scan_results.get('raw_output')
        ))
        
        conn.commit()
        conn.close()
        
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================================
# Ransomware Live Tracking endpoints
# ==========================================================================

@router.post("/ransomware/scan")
async def ransomware_scan(hours: int = 24):
    """Trigger an on-demand ransomware scan of recent logs."""
    try:
        hits = await asyncio.get_event_loop().run_in_executor(
            None, lambda: ransomware_det.scan_recent_logs(hours)
        )
        return {"status": "ok", "new_detections": len(hits)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ransomware/events")
async def ransomware_events(hours: int = 24, limit: int = 500):
    """Return ransomware detection events."""
    try:
        events = await asyncio.get_event_loop().run_in_executor(
            None, lambda: ransomware_det.get_events(hours, limit)
        )
        return events
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ransomware/stats")
async def ransomware_stats(hours: int = 24):
    """Return aggregated ransomware statistics."""
    try:
        stats = await asyncio.get_event_loop().run_in_executor(
            None, lambda: ransomware_det.get_stats(hours)
        )
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ransomware/indicators")
async def ransomware_indicators():
    """Return top recurring ransomware indicators."""
    try:
        iocs = await asyncio.get_event_loop().run_in_executor(
            None, ransomware_det.get_indicators_summary
        )
        return iocs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/ransomware/events/{event_id}/acknowledge")
async def ransomware_acknowledge(event_id: int):
    """Acknowledge a ransomware detection event."""
    try:
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: ransomware_det.acknowledge(event_id)
        )
        return {"status": "acknowledged"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================================
# Network Threat Sensor (NIDS) endpoints
# ==========================================================================

@router.get("/nids/status")
async def nids_status():
    """Return sensor health / EVE file status."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, nids_sensor.get_sensor_status
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nids/stats")
async def nids_stats(hours: int = 24):
    """Aggregated NIDS statistics."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.get_stats(hours)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nids/alerts")
async def nids_alerts(hours: int = 24, limit: int = 500, severity: Optional[str] = None):
    """Return NIDS alert events."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.get_alerts(hours, limit, severity)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nids/events")
async def nids_events(hours: int = 24, limit: int = 1000, event_type: Optional[str] = None):
    """Return all NIDS events (alerts, DNS, HTTP, TLS, flow…)."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.get_events(hours, limit, event_type)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nids/dns")
async def nids_dns(hours: int = 24, limit: int = 200):
    """Top DNS queries observed by the sensor."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.get_dns_queries(hours, limit)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nids/http")
async def nids_http(hours: int = 24, limit: int = 200):
    """HTTP transactions observed by the sensor."""
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.get_http_requests(hours, limit)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nids/ingest")
async def nids_ingest(payload: Dict):
    """
    Push raw EVE JSON lines into the sensor (for remote sensor forwarding).
    Body: { "lines": ["<json line>", ...] }
    """
    try:
        lines = payload.get("lines", [])
        if not isinstance(lines, list):
            raise HTTPException(status_code=400, detail="'lines' must be a list of strings")
        count = await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.ingest_raw(lines)
        )
        return {"status": "ok", "ingested": count}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/nids/alerts/{event_id}/acknowledge")
async def nids_acknowledge(event_id: int):
    """Acknowledge a NIDS alert."""
    try:
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: nids_sensor.acknowledge(event_id)
        )
        return {"status": "acknowledged"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/nids/poll")
async def nids_poll():
    """Manually trigger a single EVE file poll (for testing)."""
    try:
        count = await asyncio.get_event_loop().run_in_executor(
            None, nids_sensor.ingest_file
        )
        return {"status": "ok", "new_events": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))