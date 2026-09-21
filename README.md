# AI-IDS

AI-powered Security Information and Event Management (SIEM) platform with real-time threat monitoring, autonomous AI analysis, and enterprise-grade security operations features.

## Features

- **Real-time Threat Monitoring** — live dashboard with severity breakdown, threat maps, and timeline visualization
- **AI Autonomous Agent** — continuously analyses unprocessed logs via DeepSeek (OpenRouter), auto-blocks IPs, sends alerts
- **File Upload & Bulk Ingest** — JSON, CSV, log, TXT up to 2 GB; parses millions of rows in seconds
- **Threat Intelligence Feeds** — auto-syncs AlienVault OTX, AbuseIPDB, CISA KEV
- **Vulnerability Scanner** — Nmap + Metasploit integration
- **Compliance Reporting** — NIST, ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR
- **Case Management** — create, track, and resolve security incidents
- **PDF Report Generation** — scheduled and on-demand executive reports
- **Anomaly Detection** — ML-based UEBA for behavioural analysis
- **Network IDS** — real-time intrusion detection with auto-blocking

## Architecture

```
┌──────────────┐     HTTPS      ┌──────────────┐
│   Frontend   │ ────────────── │   Backend    │
│  (Streamlit) │                │  (FastAPI)   │
│  :8501       │                │  :8000       │
└──────────────┘                └──────┬───────┘
                                       │
                          ┌────────────┼────────────┐
                          │            │            │
                     ┌────▼───┐  ┌─────▼────┐ ┌────▼────┐
                     │ SQLite │  │ AI Agent │ │ Threat  │
                     │   DB   │  │(OpenRouter│ │  Feeds  │
                     └────────┘  └──────────┘ └─────────┘
```

## Quick Start (Docker)

```bash
# Clone and configure
git clone https://github.com/YOUR_USERNAME/ai-ids.git
cd ai-ids
cp .env.example .env
nano .env  # add your OPENROUTER_API_KEY and SIEM_API_KEY

# Start
docker compose up -d

# Access
# Frontend → http://localhost:8501
# Backend  → https://localhost:8000
```

## Deploy to Render

1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com) → **New** → **Blueprint**
3. Connect your GitHub repo — Render reads `render.yaml` automatically
4. Set these environment variables in the Render dashboard:
   - `OPENROUTER_API_KEY` — your OpenRouter API key
5. Deploy — both backend and frontend will start automatically

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENROUTER_API_KEY` | Yes | — | OpenRouter API key for AI analysis |
| `SIEM_API_KEY` | Yes | auto-generated | API key for backend authentication |
| `AI_AGENT_INTERVAL` | No | 60 | Seconds between agent analysis cycles |
| `AI_AGENT_BATCH` | No | 200 | Logs per analysis batch |
| `SMTP_HOST` | No | smtp.gmail.com | SMTP server for email alerts |
| `SLACK_WEBHOOK_URL` | No | — | Slack webhook for alerts |
| `ABUSEIPDB_API_KEY` | No | — | AbuseIPDB key for IP reputation |

## Project Structure

```
ai-ids/
├── frontend/           # Streamlit frontend
│   └── src/
│       ├── enhanced_app.py    # Main SPA
│       ├── config.py          # Shared backend URL config
│       ├── _pages/            # Page modules (settings, scans, etc.)
│       ├── components/        # UI components (30+ modules)
│       └── utils/             # API helpers, auth
├── server/             # FastAPI backend
│   └── src/
│       ├── api/               # Routes, server, middleware
│       ├── core/              # Storage, AI agent, threat feeds, etc.
│       └── ai/                # AI model integration
├── docker/             # Docker entrypoints, requirements, config
├── render.yaml         # Render deployment blueprint
├── docker-compose.yml  # Local Docker Compose
├── Dockerfile.backend
├── Dockerfile.frontend
└── .env.example
```

## Local Development (without Docker)

```bash
# Backend
cd server
python -m venv venv && source venv/bin/activate
pip install -r ../docker/requirements-backend.txt
python -m uvicorn src.api.server:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend
python -m venv venv && source venv/bin/activate
pip install -r ../docker/requirements-frontend.txt
SIEM_BACKEND_URL=https://localhost:8000 python -m streamlit run src/enhanced_app.py
```

## License

MIT
