#!/bin/bash
set -e

CERT_DIR="/app/certs"
mkdir -p "$CERT_DIR" /app/data /app/db /app/backups /app/reports

# Ensure siem.db in persistent /app/db directory
touch /app/db/siem.db
ln -sf /app/db/siem.db /app/siem.db

# Generate self-signed SSL cert if not already present (for local Docker)
if [ ! -f "$CERT_DIR/cert.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    echo "[entrypoint] Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -days 3650 -nodes \
        -subj "/CN=siem-backend/O=AI-IDS/C=US" \
        -addext "subjectAltName=DNS:backend,DNS:localhost,IP:127.0.0.1"
    echo "[entrypoint] SSL certificate generated."
fi

# Copy seed data files if DB data dir is empty
if [ ! -f "/app/data/dummy_logs.json" ]; then
    cp -n /app/seed/dummy_logs.json /app/data/ 2>/dev/null || true
fi
if [ ! -f "/app/data/playbooks.json" ]; then
    cp -n /app/seed/playbooks.json  /app/data/ 2>/dev/null || true
fi

# Use PORT env var (Render) or SERVER_PORT (local Docker)
LISTEN_PORT="${PORT:-${SERVER_PORT:-8000}}"

# On Render, no SSL needed (Render terminates TLS at edge)
if [ "$RENDER" = "true" ] || [ -n "$RENDER_SERVICE_ID" ]; then
    echo "[entrypoint] Render detected — starting without SSL on port $LISTEN_PORT"
    exec python -m uvicorn src.api.server:app \
        --host 0.0.0.0 \
        --port "$LISTEN_PORT" \
        --log-level info
else
    echo "[entrypoint] Starting AI-IDS backend (HTTPS) on port $LISTEN_PORT..."
    exec python -m uvicorn src.api.server:app \
        --host 0.0.0.0 \
        --port "$LISTEN_PORT" \
        --ssl-keyfile "$CERT_DIR/key.pem" \
        --ssl-certfile "$CERT_DIR/cert.pem" \
        --log-level info
fi
