#!/bin/bash
set -e

export PYTHONPATH="/app/src:${PYTHONPATH}"
mkdir -p /app/data

BACKEND_URL="${SIEM_BACKEND_URL:-https://backend:8000}"
echo "[entrypoint] Backend URL: $BACKEND_URL"

PORT="${PORT:-8501}"

echo "[entrypoint] Starting AI-IDS frontend on port $PORT..."
exec python -m streamlit run src/enhanced_app.py \
    --server.port "$PORT" \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection false
