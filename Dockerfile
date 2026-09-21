FROM python:3.11-slim

LABEL org.opencontainers.image.title="AI-IDS Backend" \
      org.opencontainers.image.description="FastAPI backend for the AI-IDS Security Operations Platform"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssl \
        iptables \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY docker/requirements-backend.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy server source code
COPY server/src/ ./src/

# Copy seed data (read-only reference; runtime data goes to /app/data via volume)
COPY server/data/ ./seed/

# Copy entrypoint
COPY docker/entrypoint-backend.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Persistent directories (override with Docker volumes in production)
VOLUME ["/app/db", "/app/data", "/app/certs", "/app/backups", "/app/reports"]

ENV PYTHONPATH=/app \
    SERVER_PORT=8000 \
    LOG_LEVEL=INFO \
    AI_ENABLED=true \
    DB_PATH=/app/db/siem.db \
    SSL_KEYFILE=/app/certs/key.pem \
    SSL_CERTFILE=/app/certs/cert.pem

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -fsk https://localhost:8000/api/v1/stats || exit 1

ENTRYPOINT ["/entrypoint.sh"]
