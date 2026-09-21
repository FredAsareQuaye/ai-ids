FROM python:3.11-slim

LABEL org.opencontainers.image.title="AI-IDS Frontend" \
      org.opencontainers.image.description="Streamlit frontend for the AI-IDS Security Operations Platform"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY docker/requirements-frontend.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --default-timeout=300 --retries=5 -r /tmp/requirements.txt

# Copy frontend source code
COPY frontend/src/ ./src/

# Copy frontend data if it exists (auth DB etc.)
RUN mkdir -p /app/data

# Override Streamlit config (no SSL, Docker-compatible)
RUN mkdir -p /root/.streamlit
COPY docker/streamlit-config.toml /root/.streamlit/config.toml

# Copy entrypoint
COPY docker/entrypoint-frontend.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SIEM_BACKEND_URL=https://backend:8000 \
    AI_ENABLED=true \
    OPENROUTER_MODEL=deepseek/deepseek-chat \
    PORT=8501

EXPOSE ${PORT:-8501}

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD curl -f http://localhost:${PORT:-8501}/_stcore/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
