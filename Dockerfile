FROM python:3.12-slim AS builder

LABEL maintainer="Abir Maheshwari <abir@aquilldriver.com>"
LABEL description="Abir-Guard: PQC Agent Memory Vault"

ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml ./
COPY abir_guard/ ./abir_guard/

RUN pip install --no-cache-dir cryptography .

RUN useradd -m -u 1000 appuser
RUN mkdir -p /data && chown appuser:appuser /data

USER appuser

EXPOSE 9090

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9090/health')" || exit 1

ENTRYPOINT ["python", "-c", "\
from abir_guard.mcp_http import McpHttpServer;\
import os;\
api_key = os.environ.get('ABIR_GUARD_API_KEY');\
server = McpHttpServer(port=9090, api_key=api_key);\
server.start(blocking=True)\
"]
