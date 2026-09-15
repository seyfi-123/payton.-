FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY 3_requirements.txt /app/3_requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /app/3_requirements.txt

COPY 2credit_engine.py /app/credit_engine.py

RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /app/certs /app/logs && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/system/health || exit 1

CMD ["uvicorn", "credit_engine:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info"]