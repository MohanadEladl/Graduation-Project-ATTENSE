# Builder stage: deps copied and installed before any source code, so this
# layer is cache-hit on every rebuild that doesn't touch requirements.txt.
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Final stage: only the built venv is copied in — pip's own footprint and any
# build-time cache never reach the shipped image.
FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Expect ATTENSE_app to be mounted at runtime (no copy here)

# ── Copy API package ────────────────────────
COPY app /app/app

# ── Nginx integration layer ─────────────────
COPY nginx_adapter.py /app/nginx_adapter.py
COPY signal_mapper_nginx.py /app/signal_mapper_nginx.py

# ── Runtime ─────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/attense_app
ENV MODE=wazuh
ENV OUTPUT_MODE=file
ENV OUTPUT_PATH=/attense/data/mapped_events.jsonl

EXPOSE 8000

# Ensure data directory exists. This service writes mapped_events.jsonl into
# it at runtime, so it's chmod'd open (lab-only convention, matches red-team's
# logs dir) rather than relying on UID match with whatever wrote into the
# pre-existing named volume.
RUN mkdir -p /attense/data && chmod 777 /attense/data

# Security boundary: drop root for the running process.
RUN groupadd -g 1000 appgroup && useradd -u 1000 -g appgroup -M -s /usr/sbin/nologin appuser
USER appuser

CMD ["sh", "-c", \
  "if [ \"$MODE\" = 'wazuh' ]; then \
  exec uvicorn app.main:app --host 0.0.0.0 --port 8000; \
  else \
  exec python -u signal_mapper_nginx.py; \
  fi"]