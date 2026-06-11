FROM python:3.12-slim

WORKDIR /app

# Dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

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

# Ensure data directory exists
RUN mkdir -p /attense/data

CMD ["sh", "-c", \
  "if [ \"$MODE\" = 'wazuh' ]; then \
  exec uvicorn app.main:app --host 0.0.0.0 --port 8000; \
  else \
  exec python -u signal_mapper_nginx.py; \
  fi"]