# Build context is the repo root. This Dockerfile copies the control API, the
# embedded Blue Team package, and the shared attense_core package.

FROM python:3.12-slim AS builder

WORKDIR /app
COPY apps/control-api/requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY apps/control-api/api /app/api
COPY apps/control-api/core /app/core
COPY apps/control-api/dependencies /app/dependencies
COPY apps/control-api/pipeline /app/pipeline
COPY apps/control-api/controller.py /app/controller.py
COPY apps/control-api/main.py /app/main.py
# Embedded Blue Team runs in this same process; standalone room containers use
# apps/blue-team-api/Dockerfile.
COPY apps/blue-team-api/blueteam /app/blueteam
# Canonical shared domain package.
COPY packages/attense-core/attense_core /app/attense_core

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV ATTENSE_DATA_PATH=/attense/data/mapped_events.jsonl
ENV ATTENSE_TEMP_PATH=/attense/temp

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8010 8020

# /attense/data is mounted read-only. /attense/temp is writable scratch space;
# /attense/actions stores analyst action JSONL logs.
RUN mkdir -p /attense/data /attense/temp /attense/actions \
    && chmod 777 /attense/temp /attense/actions
RUN mkdir -p /attense/temp/users /attense/temp/sessions /attense/temp/rooms \
    && chmod -R 777 /attense/temp

# Drop root for the running process. Group root keeps Docker socket access on
# Docker Desktop where the mounted socket is root:root mode 660.
RUN groupadd -g 1000 appgroup \
    && useradd -u 1000 -g appgroup -G root -M -s /usr/sbin/nologin appuser
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8020"]
