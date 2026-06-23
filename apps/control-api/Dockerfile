# Build context is the repo root (not this directory) — this Dockerfile also
# needs to COPY the top-level apps/blue-team-api/ package and packages/attense-core/
# (the canonical domain the ATTENSE_app/* compatibility shims import), which live
# outside apps/control-api/. See docker-compose.yml's `attense-app` service.

# Builder stage: deps copied and installed before any source code, so this
# layer is cache-hit on every rebuild that doesn't touch requirements.txt.
FROM python:3.12-slim AS builder

WORKDIR /app
COPY apps/control-api/requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Final stage: only the built venv is copied in — pip's own footprint and any
# build-time cache never reach the shipped image.
FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY apps/control-api/ATTENSE_app /app/ATTENSE_app
COPY apps/control-api/api /app/api
COPY apps/control-api/core /app/core
COPY apps/control-api/dependencies /app/dependencies
COPY apps/control-api/pipeline /app/pipeline
COPY apps/control-api/controller.py /app/controller.py
COPY apps/control-api/main.py /app/main.py
# Embedded BlueTeam — runs in this same process (controller.py spins it up on
# its own uvicorn thread, port 8010). Built standalone too, for per-room
# containers; see apps/blue-team-api/Dockerfile. The importable package is
# nested one level deeper than the service directory (blue-team-api is
# hyphenated, not a valid Python identifier for `from blueteam.main import app`).
COPY apps/blue-team-api/blueteam /app/blueteam
# Canonical domain (models/evaluation/repositories/scenarios) the ATTENSE_app/*
# compatibility shims import as attense_core.* — see packages/attense-core and
# MIGRATION.md.
COPY packages/attense-core/attense_core /app/attense_core

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV ATTENSE_DATA_PATH=/attense/data/mapped_events.jsonl
ENV ATTENSE_TEMP_PATH=/attense/temp

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8010 8020

# /attense/data is mounted read-only. /attense/temp is read-write (scratch
# space for the controller's docker-orchestration features) and lands on a
# brand-new named volume, so chmod here is enough — there's no pre-existing
# volume content to fix up like there was for signal-store. /attense/actions
# (analyst-action JSONL logs, written by blueteam/api/analyst_actions.py) has
# no volume mount at all -- without this, /attense itself is root:root 755 and
# the non-root appuser below gets a silent permission-denied creating it
# (caught and only logged, never raised, so the API call still returns 201).
RUN mkdir -p /attense/data /attense/temp /attense/actions \
    && chmod 777 /attense/temp /attense/actions
RUN mkdir -p /attense/temp/users /attense/temp/sessions /attense/temp/rooms \
    && chmod -R 777 /attense/temp

# Security boundary: drop root for the running process. The controller also
# needs to reach the mounted /var/run/docker.sock (root:root, mode 660 on
# Docker Desktop) for its docker.from_env() orchestration calls —
# supplementary group 0 grants that without making the process itself UID 0.
# On a host where the docker group has a different GID, add that GID here
# instead.
RUN groupadd -g 1000 appgroup \
    && useradd -u 1000 -g appgroup -G root -M -s /usr/sbin/nologin appuser
USER appuser

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8020"]
