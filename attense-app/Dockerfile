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

COPY ATTENSE_app /app/ATTENSE_app
COPY api /app/api
COPY core /app/core
COPY dependencies /app/dependencies
COPY controller.py /app/controller.py
COPY main.py /app/main.py

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
# volume content to fix up like there was for signal-store.
RUN mkdir -p /attense/data /attense/temp && chmod 777 /attense/temp
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
