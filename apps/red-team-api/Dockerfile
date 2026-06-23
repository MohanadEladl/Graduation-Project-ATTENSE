# ── red-team Dockerfile ───────────────────────────────────────────────────────
# Runs the FastAPI interactive-shell server. Operator interacts via the React
# frontend on port 3000, which talks to this backend on 8000 over WebSocket.

# Builder stage: deps copied and installed before any source code, so this
# layer is cache-hit on every rebuild that doesn't touch requirements.txt.
FROM python:3.12-slim AS builder

WORKDIR /red-team
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Final stage: only the built venv is copied in — pip's own footprint never
# reaches the shipped image.
FROM python:3.12-slim

WORKDIR /red-team

# System deps — curl for healthcheck only. update+install+cleanup chained in
# one RUN so the apt cache never persists in its own layer.
# Docker exec is handled by the Python docker SDK via the mounted socket.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Application code
COPY core/     ./core/
COPY modules/  ./modules/
COPY utils/    ./utils/
COPY engine/   ./engine/
COPY backend/  ./backend/
COPY main.py   ./main.py

# Logs directory
RUN mkdir -p /red-team/logs && chmod 777 /red-team/logs

ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/red-team \
    LOG_DIR=/red-team/logs \
    TARGET_HOST=target-agent \
    TARGET_PORT=80

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Security boundary: drop root for the running process. This container also
# needs to reach the mounted /var/run/docker.sock (root:root, mode 660 on
# Docker Desktop) to run `docker exec` into attackbox/target-agent — adding
# the app user to supplementary group 0 grants that without making the
# process itself UID 0. On a host where the docker group has a different
# GID, add that GID here instead.
RUN groupadd -g 1000 appgroup \
    && useradd -u 1000 -g appgroup -G root -M -s /usr/sbin/nologin appuser
USER appuser

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
