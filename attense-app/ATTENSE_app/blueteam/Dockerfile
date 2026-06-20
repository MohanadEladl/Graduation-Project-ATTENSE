# ═══════════════════════════════════════════════════════════════════════════════
# BlueTeam Component — Single Container (Option B)
# ═══════════════════════════════════════════════════════════════════════════════
# This container runs ALL BlueTeam-internal processes:
#   - Cassandra        (TheHive storage backend)
#   - Elasticsearch    (TheHive index backend)
#   - TheHive          (analyst case-management UI)
#   - BlueTeam API     (FastAPI — the ONLY externally exposed process)
#
# External interface: port 8010 ONLY.
# TheHive, Cassandra, and Elasticsearch are INTERNAL implementation details.
# ATTENSE Core never talks to them directly.
# ═══════════════════════════════════════════════════════════════════════════════

# Builder stage: deps copied and installed before any source code, so this
# layer is cache-hit on every rebuild that doesn't touch requirments.txt.
FROM python:3.11-slim AS builder

WORKDIR /app
COPY ATTENSE_app/blueteam/requirments.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirments.txt

# Final stage: only the built venv is copied in below — pip's own footprint
# never reaches the shipped image.
FROM python:3.11-slim

# ── System dependencies ──────────────────────────────────────────────────────
# update+install+cleanup chained in one RUN so the apt cache never persists
# in its own layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
        supervisor \
        curl \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH=/app

# ── BlueTeam source ───────────────────────────────────────────────────────────
COPY ATTENSE_app /app/ATTENSE_app

# ── Supervisord configuration ─────────────────────────────────────────────────
COPY ATTENSE_app/blueteam/supervisord.conf /etc/supervisor/conf.d/blueteam.conf

# ── Startup wait script ───────────────────────────────────────────────────────
COPY ATTENSE_app/blueteam/start.sh /start.sh
RUN sed -i 's/\r$//' /start.sh && chmod +x /start.sh

# ── Log directory ─────────────────────────────────────────────────────────────
RUN mkdir -p /var/log && chmod 777 /var/log

# ── Environment defaults ──────────────────────────────────────────────────────
ENV ATTENSE_APP_PATH=/attense_app
ENV HIVE_URL=http://localhost:9000

# Only the BlueTeam API is exposed externally
EXPOSE 8010

HEALTHCHECK --interval=5s --timeout=3s --start-period=15s --retries=12 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=2)"

# Security boundary: drop root for the running process. No privileged ports
# or system capabilities are needed (supervisord only spawns uvicorn on 8010).
RUN groupadd -g 1000 appgroup && useradd -u 1000 -g appgroup -M -s /usr/sbin/nologin appuser \
    && chown -R appuser:appgroup /app
USER appuser

# supervisord manages all internal processes
# start.sh waits for internal dependencies before exec'ing supervisord
ENTRYPOINT ["/start.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/blueteam.conf"]
