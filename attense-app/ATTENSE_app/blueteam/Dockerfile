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

FROM python:3.11-slim

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        supervisor \
        curl \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY requirments.txt .
RUN pip install --no-cache-dir -r requirments.txt

# ── BlueTeam source ───────────────────────────────────────────────────────────
COPY . .

# ── Supervisord configuration ─────────────────────────────────────────────────
COPY supervisord.conf /etc/supervisor/conf.d/blueteam.conf

# ── Startup wait script ───────────────────────────────────────────────────────
COPY start.sh /start.sh
RUN chmod +x /start.sh

# ── Log directory ─────────────────────────────────────────────────────────────
RUN mkdir -p /var/log

# ── Environment defaults ──────────────────────────────────────────────────────
ENV ATTENSE_APP_PATH=/attense_app
ENV HIVE_URL=http://localhost:9000
ENV HIVE_API_KEY=changeme
ENV WEBHOOK_SECRET=changeme-webhook

# Only the BlueTeam API is exposed externally
EXPOSE 8010

# supervisord manages all internal processes
# start.sh waits for internal dependencies before exec'ing supervisord
ENTRYPOINT ["/start.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/blueteam.conf"]
