# Blue Team single-container image.
# Build context is the repo root so this image can copy both the Blue Team
# service package and the shared attense_core package.

FROM python:3.11-slim AS builder

WORKDIR /app
COPY apps/blue-team-api/requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        supervisor \
        curl \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONPATH=/app

# The importable package is apps/blue-team-api/blueteam/.
COPY apps/blue-team-api/blueteam /app/blueteam
# Canonical shared domain package.
COPY packages/attense-core/attense_core /app/attense_core

COPY apps/blue-team-api/supervisord.conf /etc/supervisor/conf.d/blueteam.conf
COPY apps/blue-team-api/start.sh /start.sh
RUN sed -i 's/\r$//' /start.sh && chmod +x /start.sh

RUN mkdir -p /var/log && chmod 777 /var/log

# blueteam/api/analyst_actions.py writes /attense/actions/<analyst>_<date>.jsonl.
RUN mkdir -p /attense/actions && chmod 777 /attense/actions

ENV HIVE_URL=http://localhost:9000

EXPOSE 8010

HEALTHCHECK --interval=5s --timeout=3s --start-period=15s --retries=12 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=2)"

RUN groupadd -g 1000 appgroup && useradd -u 1000 -g appgroup -M -s /usr/sbin/nologin appuser \
    && chown -R appuser:appgroup /app
USER appuser

ENTRYPOINT ["/start.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/blueteam.conf"]
