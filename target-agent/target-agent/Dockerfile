# ── target-agent Dockerfile ───────────────────────────────────────────────────
# Runs three processes inside one container:
#   1. Wazuh agent   → ships logs to wazuh-manager
#   2. nginx         → reverse proxy port 80 → Flask :5000
#   3. Flask app     → intentionally vulnerable Python web app
# Builder stage: only python3-pip/python3-venv (needed to build the venv) and
# the Flask app's deps live here. requirements.txt is copied and installed
# before anything else so this layer is cache-hit on unrelated rebuilds.
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# Final stage: only the built venv is copied in below (see "Flask vulnerable
# app" section) — final stage's python3 install skips pip/venv entirely,
# since the venv already carries its own pip.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg apt-transport-https lsb-release ca-certificates \
        nginx \
        iputils-ping \
        python3 \
        procps netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── Wazuh Agent 4.9.2 ─────────────────────────────────────────────────────────
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
          https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=4.9.2-1 && \
    rm -rf /var/lib/apt/lists/*

# ── nginx config (proxy to Flask on :5000) ────────────────────────────────────
COPY nginx.conf /etc/nginx/nginx.conf

# ── Wazuh agent config (shipped into /var/ossec/etc) ──────────────────────────
COPY ossec.conf /var/ossec/etc/ossec.conf
RUN chown root:wazuh /var/ossec/etc/ossec.conf && chmod 660 /var/ossec/etc/ossec.conf

# ── Flask vulnerable app ──────────────────────────────────────────────────────
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY app/ /app/

# Create log + upload dirs with open permissions (lab only)
RUN mkdir -p /app/logs /app/static/uploads && \
    chmod 777 /app/logs /app/static/uploads

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

# Security boundary exception: this container intentionally stays root.
# nginx's master process must bind port 80 (a privileged port) and the Wazuh
# agent manages its own privileged daemons — neither works after USER drops
# root, and this entrypoint boots both as PID 1 in sequence.
CMD ["/entrypoint.sh"]
