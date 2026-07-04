# ── target-agent Dockerfile ───────────────────────────────────────────────────
# Runs three processes inside one container:
#   1. Wazuh agent   → ships logs to wazuh-manager
#   2. nginx         → reverse proxy port 80 → Flask :5000
#   3. Flask app     → intentionally vulnerable Python web app
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg apt-transport-https lsb-release ca-certificates \
        nginx \
        iputils-ping \
        python3 python3-pip python3-venv \
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
COPY app/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt || \
    pip3 install --no-cache-dir -r requirements.txt

COPY app/ /app/

# Create log + upload dirs with open permissions (lab only)
RUN mkdir -p /app/logs /app/static/uploads && \
    chmod 777 /app/logs /app/static/uploads

# ── Entrypoint ────────────────────────────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

CMD ["/entrypoint.sh"]
