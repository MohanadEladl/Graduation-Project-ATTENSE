# ── AttackBox — lightweight local penetration testing container ──────────────
# NOT a full Kali desktop. Provides CLI tools scoped to the local lab target.
# Stays alive via `sleep infinity`; the red-team-backend executes commands
# inside this container via `docker exec`.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Pin to official Kali CDN (HTTP avoids ca-cert bootstrap issue in minimal images)
# Configure apt to retry on transient network failures (mid-download drops crash the layer)
RUN echo 'Acquire::Retries "5";'           >  /etc/apt/apt.conf.d/99-retries \
 && echo 'Acquire::http::Timeout "120";'   >> /etc/apt/apt.conf.d/99-retries \
 && echo 'Acquire::https::Timeout "120";'  >> /etc/apt/apt.conf.d/99-retries \
 && echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" \
        > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    curl \
    nmap \
    hydra \
    ffuf \
    gobuster \
    jq \
    python3 \
    python3-pip \
    netcat-openbsd \
    ca-certificates \
    dnsutils \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /lab

COPY wordlists /wordlists

# Symlink so both /wordlists/ and /opt/wordlists/ work in operator commands
RUN ln -s /wordlists /opt/wordlists

# ─────────────────────────────────────────────────────────────────────────────
# Tag every outbound request from this container with a User-Agent the
# target-agent recognizes as "via=attackbox". This is what lets operator-mode
# missions distinguish AttackBox traffic from the lab-browser iframe traffic.
#
# We do three things:
#   1. Set $USER_AGENT and $HTTP_USER_AGENT for tools that honor them.
#   2. Drop /etc/curlrc with `user-agent = "AttenseAttackBox/1.0"`. curl reads
#      this on every invocation unless the user passes -A explicitly.
#   3. Add bash aliases so that `curl` AND `wget` AND `gobuster` AND `hydra`
#      pre-set the User-Agent header. Operators can still override with -A.
# ─────────────────────────────────────────────────────────────────────────────
RUN printf '%s\n' 'user-agent = "AttenseAttackBox/1.0"' > /etc/curlrc \
 && printf '%s\n' \
    'export USER_AGENT="AttenseAttackBox/1.0"' \
    'export HTTP_USER_AGENT="AttenseAttackBox/1.0"' \
    'alias curl='"'"'curl -A "AttenseAttackBox/1.0"'"'"'' \
    'alias wget='"'"'wget --user-agent="AttenseAttackBox/1.0"'"'"'' \
    'alias gobuster='"'"'gobuster -a "AttenseAttackBox/1.0"'"'"'' \
    > /etc/profile.d/attense-attackbox.sh \
 && cp /etc/profile.d/attense-attackbox.sh /root/.bashrc \
 && chmod +x /etc/profile.d/attense-attackbox.sh

# Wrapper scripts that ALWAYS inject the AttenseAttackBox UA, regardless of
# how the command is invoked. The backend's exec_in_attackbox runs commands
# via `bash -c "..."` which is non-interactive and so does NOT load aliases
# from profile.d. Wrappers in /usr/local/bin shadow /usr/bin/curl|wget on
# PATH and apply unconditionally — operators can still override with -A
# (curl) / --user-agent (wget) since the flag goes to the same arg list.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'exec /usr/bin/curl -A "AttenseAttackBox/1.0" "$@"' \
    > /usr/local/bin/curl \
 && printf '%s\n' \
    '#!/bin/sh' \
    'exec /usr/bin/wget --user-agent="AttenseAttackBox/1.0" "$@"' \
    > /usr/local/bin/wget \
 && chmod +x /usr/local/bin/curl /usr/local/bin/wget

# Default ENV so non-login shells also get tagged
ENV USER_AGENT="AttenseAttackBox/1.0" \
    HTTP_USER_AGENT="AttenseAttackBox/1.0"

CMD ["sleep", "infinity"]
