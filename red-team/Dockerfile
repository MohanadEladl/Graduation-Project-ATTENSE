# ── red-team Dockerfile ───────────────────────────────────────────────────────
# Runs the FastAPI interactive-shell server. Operator interacts via the React
# frontend on port 3000, which talks to this backend on 8000 over WebSocket.
FROM python:3.12-slim

WORKDIR /red-team

# System deps — curl for healthcheck only.
# Docker exec is handled by the Python docker SDK via the mounted socket.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
