FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker-cli && rm -rf /var/lib/apt/lists/*

COPY app /app/app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

RUN mkdir -p /app/reports && chmod 777 /app/reports

RUN groupadd -g 1000 appgroup && useradd -u 1000 -g appgroup -M -s /usr/sbin/nologin appuser
USER appuser

CMD ["python", "-m", "app.agent"]
