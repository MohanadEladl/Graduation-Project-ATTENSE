FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY app /app/app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV MODE=wazuh
ENV OUTPUT_MODE=file
ENV OUTPUT_PATH=/attense/data/mapped_events.jsonl

EXPOSE 8000

# This service writes mapped_events.jsonl at runtime.
RUN mkdir -p /attense/data && chmod 777 /attense/data

RUN groupadd -g 1000 appgroup && useradd -u 1000 -g appgroup -M -s /usr/sbin/nologin appuser
USER appuser

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
