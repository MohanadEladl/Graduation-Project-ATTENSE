FROM python:3.12-slim

WORKDIR /app

# Core logic
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ATTENSE_app /app/ATTENSE_app
COPY controller.py /app/controller.py

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV ATTENSE_DATA_PATH=/attense/data/mapped_events.jsonl

# Ensure data directory exists (for mounting)
RUN mkdir -p /attense/data

CMD ["python", "controller.py"]
