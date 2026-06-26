FROM python:3.12-slim

RUN apt-get update -qq && \
    apt-get install -y -qq auditd audispd-plugins && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "agent.py"]
