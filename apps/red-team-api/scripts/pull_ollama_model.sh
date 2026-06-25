#!/bin/sh
# Pull the Ollama model on first startup.
# Called from the red-team-backend entrypoint after the server starts.
# Safe to re-run — Ollama skips the download if the model is already present.

MODEL="${OLLAMA_MODEL:-llama3.2:3b}"
OLLAMA_URL="${OLLAMA_URL:-http://ollama:11434}"

echo "[attense] Waiting for Ollama to be ready..."
for i in $(seq 1 30); do
  if curl -sf "${OLLAMA_URL}/api/tags" >/dev/null 2>&1; then
    echo "[attense] Ollama is ready. Pulling model: ${MODEL}"
    curl -sf -X POST "${OLLAMA_URL}/api/pull" \
         -H "Content-Type: application/json" \
         -d "{\"name\": \"${MODEL}\"}" >/dev/null
    echo "[attense] Model pull complete."
    exit 0
  fi
  sleep 2
done
echo "[attense] Ollama did not become ready in time — skipping model pull."
exit 0
