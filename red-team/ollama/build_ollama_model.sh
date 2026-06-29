#!/usr/bin/env bash
# Build the MITRE-specialised ATT3NSE analyst model inside the running ollama
# container. Idempotent — safe to re-run after editing the Modelfile.
#
#   bash red-team/ollama/build_ollama_model.sh
#
# Requires: the attense_ollama container running, with llama3.2:3b already
# pulled (the base model). Env overrides:
#   OLLAMA_CONTAINER  (default: attense_ollama)
#   ANALYST_MODEL     (default: attense-analyst)
set -euo pipefail

CONTAINER="${OLLAMA_CONTAINER:-attense_ollama}"
MODEL="${ANALYST_MODEL:-attense-analyst}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELFILE="$HERE/Modelfile.attense-analyst"

echo "[*] Ensuring base model llama3.2:3b is present..."
docker exec "$CONTAINER" ollama pull llama3.2:3b

echo "[*] Copying Modelfile into $CONTAINER..."
docker cp "$MODELFILE" "$CONTAINER:/tmp/Modelfile.attense-analyst"

echo "[*] Creating model '$MODEL'..."
docker exec "$CONTAINER" ollama create "$MODEL" -f /tmp/Modelfile.attense-analyst

echo "[*] Done. Models now available:"
docker exec "$CONTAINER" ollama list
