#!/bin/bash
# start.sh — BlueTeam container startup
# ======================================
# Launches supervisord which starts the BlueTeam FastAPI service.
#
# TheHive, Cassandra and Elasticsearch are NOT running inside this
# container (they are external or stubbed). The HiveClient already
# handles connection failures gracefully (returns {} on error), so
# the API starts immediately without waiting for them.

set -e

echo "[start.sh] BlueTeam component starting..."
echo "[start.sh] Launching BlueTeam API via supervisord..."
exec "$@"
