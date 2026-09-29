#!/bin/bash
# CartBreach 30-minute Automated State Recovery Script
# Resets modified database state, temporary shells, and cron scripts
set -e

COMPOSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$COMPOSE_DIR"

echo "[$(date -u)] Initiating CartBreach automated environment reset..."

# Terminate containers and destroy volatile volumes (clears altered DB data)
docker compose down -v

# Rebuild and start container microservices stack
docker compose up -d --build

echo "[$(date -u)] CartBreach CTF environment successfully reset."
