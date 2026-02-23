#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE=${COMPOSE_FILE:-infra/docker-compose/docker-compose.yml}
ENV_FILE=${ENV_FILE:-.env}
if [ ! -f "$ENV_FILE" ]; then
  ENV_FILE=.env.example
fi
AUTH_MODE=${AUTH_MODE:-off}
export AUTH_MODE
ALLOW_INSECURE_AUTH_OFF=${ALLOW_INSECURE_AUTH_OFF:-true}
export ALLOW_INSECURE_AUTH_OFF
BASE=${BASE:-http://localhost:8080}
dc() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

wait_for() {
  local url=$1
  local max=${2:-60}
  local i=0
  until curl -fsS "$url" >/dev/null 2>&1; do
    i=$((i+1))
    if [ "$i" -ge "$max" ]; then
      echo "timeout waiting for $url"
      return 1
    fi
    sleep 2
  done
}

echo "bootstrapping stack"
dc up -d --build
wait_for "$BASE/healthz" 90
./scripts/e2e.sh
echo "bootstrap complete"
