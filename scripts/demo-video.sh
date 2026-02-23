#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE=${COMPOSE_FILE:-infra/docker-compose/docker-compose.yml}
BASE=${BASE:-http://localhost:8080}
UI_URL=${UI_URL:-http://localhost:5173}

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

mkdir -p docs/demo

docker compose -f "$COMPOSE_FILE" up -d --build
wait_for "$BASE/healthz" 90

pushd ui/console >/dev/null
if [ ! -d node_modules ]; then
  npm install
fi
npm run dev -- --host 127.0.0.1 --port 5173 >/tmp/axiomos-vite.log 2>&1 &
VITE_PID=$!
popd >/dev/null

wait_for "$UI_URL" 60

pushd ui/console >/dev/null
npx playwright test --config playwright.config.ts --project=chromium
popd >/dev/null

kill "$VITE_PID" >/dev/null 2>&1 || true

VIDEO=$(find ui/console/test-results -name '*.webm' | sort | tail -1)
if [ -z "$VIDEO" ]; then
  echo "no video produced" >&2
  exit 1
fi
cp "$VIDEO" docs/demo/axiomos-demo.webm

echo "demo video written to docs/demo/axiomos-demo.webm"
