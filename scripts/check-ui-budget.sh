#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/ui/console/dist/assets"
RAW_BUDGET_BYTES="${UI_INITIAL_JS_BUDGET_BYTES:-256000}"
GZIP_BUDGET_BYTES="${UI_INITIAL_JS_GZIP_BUDGET_BYTES:-102400}"

if [[ ! -d "$DIST_DIR" ]]; then
  echo "ui budget check failed: dist not found at $DIST_DIR (run ui build first)"
  exit 1
fi

ENTRY_FILE="$(find "$DIST_DIR" -maxdepth 1 -type f -name 'index-*.js' | head -n 1)"
if [[ -z "$ENTRY_FILE" ]]; then
  echo "ui budget check failed: entry bundle index-*.js not found in $DIST_DIR"
  exit 1
fi

RAW_BYTES="$(wc -c < "$ENTRY_FILE" | tr -d ' ')"
GZIP_BYTES="$(gzip -c "$ENTRY_FILE" | wc -c | tr -d ' ')"

echo "ui budget: entry=$(basename "$ENTRY_FILE") raw=${RAW_BYTES}B gzip=${GZIP_BYTES}B budget_raw=${RAW_BUDGET_BYTES}B budget_gzip=${GZIP_BUDGET_BYTES}B"

if (( RAW_BYTES > RAW_BUDGET_BYTES )); then
  echo "ui budget check failed: raw size ${RAW_BYTES} exceeds ${RAW_BUDGET_BYTES}"
  exit 1
fi

if (( GZIP_BYTES > GZIP_BUDGET_BYTES )); then
  echo "ui budget check failed: gzip size ${GZIP_BYTES} exceeds ${GZIP_BUDGET_BYTES}"
  exit 1
fi

echo "ui budget check passed"
