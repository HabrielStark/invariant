#!/usr/bin/env bash
set -euo pipefail

THRESHOLD="${1:-85.0}"
PROFILE="${2:-coverage_all.out}"
if [[ $# -ge 2 ]]; then
  shift 2
else
  shift $#
fi
EXTRA_GO_TEST_ARGS=("$@")

PKGS=()
while IFS= read -r pkg; do
  if [[ -n "${pkg}" ]]; then
    PKGS+=("${pkg}")
  fi
done < <(go list -f '{{if or (gt (len .TestGoFiles) 0) (gt (len .XTestGoFiles) 0)}}{{.ImportPath}}{{end}}' ./... | sed '/^$/d')

if [[ "${#PKGS[@]}" -eq 0 ]]; then
  echo "[coverage] failed: no packages with tests found"
  exit 1
fi

echo "[coverage] running go test with coverage profile ${PROFILE}"
go test "${EXTRA_GO_TEST_ARGS[@]}" "${PKGS[@]}" -covermode=atomic -coverprofile="${PROFILE}" >/tmp/go-test-cover.log

TOTAL_RAW="$(go tool cover -func="${PROFILE}" | awk '/^total:/ {print $3}')"
TOTAL="${TOTAL_RAW%\%}"

if [[ -z "${TOTAL}" ]]; then
  echo "[coverage] failed: cannot parse total coverage"
  exit 1
fi

echo "[coverage] total=${TOTAL}% threshold=${THRESHOLD}%"

awk -v total="${TOTAL}" -v threshold="${THRESHOLD}" 'BEGIN { if (total + 0 < threshold + 0) exit 1 }' || {
  echo "[coverage] gate failed: total coverage ${TOTAL}% is below ${THRESHOLD}%"
  exit 1
}

echo "[coverage] gate passed"
