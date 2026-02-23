#!/usr/bin/env bash
set -euo pipefail
export DATABASE_URL=${DATABASE_URL:-postgres://axiom:axiom@localhost:5432/axiom?sslmode=disable}
export REDIS_ADDR=${REDIS_ADDR:-localhost:6379}

go run ./cmd/policy &
go run ./cmd/state &
go run ./cmd/verifier &
go run ./cmd/mock-ontology &
go run ./cmd/tool-mock &
go run ./cmd/gateway &

wait
