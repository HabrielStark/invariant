#!/usr/bin/env bash
set -euo pipefail
DB_URL=${DATABASE_URL:-postgres://axiom:axiom@localhost:5432/axiom?sslmode=disable}
psql "$DB_URL" -f migrations/001_init.sql
