#!/usr/bin/env bash
set -euo pipefail

echo "[1/17] go fmt check"
test -z "$(gofmt -l $(find cmd pkg -name '*.go'))"

echo "[2/17] go vet"
go vet ./...

echo "[3/17] gosec"
make gosec

echo "[4/17] go test -race"
make test-race

echo "[5/17] go coverage gate"
bash ./scripts/check-go-coverage.sh 85.0 coverage_all.out

echo "[6/17] ui install + build"
(cd ui/console && npm ci && npm run build)

echo "[7/17] ui budget"
./scripts/check-ui-budget.sh

echo "[8/17] ui audit"
(cd ui/console && npm audit --omit=dev --audit-level=critical)

echo "[9/17] sdk ts build"
make sdk-ts-build

echo "[10/17] go sbom"
make sbom

echo "[11/17] ui sbom"
(cd ui/console && npx --yes @cyclonedx/cyclonedx-npm@1.19.0 --output-file sbom-ui.json)

echo "[12/17] vuln scan"
make vuln

echo "[13/17] trivy critical scan"
make trivy

echo "[14/17] smoke"
./scripts/smoke-compose.sh

echo "[15/17] contract"
./scripts/contract-compose.sh

echo "[16/17] chaos"
./scripts/chaos-compose.sh

echo "[17/17] perf"
./scripts/perf-compose.sh

echo "self-audit complete"
