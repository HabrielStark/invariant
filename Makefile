.PHONY: test test-race build build-z3 fmt lint gosec sbom sbom-ui vuln trivy migrate dev smoke contract chaos perf self-audit bootstrap sdk-ts-build ui-budget pentest-external
TRIVY_IMAGE ?= aquasec/trivy:0.59.1@sha256:029e990b328d149bf0a9ffe355919041e1f86192db2df47e217f8a36dd42ceac
 
build-z3:
	go build -tags z3cgo ./cmd/gateway ./cmd/verifier ./cmd/policy ./cmd/state ./cmd/mock-ontology ./cmd/tool-mock ./cmd/axiomctl ./cmd/migrator ./cmd/axiomdsl-lsp

test:
	go test -race -count=1 ./...

test-race:
	go test -race -count=1 -timeout 300s ./...

build:
	go build ./cmd/gateway ./cmd/verifier ./cmd/policy ./cmd/state ./cmd/mock-ontology ./cmd/tool-mock ./cmd/axiomctl ./cmd/migrator ./cmd/axiomdsl-lsp

fmt:
	gofmt -w $$(find cmd pkg -name '*.go')

lint:
	go vet ./...

gosec:
	go install github.com/securego/gosec/v2/cmd/gosec@v2.22.0
	$$(go env GOPATH)/bin/gosec -fmt text ./cmd/... ./pkg/...

sbom:
	go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.8.0
	$$(go env GOPATH)/bin/cyclonedx-gomod mod -json -output sbom-go.json

sbom-ui:
	cd ui/console && npx --yes @cyclonedx/cyclonedx-npm@1.19.0 --output-file sbom-ui.json

vuln:
	go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
	$$(go env GOPATH)/bin/govulncheck ./...

trivy:
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --scanners vuln,secret --severity CRITICAL --ignore-unfixed --exit-code 1 . ; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v "$$PWD:/workspace" -w /workspace $(TRIVY_IMAGE) fs --scanners vuln,secret --severity CRITICAL --ignore-unfixed --exit-code 1 . ; \
	else \
		echo "trivy scan unavailable: neither trivy nor docker found" ; \
		exit 1 ; \
	fi

migrate:
	./scripts/migrate.sh

dev:
	./scripts/dev.sh

smoke:
	./scripts/smoke-compose.sh

contract:
	./scripts/contract-compose.sh

chaos:
	./scripts/chaos-compose.sh

perf:
	./scripts/perf-compose.sh

self-audit:
	./scripts/self-audit.sh

pentest-external:
	./scripts/pentest-external.sh

bootstrap:
	./scripts/bootstrap.sh

sdk-ts-build:
	cd sdk/ts && ../../ui/console/node_modules/.bin/tsc -p tsconfig.json

ui-budget:
	./scripts/check-ui-budget.sh
