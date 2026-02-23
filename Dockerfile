FROM golang:1.24.0@sha256:3f7444391c51a11a039bf0359ee81cc64e663c17d787ad0e637a4de1a3f62a71 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
RUN apt-get update && apt-get install -y --no-install-recommends z3 libz3-dev gcc g++ make && rm -rf /var/lib/apt/lists/*
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway
RUN CGO_ENABLED=1 go build -tags z3cgo -o /out/verifier ./cmd/verifier
RUN CGO_ENABLED=0 go build -o /out/policy ./cmd/policy
RUN CGO_ENABLED=0 go build -o /out/state ./cmd/state
RUN CGO_ENABLED=0 go build -o /out/mock-ontology ./cmd/mock-ontology
RUN CGO_ENABLED=0 go build -o /out/tool-mock ./cmd/tool-mock
RUN CGO_ENABLED=0 go build -o /out/axiomctl ./cmd/axiomctl
RUN CGO_ENABLED=0 go build -o /out/invariant ./cmd/invariant
RUN CGO_ENABLED=0 go build -o /out/openclaw-http-proxy ./adapters/openclaw/http-proxy
RUN CGO_ENABLED=0 go build -o /out/openclaw-ws-node ./adapters/openclaw/ws-node
RUN CGO_ENABLED=0 go build -o /out/migrator ./cmd/migrator
RUN mkdir -p /out/lib && \
    Z3_LIBS=$(find /usr/lib /lib -name 'libz3.so*' -type f) && \
    test -n "$Z3_LIBS" && \
    echo "$Z3_LIBS" | xargs -I{} cp -v {} /out/lib/

FROM gcr.io/distroless/cc-debian12@sha256:72344f7f909a8bf003c67f55687e6d51a441b49661af8f660aa7b285f00e57df
WORKDIR /app
COPY --from=build /out/ ./
COPY --from=build /usr/bin/z3 /usr/bin/z3
COPY --from=build /out/lib/ /usr/lib/
COPY --from=build /src/migrations ./migrations
USER nonroot:nonroot
CMD ["./gateway"]
