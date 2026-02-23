package telemetry

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func sampleDecision(s sdktrace.Sampler) sdktrace.SamplingDecision {
	return s.ShouldSample(sdktrace.SamplingParameters{
		ParentContext: context.Background(),
		TraceID:       oteltrace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Name:          "telemetry-test",
	}).Decision
}

func TestParseSampler(t *testing.T) {
	t.Parallel()

	if got := sampleDecision(parseSampler("always_off", "")); got != sdktrace.Drop {
		t.Fatalf("always_off must drop, got %v", got)
	}
	if got := sampleDecision(parseSampler("always_on", "")); got != sdktrace.RecordAndSample {
		t.Fatalf("always_on must sample, got %v", got)
	}
	if got := sampleDecision(parseSampler("traceidratio", "2")); got != sdktrace.RecordAndSample {
		t.Fatalf("ratio should clamp to 1 and sample, got %v", got)
	}
	if got := sampleDecision(parseSampler("traceidratio", "-1")); got != sdktrace.Drop {
		t.Fatalf("ratio should clamp to 0 and drop, got %v", got)
	}
	if got := sampleDecision(parseSampler("parentbased", "0")); got != sdktrace.Drop {
		t.Fatalf("parentbased ratio=0 should drop without sampled parent, got %v", got)
	}
	if got := sampleDecision(parseSampler("unknown", "")); got != sdktrace.RecordAndSample {
		t.Fatalf("default sampler should sample at ratio 1, got %v", got)
	}
}

func TestParseHeaders(t *testing.T) {
	t.Parallel()

	headers := parseHeaders("k1=v1, k2 = v2,broken")
	if len(headers) != 2 {
		t.Fatalf("expected 2 parsed headers, got %d", len(headers))
	}
	if headers["k1"] != "v1" {
		t.Fatalf("expected k1=v1, got %q", headers["k1"])
	}
	if headers["k2"] != "v2" {
		t.Fatalf("expected k2=v2, got %q", headers["k2"])
	}
	if got := parseHeaders("   "); got != nil {
		t.Fatalf("expected nil for empty header string, got %v", got)
	}
	headers = parseHeaders("k1=v1, , =bad, k2=v2")
	if len(headers) != 2 {
		t.Fatalf("expected 2 headers when empty parts/keys skipped, got %d (%#v)", len(headers), headers)
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("TELEMETRY_TEST_INT", "42")
	if got := envInt("TELEMETRY_TEST_INT", 1); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	t.Setenv("TELEMETRY_TEST_INT", "bad")
	if got := envInt("TELEMETRY_TEST_INT", 7); got != 7 {
		t.Fatalf("expected default 7, got %d", got)
	}
}

func TestInitWithoutExporterAndInstrumentClient(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_REQUIRED", "false")
	shutdown, err := Init(context.Background(), "telemetry-test")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	client := InstrumentClient(nil)
	if client == nil {
		t.Fatal("expected instrumented client")
	}
	if client.Transport == nil {
		t.Fatal("expected transport to be set")
	}

	existing := &http.Client{Transport: http.DefaultTransport}
	instrumented := InstrumentClient(existing)
	if instrumented != existing {
		t.Fatal("expected instrumentation to mutate and return same client")
	}
}

func TestHTTPMiddleware(t *testing.T) {
	handler := HTTPMiddleware("gateway")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", rr.Code)
	}
}

func TestHTTPMiddlewareDefaultServiceName(t *testing.T) {
	handler := HTTPMiddleware("   ")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected status 202, got %d", rr.Code)
	}
}

func TestInitExporterRequiredVsOptional(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4318")
	t.Setenv("OTEL_REQUIRED", "false")
	ctxOptional, cancelOptional := context.WithCancel(context.Background())
	cancelOptional()
	shutdown, err := Init(ctxOptional, "telemetry-optional-exporter")
	if err != nil {
		t.Fatalf("required=false should fallback without error, got %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected shutdown function on fallback")
	}
	_ = shutdown(context.Background())

	t.Setenv("OTEL_REQUIRED", "true")
	ctxRequired, cancelRequired := context.WithCancel(context.Background())
	cancelRequired()
	if _, err := Init(ctxRequired, "telemetry-required-exporter"); err == nil {
		t.Fatal("required=true must return exporter init error when exporter cannot start")
	}
}

func TestInitExporterSuccessWithHeadersAndInsecure(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/traces") {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer collector.Close()

	u, err := url.Parse(collector.URL)
	if err != nil {
		t.Fatalf("parse collector url: %v", err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", u.Host)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "x-test=1")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT_SEC", "1")
	t.Setenv("OTEL_REQUIRED", "true")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	shutdown, err := Init(ctx, "   ")
	if err != nil {
		t.Fatalf("expected exporter init success, got %v", err)
	}
	if shutdown == nil {
		t.Fatal("expected shutdown function")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestInitExporterRequiredFailureByBadEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host := ln.Addr().String()
	_ = ln.Close()

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+host)
	t.Setenv("OTEL_REQUIRED", "true")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Init(ctx, "telemetry-required-bad-endpoint"); err == nil {
		t.Fatal("expected init error for invalid endpoint format when required=true")
	}
}
