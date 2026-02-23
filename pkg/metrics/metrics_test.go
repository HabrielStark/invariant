package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistryObserveAndSnapshot(t *testing.T) {
	r := NewRegistry()
	r.Observe("GET /healthz", 200, 15*time.Millisecond)
	r.Observe("GET /healthz", 503, 35*time.Millisecond)
	r.IncVerdict("ALLOW")
	r.IncVerdict("ALLOW")
	r.IncReason("OK")
	r.SetGauge("escrow_pending", 3)

	snap := r.Snapshot()
	ep, ok := snap.Endpoints["GET /healthz"]
	if !ok {
		t.Fatal("missing endpoint metric")
	}
	if ep.Count != 2 {
		t.Fatalf("expected count=2 got=%d", ep.Count)
	}
	if ep.ErrorCount != 1 {
		t.Fatalf("expected error_count=1 got=%d", ep.ErrorCount)
	}
	if ep.MaxMillis != 35 {
		t.Fatalf("expected max_millis=35 got=%d", ep.MaxMillis)
	}
	if snap.Verdicts["ALLOW"] != 2 {
		t.Fatalf("expected ALLOW=2 got=%d", snap.Verdicts["ALLOW"])
	}
	if snap.Reasons["OK"] != 1 {
		t.Fatalf("expected OK=1 got=%d", snap.Reasons["OK"])
	}
	if snap.Gauges["escrow_pending"] != 3 {
		t.Fatalf("expected gauge escrow_pending=3 got=%v", snap.Gauges["escrow_pending"])
	}
}

func TestSortedKeys(t *testing.T) {
	keys := SortedKeys(map[string]int{"b": 2, "a": 1, "c": 3})
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys got=%d", len(keys))
	}
	if keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Fatalf("unexpected order: %#v", keys)
	}
}

func TestPrometheusHandler(t *testing.T) {
	r := NewRegistry()
	r.Observe("POST /v1/tool/execute", 200, 12*time.Millisecond)
	r.Observe("POST /v1/tool/execute", 500, 20*time.Millisecond)
	r.IncVerdict("ALLOW")
	r.IncReason("OK")
	r.SetGauge("escrow_pending", 7)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics/prometheus", nil)
	r.PrometheusHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "axiom_endpoint_count") {
		t.Fatalf("missing endpoint metric: %s", body)
	}
	if !strings.Contains(body, "axiom_verdict_total{verdict=\"ALLOW\"} 1") {
		t.Fatalf("missing verdict metric: %s", body)
	}
	if !strings.Contains(body, "axiom_gauge{name=\"escrow_pending\"} 7.000") {
		t.Fatalf("missing gauge metric: %s", body)
	}
}

func TestJSONHandlerAndEmptyInputs(t *testing.T) {
	r := NewRegistry()
	r.IncVerdict("")
	r.IncReason("")
	r.SetGauge("", 5)
	r.Observe("GET /healthz", 204, 5*time.Millisecond)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected json content type, got %q", got)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "\"GeneratedAt\"") && !strings.Contains(body, "\"generated_at\"") {
		t.Fatalf("expected generated timestamp in body: %s", body)
	}
	if strings.Contains(body, "\"\"") {
		t.Fatalf("did not expect empty-key counters in body: %s", body)
	}
}
