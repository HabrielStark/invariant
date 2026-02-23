package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Additional tests for uncovered branches in tool-mock
// Note: Main tests are in main_test.go

func TestHandleExecuteEmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(""))
	rec := httptest.NewRecorder()
	handleExecute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 even with empty body, got %d", rec.Code)
	}
}

func TestHandleExecutePayloadWrap(t *testing.T) {
	// Test payload wrapping when payload key exists
	body := `{"payload":{"action":"deploy"}}`
	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleExecute(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"payload"`) {
		t.Fatalf("expected payload in response, got %s", rec.Body.String())
	}
}

func TestEnvDurationSecWithDefault(t *testing.T) {
	// Test duration with unset env
	dur := envDurationSec("NONEXISTENT_DURATION_VAR_XYZ", 15)
	if dur.Seconds() != 15 {
		t.Fatalf("expected 15s default, got %v", dur)
	}
}
