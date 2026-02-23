package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Tests for uncovered branches in mock-ontology

func TestEnvFunctions(t *testing.T) {
	// Test env with default
	if got := env("NONEXISTENT_VAR_123", "default"); got != "default" {
		t.Fatalf("expected default, got %q", got)
	}

	// Test env with set value
	t.Setenv("TEST_ENV_VAR", "testvalue")
	if got := env("TEST_ENV_VAR", "default"); got != "testvalue" {
		t.Fatalf("expected testvalue, got %q", got)
	}

	// Test envInt with default
	if got := envInt("NONEXISTENT_INT_VAR", 42); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}

	// Test envInt with valid value
	t.Setenv("TEST_INT_VAR", "100")
	if got := envInt("TEST_INT_VAR", 42); got != 100 {
		t.Fatalf("expected 100, got %d", got)
	}

	// Test envInt with invalid value (not a number)
	t.Setenv("TEST_INVALID_INT", "notanumber")
	if got := envInt("TEST_INVALID_INT", 42); got != 42 {
		t.Fatalf("expected 42 for invalid int, got %d", got)
	}

	// Test envDurationSec
	if got := envDurationSec("NONEXISTENT_DUR", 5); got.Seconds() != 5 {
		t.Fatalf("expected 5s, got %v", got)
	}
}

func TestStoreExecuteOperations(t *testing.T) {
	store := &Store{items: make(map[string]Object)}

	// Test create operation
	createReq := `{"op":"create","object":{"id":"obj-1","data":{"name":"test"}}}`
	req := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(createReq))
	rec := httptest.NewRecorder()
	store.execute(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if len(store.items) != 1 {
		t.Fatalf("expected 1 item after create, got %d", len(store.items))
	}

	// Test update operation
	updateReq := `{"op":"update","object":{"id":"obj-1","data":{"name":"updated"}}}`
	req = httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(updateReq))
	rec = httptest.NewRecorder()
	store.execute(rec, req)
	if store.items["obj-1"].Data["name"] != "updated" {
		t.Fatalf("expected updated data")
	}

	// Test update of nonexistent item
	updateNonexistent := `{"op":"update","object":{"id":"obj-999","data":{"name":"new"}}}`
	req = httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(updateNonexistent))
	rec = httptest.NewRecorder()
	store.execute(rec, req)
	if len(store.items) != 1 { // Should still be 1
		t.Fatalf("expected 1 item (no update for nonexistent), got %d", len(store.items))
	}

	// Test delete operation
	deleteReq := `{"op":"delete","ids":["obj-1"]}`
	req = httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(deleteReq))
	rec = httptest.NewRecorder()
	store.execute(rec, req)
	if len(store.items) != 0 {
		t.Fatalf("expected 0 items after delete, got %d", len(store.items))
	}
}

func TestStoreExecuteWithMode(t *testing.T) {
	store := &Store{items: make(map[string]Object)}
	store.items["existing"] = Object{ID: "existing", Data: map[string]interface{}{"foo": "bar"}}

	// Test READ_ONLY mode
	readOnlyReq := `{"mode":"READ_ONLY","payload":{"op":"delete","ids":["existing"]}}`
	req := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(readOnlyReq))
	rec := httptest.NewRecorder()
	store.execute(rec, req)

	var resp map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["mode"] != "READ_ONLY" {
		t.Fatalf("expected READ_ONLY mode in response, got %v", resp["mode"])
	}
	// Item should NOT be deleted in READ_ONLY mode
	if len(store.items) != 1 {
		t.Fatalf("expected item to remain in READ_ONLY mode")
	}

	// Test DRY_RUN mode
	dryRunReq := `{"mode":"DRY_RUN","payload":{"op":"create","object":{"id":"new","data":{}}}}`
	req = httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(dryRunReq))
	rec = httptest.NewRecorder()
	store.execute(rec, req)

	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["mode"] != "DRY_RUN" {
		t.Fatalf("expected DRY_RUN mode in response")
	}
	// No new item should be created
	if len(store.items) != 1 {
		t.Fatalf("expected no new item in DRY_RUN mode")
	}
}

func TestRunMockOntologyTelemetryError(t *testing.T) {
	err := runMockOntology(
		func(ctx context.Context, service string) (func(context.Context) error, error) {
			return nil, errors.New("telemetry init failed")
		},
		nil,
	)
	if err == nil || err.Error() != "telemetry init failed" {
		t.Fatalf("expected telemetry error, got %v", err)
	}
}

func TestRunMockOntologySuccess(t *testing.T) {
	t.Setenv("ADDR", "127.0.0.1:0")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "1")
	t.Setenv("HTTP_READ_TIMEOUT_SEC", "2")
	t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "3")
	t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "10")

	err := runMockOntology(
		func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		},
		func(server *http.Server) error {
			// Test that server is configured correctly
			if server.ReadHeaderTimeout.Seconds() != 1 {
				return errors.New("incorrect read header timeout")
			}
			return errors.New("test-stop")
		},
	)
	if err == nil || err.Error() != "test-stop" {
		t.Fatalf("expected test-stop error, got %v", err)
	}
}

func TestEnvWithValue(t *testing.T) {
	// Set env var and verify it's read
	originalVal := os.Getenv("ADDR")
	t.Setenv("ADDR", ":9999")
	if got := env("ADDR", ":default"); got != ":9999" {
		t.Fatalf("expected :9999, got %q", got)
	}
	if originalVal != "" {
		t.Setenv("ADDR", originalVal)
	}
}
