package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteReadOnlyAndDryRun(t *testing.T) {
	t.Parallel()

	store := &Store{items: map[string]Object{
		"o1": {ID: "o1", Data: map[string]interface{}{"k": "v"}},
	}}

	for _, mode := range []string{"READ_ONLY", "DRY_RUN"} {
		req := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(`{"mode":"`+mode+`","payload":{"op":"create","object":{"id":"o2","data":{"x":"y"}}}}`))
		rr := httptest.NewRecorder()
		store.execute(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", mode, rr.Code)
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if body["mode"] != mode {
			t.Fatalf("expected mode %s, got %v", mode, body["mode"])
		}
		if len(store.items) != 1 {
			t.Fatalf("expected item count unchanged in %s mode, got %d", mode, len(store.items))
		}
	}
}

func TestExecuteCreateUpdateDelete(t *testing.T) {
	t.Parallel()

	store := &Store{items: map[string]Object{}}

	createReq := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(`{"payload":{"op":"create","object":{"id":"o1","data":{"status":"new"}}}}`))
	createRR := httptest.NewRecorder()
	store.execute(createRR, createReq)
	if createRR.Code != http.StatusOK {
		t.Fatalf("expected create 200, got %d", createRR.Code)
	}
	if _, ok := store.items["o1"]; !ok {
		t.Fatal("expected created object")
	}

	updateReq := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(`{"payload":{"op":"update","object":{"id":"o1","data":{"status":"updated"}}}}`))
	updateRR := httptest.NewRecorder()
	store.execute(updateRR, updateReq)
	if got := store.items["o1"].Data["status"]; got != "updated" {
		t.Fatalf("expected updated status, got %v", got)
	}

	deleteReq := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(`{"payload":{"op":"delete","ids":["o1"]}}`))
	deleteRR := httptest.NewRecorder()
	store.execute(deleteRR, deleteReq)
	if len(store.items) != 0 {
		t.Fatalf("expected empty store after delete, got %d", len(store.items))
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("MOCK_ENV_STRING", "value")
	if got := env("MOCK_ENV_STRING", "default"); got != "value" {
		t.Fatalf("expected env value, got %q", got)
	}
	if got := env("MOCK_ENV_MISSING", "default"); got != "default" {
		t.Fatalf("expected default value, got %q", got)
	}

	t.Setenv("MOCK_ENV_INT", "42")
	if got := envInt("MOCK_ENV_INT", 7); got != 42 {
		t.Fatalf("expected 42, got %d", got)
	}
	t.Setenv("MOCK_ENV_INT", "invalid")
	if got := envInt("MOCK_ENV_INT", 7); got != 7 {
		t.Fatalf("expected fallback 7, got %d", got)
	}
	t.Setenv("MOCK_ENV_INT", "9")
	if got := envDurationSec("MOCK_ENV_INT", 1); got.Seconds() != 9 {
		t.Fatalf("expected duration 9s from env, got %v", got)
	}
	t.Setenv("MOCK_ENV_INT", "invalid")
	if got := envDurationSec("MOCK_ENV_INT", 4); got.Seconds() != 4 {
		t.Fatalf("expected fallback duration 4s, got %v", got)
	}
}

func TestRunMockOntology(t *testing.T) {
	t.Run("telemetry init error", func(t *testing.T) {
		err := runMockOntology(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return nil, errors.New("otel failed")
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "otel failed") {
			t.Fatalf("expected telemetry error, got %v", err)
		}
	})

	t.Run("server config and routes", func(t *testing.T) {
		t.Setenv("ADDR", ":19084")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "6")
		t.Setenv("HTTP_READ_TIMEOUT_SEC", "10")
		t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "12")
		t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "16")

		captured := &http.Server{}
		err := runMockOntology(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(server *http.Server) error {
				captured = server
				return errors.New("listen stop")
			},
		)
		if err == nil || !strings.Contains(err.Error(), "listen stop") {
			t.Fatalf("expected listen error, got %v", err)
		}
		if captured.Addr != ":19084" {
			t.Fatalf("expected addr :19084, got %q", captured.Addr)
		}
		if captured.ReadHeaderTimeout.Seconds() != 6 ||
			captured.ReadTimeout.Seconds() != 10 ||
			captured.WriteTimeout.Seconds() != 12 ||
			captured.IdleTimeout.Seconds() != 16 {
			t.Fatalf("unexpected timeout config: %+v", captured)
		}

		healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		healthRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(healthRR, healthReq)
		if healthRR.Code != http.StatusOK || !strings.Contains(healthRR.Body.String(), `"service":"mock-ontology"`) {
			t.Fatalf("expected healthz response, got %d body=%s", healthRR.Code, healthRR.Body.String())
		}

		execReq := httptest.NewRequest(http.MethodPost, "/actions/execute", strings.NewReader(`{"payload":{"op":"create","object":{"id":"o1","data":{"x":"y"}}}}`))
		execRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(execRR, execReq)
		if execRR.Code != http.StatusOK || !strings.Contains(execRR.Body.String(), `"count":1`) {
			t.Fatalf("expected create execute response, got %d body=%s", execRR.Code, execRR.Body.String())
		}
	})
}
