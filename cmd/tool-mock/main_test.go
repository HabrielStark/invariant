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

func TestHandleExecuteWithModeAndPayload(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"mode":"READ_ONLY","payload":{"op":"simulate","input":{"invoice":"inv-1"}}}`))
	rr := httptest.NewRecorder()
	handleExecute(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
	if body["mode"] != "READ_ONLY" {
		t.Fatalf("expected READ_ONLY mode, got %v", body["mode"])
	}
	echo, ok := body["echo"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected echo payload object, got %T", body["echo"])
	}
	if _, ok := echo["payload"]; !ok {
		t.Fatalf("expected wrapped payload, got %v", echo)
	}
}

func TestHandleExecuteWithoutMode(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"op":"noop"}`))
	rr := httptest.NewRecorder()
	handleExecute(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := body["mode"]; ok {
		t.Fatalf("did not expect mode in response, got %v", body["mode"])
	}
}

func TestToolEnvHelpers(t *testing.T) {
	t.Setenv("TOOL_ENV_STRING", "value")
	if got := env("TOOL_ENV_STRING", "default"); got != "value" {
		t.Fatalf("expected env value, got %q", got)
	}
	if got := env("TOOL_ENV_MISSING", "default"); got != "default" {
		t.Fatalf("expected default value, got %q", got)
	}

	t.Setenv("TOOL_ENV_INT", "12")
	if got := envInt("TOOL_ENV_INT", 1); got != 12 {
		t.Fatalf("expected 12, got %d", got)
	}
	t.Setenv("TOOL_ENV_INT", "bad")
	if got := envInt("TOOL_ENV_INT", 5); got != 5 {
		t.Fatalf("expected fallback 5, got %d", got)
	}
	t.Setenv("TOOL_ENV_INT", "11")
	if got := envDurationSec("TOOL_ENV_INT", 3); got.Seconds() != 11 {
		t.Fatalf("expected duration 11s from env, got %v", got)
	}
	t.Setenv("TOOL_ENV_INT", "bad")
	if got := envDurationSec("TOOL_ENV_INT", 3); got.Seconds() != 3 {
		t.Fatalf("expected fallback duration 3s, got %v", got)
	}
}

func TestRunToolMock(t *testing.T) {
	t.Run("telemetry init error", func(t *testing.T) {
		err := runToolMock(
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
		t.Setenv("ADDR", ":19085")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "7")
		t.Setenv("HTTP_READ_TIMEOUT_SEC", "11")
		t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "13")
		t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "17")

		captured := &http.Server{}
		err := runToolMock(
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
		if captured.Addr != ":19085" {
			t.Fatalf("expected addr :19085, got %q", captured.Addr)
		}
		if captured.ReadHeaderTimeout.Seconds() != 7 ||
			captured.ReadTimeout.Seconds() != 11 ||
			captured.WriteTimeout.Seconds() != 13 ||
			captured.IdleTimeout.Seconds() != 17 {
			t.Fatalf("unexpected timeout config: %+v", captured)
		}

		healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		healthRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(healthRR, healthReq)
		if healthRR.Code != http.StatusOK || !strings.Contains(healthRR.Body.String(), `"service":"tool-mock"`) {
			t.Fatalf("expected healthz response, got %d body=%s", healthRR.Code, healthRR.Body.String())
		}

		execReq := httptest.NewRequest(http.MethodPost, "/execute", strings.NewReader(`{"payload":{"op":"simulate"}}`))
		execRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(execRR, execReq)
		if execRR.Code != http.StatusOK || !strings.Contains(execRR.Body.String(), `"status":"ok"`) {
			t.Fatalf("expected execute response, got %d body=%s", execRR.Code, execRR.Body.String())
		}
	})
}
