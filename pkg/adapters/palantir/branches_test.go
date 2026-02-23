package palantir

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFoundryOntologyExecutorBranches(t *testing.T) {
	t.Run("base_url_required", func(t *testing.T) {
		exec := FoundryOntologyExecutor{}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{}`)); err == nil {
			t.Fatal("expected empty base url error")
		}
	})

	t.Run("invalid_payload", func(t *testing.T) {
		exec := FoundryOntologyExecutor{BaseURL: "https://example.com"}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{bad`)); err == nil {
			t.Fatal("expected invalid payload json error")
		}
	})

	t.Run("ontology_and_action_required", func(t *testing.T) {
		exec := FoundryOntologyExecutor{BaseURL: "https://example.com"}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{"action":"run"}`)); err == nil || !strings.Contains(err.Error(), "ontology is required") {
			t.Fatalf("expected ontology required error, got %v", err)
		}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{"ontology":"finance"}`)); err == nil || !strings.Contains(err.Error(), "action is required") {
			t.Fatalf("expected action required error, got %v", err)
		}
	})

	t.Run("dry_run_disabled", func(t *testing.T) {
		exec := FoundryOntologyExecutor{
			BaseURL:      "https://example.com",
			AllowDryRun:  false,
			AllowPreview: false,
		}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{"ontology":"finance","action":"pay","mode":"READ_ONLY"}`)); err == nil {
			t.Fatal("expected dry-run disabled error")
		}
	})

	t.Run("batch_disabled", func(t *testing.T) {
		exec := FoundryOntologyExecutor{
			BaseURL:     "https://example.com",
			AllowBatch:  false,
			AllowDryRun: true,
		}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{"ontology":"finance","action":"pay","batch":[{"id":"1"}]}`)); err == nil {
			t.Fatal("expected batch disabled error")
		}
	})

	t.Run("upstream_non_2xx", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer ts.Close()
		exec := FoundryOntologyExecutor{
			BaseURL:     ts.URL,
			AllowBatch:  true,
			AllowDryRun: true,
		}
		_, err := exec.Execute(context.Background(), json.RawMessage(`{"ontology":"finance","action":"pay","parameters":{"x":"1"}}`))
		if err == nil || !strings.Contains(err.Error(), "foundry upstream error") {
			t.Fatalf("expected non-2xx upstream error, got %v", err)
		}
	})

	t.Run("args_fallback_and_header_injection", func(t *testing.T) {
		var authHeader string
		var customHeader string
		var reqBody map[string]interface{}
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader = r.Header.Get("Authorization")
			customHeader = r.Header.Get("X-Custom")
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer ts.Close()

		dryRun := false
		previewOnly := true
		exec := FoundryOntologyExecutor{
			Client:       nil,
			BaseURL:      ts.URL,
			Token:        "token-1",
			OntologyID:   "finance",
			Headers:      map[string]string{"X-Custom": "yes"},
			Retries:      1,
			RetryDelay:   5 * time.Millisecond,
			AllowBatch:   true,
			AllowDryRun:  true,
			AllowPreview: true,
		}
		payload := map[string]interface{}{
			"action_name":  "pay",
			"args":         map[string]interface{}{"amount": "10.00"},
			"dry_run":      &dryRun,
			"preview_only": &previewOnly,
		}
		raw, _ := json.Marshal(payload)
		if _, err := exec.Execute(context.Background(), raw); err != nil {
			t.Fatalf("expected foundry execute success, got %v", err)
		}
		if authHeader != "Bearer token-1" {
			t.Fatalf("expected Authorization header injection, got %q", authHeader)
		}
		if customHeader != "yes" {
			t.Fatalf("expected custom header propagation, got %q", customHeader)
		}
		if reqBody["previewOnly"] != true {
			t.Fatalf("expected previewOnly=true in body, got %#v", reqBody["previewOnly"])
		}
		if reqBody["dryRun"] != nil {
			t.Fatalf("expected dryRun to be absent/false with explicit override, got %#v", reqBody["dryRun"])
		}
	})
}

func TestHTTPExecutorBranches(t *testing.T) {
	t.Run("endpoint_required", func(t *testing.T) {
		exec := HTTPExecutor{}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{}`)); err == nil {
			t.Fatal("expected endpoint required error")
		}
	})

	t.Run("default_client_request_error", func(t *testing.T) {
		exec := HTTPExecutor{Endpoint: "http://127.0.0.1:1", Retries: 0}
		if _, err := exec.Execute(context.Background(), json.RawMessage(`{}`)); err == nil {
			t.Fatal("expected request error with unreachable endpoint")
		}
	})
}
