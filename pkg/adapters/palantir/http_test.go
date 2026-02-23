package palantir

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPExecutorExecute(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer ts.Close()
	exec := HTTPExecutor{
		Endpoint:   ts.URL,
		Retries:    1,
		RetryDelay: 10 * time.Millisecond,
	}
	out, err := exec.Execute(context.Background(), json.RawMessage(`{"a":1}`))
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if parsed["status"] != "ok" {
		t.Fatalf("unexpected response: %v", parsed)
	}
}

func TestHTTPExecutorErrorsOnNon2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer ts.Close()
	exec := HTTPExecutor{Endpoint: ts.URL}
	_, err := exec.Execute(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error")
	}
}
