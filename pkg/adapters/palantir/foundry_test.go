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

func TestFoundryOntologyExecutorApply(t *testing.T) {
	var gotPath string
	var gotBody map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	exec := FoundryOntologyExecutor{
		Client:      &http.Client{Timeout: time.Second},
		BaseURL:     ts.URL,
		OntologyID:  "",
		AllowBatch:  true,
		AllowDryRun: true,
	}
	payload := map[string]interface{}{
		"ontology":   "finance",
		"action":     "pay_invoice",
		"parameters": map[string]interface{}{"amount": "10.00"},
		"mode":       "DRY_RUN",
	}
	raw, _ := json.Marshal(payload)
	if _, err := exec.Execute(context.Background(), raw); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v2/ontologies/finance/actions/pay_invoice/apply" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if gotBody["dryRun"] != true {
		t.Fatalf("expected dryRun true, got %#v", gotBody["dryRun"])
	}
	params, ok := gotBody["parameters"].(map[string]interface{})
	if !ok || params["amount"] != "10.00" {
		t.Fatalf("unexpected parameters: %#v", gotBody["parameters"])
	}
}

func TestFoundryOntologyExecutorBatch(t *testing.T) {
	var gotPath string
	var gotBody map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	exec := FoundryOntologyExecutor{
		Client:     &http.Client{Timeout: time.Second},
		BaseURL:    ts.URL,
		AllowBatch: true,
	}
	payload := map[string]interface{}{
		"ontology": "supply",
		"action":   "change_status",
		"batch": []map[string]interface{}{
			{"id": "a1", "status": "OK"},
			{"id": "a2", "status": "OK"},
		},
	}
	raw, _ := json.Marshal(payload)
	if _, err := exec.Execute(context.Background(), raw); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotPath != "/api/v2/ontologies/supply/actions/change_status/applyBatch" {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	requests, ok := gotBody["requests"].([]interface{})
	if !ok || len(requests) != 2 {
		t.Fatalf("unexpected requests: %#v", gotBody["requests"])
	}
	if !strings.Contains(strings.ToLower(gotBody["requests"].([]interface{})[0].(map[string]interface{})["parameters"].(map[string]interface{})["status"].(string)), "ok") {
		t.Fatalf("unexpected request payload: %#v", gotBody["requests"])
	}
}
