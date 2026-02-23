package openclaw

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMapInvocationDeterministic(t *testing.T) {
	cfg := Config{
		DefaultActorID:          "agent-main",
		DefaultTenant:           "acme",
		DefaultRoles:            []string{"FinanceOperator"},
		DefaultWorkspace:        "finance",
		DefaultSafetyMode:       "NORMAL",
		DefaultActionType:       "TOOL_CALL",
		DefaultMaxStalenessSec:  30,
		MaxStalenessByOperation: map[string]int{"openclaw.send": 15},
		PolicyVersion:           "v1",
		CertTTL:                 2 * time.Minute,
	}
	now := time.Date(2026, 2, 22, 10, 11, 12, 0, time.UTC)
	req := InvokeRequest{
		Tool:           "openclaw.send",
		IdempotencyKey: "idem-123",
		Args: json.RawMessage(`{
			"message":"hello",
			"api_key":"top-secret",
			"amount":12.25,
			"to":"+15550001111"
		}`),
		Roles:      []string{"Viewer"},
		ActorID:    "agent-a",
		Tenant:     "tenant-a",
		Workspace:  "finance",
		SafetyMode: "STRICT",
	}
	first, err := MapInvocation(cfg, req, now)
	if err != nil {
		t.Fatalf("map first: %v", err)
	}
	second, err := MapInvocation(cfg, req, now)
	if err != nil {
		t.Fatalf("map second: %v", err)
	}
	if string(first.IntentRawCanonical) != string(second.IntentRawCanonical) {
		t.Fatalf("intent canonicalization must be deterministic\nfirst=%s\nsecond=%s", string(first.IntentRawCanonical), string(second.IntentRawCanonical))
	}
	if first.Nonce != second.Nonce {
		t.Fatalf("nonce must be deterministic for same input: %s != %s", first.Nonce, second.Nonce)
	}
	if first.Intent.ActionType != "TOOL_CALL" {
		t.Fatalf("expected TOOL_CALL, got %s", first.Intent.ActionType)
	}
	if first.Intent.Operation.Name != "openclaw.send" {
		t.Fatalf("unexpected op name: %s", first.Intent.Operation.Name)
	}
	if first.Intent.SafetyMode != "STRICT" {
		t.Fatalf("unexpected safety mode: %s", first.Intent.SafetyMode)
	}
	if first.Intent.DataRequirements.MaxStalenessSec != 15 {
		t.Fatalf("expected per-op max staleness, got %d", first.Intent.DataRequirements.MaxStalenessSec)
	}
	var params map[string]interface{}
	if err := json.Unmarshal(first.Intent.Operation.Params, &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	if got := params["api_key"]; got != "<redacted>" {
		t.Fatalf("expected redacted api_key, got %v", got)
	}
	if got := params["amount"]; got != "12.25" {
		t.Fatalf("expected decimal serialized as string for determinism, got %#v", got)
	}
	if first.Intent.Time.RequestTime != "2026-02-22T10:11:12Z" {
		t.Fatalf("unexpected request time: %s", first.Intent.Time.RequestTime)
	}
}
