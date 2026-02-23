package openclaw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"axiom/pkg/models"
	"axiom/pkg/rta"
)

type mockGateway struct {
	mu       sync.Mutex
	calls    int
	response models.GatewayResponse
}

func (m *mockGateway) ExecuteTool(ctx context.Context, req GatewayExecuteRequest) (models.GatewayResponse, error) {
	m.mu.Lock()
	m.calls++
	resp := m.response
	m.mu.Unlock()
	return resp, nil
}

func (m *mockGateway) ListEscrows(ctx context.Context, limit int, status string) (json.RawMessage, error) {
	return json.RawMessage(`{"items":[]}`), nil
}

func (m *mockGateway) ApproveEscrow(ctx context.Context, escrowID, approver string) (json.RawMessage, error) {
	return json.RawMessage(`{"status":"APPROVED"}`), nil
}

func (m *mockGateway) ExecuteEscrow(ctx context.Context, escrowID string) (json.RawMessage, error) {
	return json.RawMessage(`{"status":"CLOSED"}`), nil
}

func TestAdapterIdempotencyAndReplay(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	_ = pub
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := Config{
		GatewayURL:                 "http://gateway.local",
		PolicySetID:                "finance",
		PolicyVersion:              "v1",
		SignerKid:                  "kid-1",
		SignerName:                 "adapter",
		PrivateKeyB64:              base64.StdEncoding.EncodeToString(priv),
		DefaultActorID:             "agent",
		DefaultTenant:              "acme",
		DefaultRoles:               []string{"FinanceOperator"},
		DefaultWorkspace:           "finance",
		DefaultSafetyMode:          "STRICT",
		DefaultActionType:          "TOOL_CALL",
		DefaultMaxStalenessSec:     20,
		CertTTL:                    90 * time.Second,
		ReplayTTL:                  5 * time.Minute,
		MissingRollbackForceEscrow: true,
	}
	signer, err := LoadSigner(cfg)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	gateway := &mockGateway{response: models.GatewayResponse{Verdict: rta.VerdictAllow, ReasonCode: "OK", Result: json.RawMessage(`{"ok":true}`)}}
	adapter := NewAdapter(cfg, gateway, signer, nil)
	now := time.Date(2026, 2, 22, 10, 0, 0, 0, time.UTC)
	adapter.timeNow = func() time.Time { return now }

	req := InvokeRequest{
		Tool:           "openclaw.send",
		IdempotencyKey: "idem-1",
		Nonce:          "nonce-1",
		Args:           json.RawMessage(`{"to":"+1555","message":"hi"}`),
		Payload:        json.RawMessage(`{"op":"simulate"}`),
		RollbackPlan:   &models.Rollback{Type: "COMPENSATING_ACTION", Steps: []string{"{\"op\":\"undo\"}"}},
	}
	resp1, err := adapter.HandleInvocation(context.Background(), req)
	if err != nil {
		t.Fatalf("first call err: %v", err)
	}
	if !resp1.OK || resp1.Verdict != rta.VerdictAllow {
		t.Fatalf("expected first call ALLOW, got %#v", resp1)
	}
	resp2, err := adapter.HandleInvocation(context.Background(), req)
	if err != nil {
		t.Fatalf("second call err: %v", err)
	}
	if !resp2.OK || resp2.Verdict != rta.VerdictAllow {
		t.Fatalf("expected second call ALLOW, got %#v", resp2)
	}
	if gateway.calls != 1 {
		t.Fatalf("expected single upstream call due idempotency cache, got %d", gateway.calls)
	}

	conflict := req
	conflict.IdempotencyKey = "idem-2"
	conflictResp, err := adapter.HandleInvocation(context.Background(), conflict)
	if err != nil {
		t.Fatalf("conflict call err: %v", err)
	}
	if conflictResp.Verdict != rta.VerdictDeny || conflictResp.ReasonCode != "REPLAY_DETECTED" {
		t.Fatalf("expected replay deny, got %#v", conflictResp)
	}
}

func TestAdapterDeferReleasesNonce(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cfg := Config{
		PolicySetID:            "finance",
		PolicyVersion:          "v1",
		SignerKid:              "kid-1",
		SignerName:             "adapter",
		PrivateKeyB64:          base64.StdEncoding.EncodeToString(priv),
		DefaultActorID:         "agent",
		DefaultTenant:          "acme",
		DefaultRoles:           []string{"Viewer"},
		DefaultWorkspace:       "finance",
		DefaultSafetyMode:      "NORMAL",
		DefaultActionType:      "TOOL_CALL",
		DefaultMaxStalenessSec: 20,
		CertTTL:                60 * time.Second,
		ReplayTTL:              60 * time.Second,
	}
	signer, err := LoadSigner(cfg)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	gateway := &mockGateway{response: models.GatewayResponse{Verdict: rta.VerdictDefer, ReasonCode: "VERIFY_TIMEOUT", RetryAfterMS: 10}}
	adapter := NewAdapter(cfg, gateway, signer, nil)
	req := InvokeRequest{Tool: "openclaw.send", IdempotencyKey: "idem-1", Nonce: "same-nonce", Payload: json.RawMessage(`{"op":"simulate"}`)}
	resp1, err := adapter.HandleInvocation(context.Background(), req)
	if err != nil {
		t.Fatalf("first defer err: %v", err)
	}
	if resp1.Verdict != rta.VerdictDefer {
		t.Fatalf("expected DEFER, got %#v", resp1)
	}
	req.IdempotencyKey = "idem-2"
	resp2, err := adapter.HandleInvocation(context.Background(), req)
	if err != nil {
		t.Fatalf("second defer err: %v", err)
	}
	if resp2.Verdict != rta.VerdictDefer {
		t.Fatalf("expected second DEFER, got %#v", resp2)
	}
	if gateway.calls != 2 {
		t.Fatalf("expected second upstream call after nonce release, got %d", gateway.calls)
	}
}
