package openclaw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/rta"
)

func TestLoadConfigFromEnvAndHelpers(t *testing.T) {
	t.Setenv("INVARIANT_GATEWAY_URL", "http://gateway.local")
	t.Setenv("OPENCLAW_POLICY_SET_ID", "ops")
	t.Setenv("OPENCLAW_POLICY_VERSION", "v7")
	t.Setenv("OPENCLAW_SIGNER_KID", "kid-x")
	t.Setenv("OPENCLAW_SIGNER_NAME", "adapter-x")
	t.Setenv("OPENCLAW_SIGNER_PRIVATE_KEY_PATH", "/tmp/key")
	t.Setenv("OPENCLAW_SIGNER_PRIVATE_KEY_B64", "  abc  ")
	t.Setenv("OPENCLAW_DEFAULT_ACTOR_ID", "actor-x")
	t.Setenv("OPENCLAW_DEFAULT_TENANT", "tenant-x")
	t.Setenv("OPENCLAW_DEFAULT_ROLES", "Admin, Viewer , ,")
	t.Setenv("OPENCLAW_DEFAULT_WORKSPACE", "ws-x")
	t.Setenv("OPENCLAW_DEFAULT_SAFETY_MODE", "strict")
	t.Setenv("OPENCLAW_DEFAULT_ACTION_TYPE", "ontology_action")
	t.Setenv("OPENCLAW_MAX_STALENESS_DEFAULT_SEC", "-1")
	t.Setenv("OPENCLAW_MAX_STALENESS_BY_OPERATION", "send=10,bad,noeq=,neg=-1")
	t.Setenv("OPENCLAW_CERT_TTL_SEC", "0")
	t.Setenv("OPENCLAW_REPLAY_TTL_SEC", "0")
	t.Setenv("OPENCLAW_MISSING_ROLLBACK_FORCE_ESCROW", "off")
	t.Setenv("OPENCLAW_SIDE_EFFECT_FREE_OPS", "health,Read")
	t.Setenv("OPENCLAW_FORCE_ESCROW_OPS", "send,agent")
	t.Setenv("INVARIANT_GATEWAY_AUTH_HEADER", "X-Token")
	t.Setenv("INVARIANT_GATEWAY_AUTH_TOKEN", "secret-token")
	t.Setenv("OPENCLAW_REQUEST_TIMEOUT_MS", "0")

	cfg := LoadConfigFromEnv()
	if cfg.GatewayURL != "http://gateway.local" {
		t.Fatalf("unexpected gateway url: %q", cfg.GatewayURL)
	}
	if cfg.PolicySetID != "ops" || cfg.PolicyVersion != "v7" {
		t.Fatalf("unexpected policy: %q/%q", cfg.PolicySetID, cfg.PolicyVersion)
	}
	if cfg.SignerKid != "kid-x" || cfg.SignerName != "adapter-x" {
		t.Fatalf("unexpected signer metadata: %q/%q", cfg.SignerKid, cfg.SignerName)
	}
	if cfg.PrivateKeyPath != "/tmp/key" || cfg.PrivateKeyB64 != "abc" {
		t.Fatalf("unexpected key settings: path=%q b64=%q", cfg.PrivateKeyPath, cfg.PrivateKeyB64)
	}
	if cfg.DefaultActorID != "actor-x" || cfg.DefaultTenant != "tenant-x" || cfg.DefaultWorkspace != "ws-x" {
		t.Fatalf("unexpected actor defaults: %#v", cfg)
	}
	if len(cfg.DefaultRoles) != 2 || cfg.DefaultRoles[0] != "Admin" || cfg.DefaultRoles[1] != "Viewer" {
		t.Fatalf("unexpected roles: %#v", cfg.DefaultRoles)
	}
	if cfg.DefaultSafetyMode != "STRICT" || cfg.DefaultActionType != "ONTOLOGY_ACTION" {
		t.Fatalf("unexpected mode/action: %q %q", cfg.DefaultSafetyMode, cfg.DefaultActionType)
	}
	if cfg.DefaultMaxStalenessSec != 30 {
		t.Fatalf("expected stale fallback 30, got %d", cfg.DefaultMaxStalenessSec)
	}
	if got := cfg.MaxStalenessByOperation["send"]; got != 10 {
		t.Fatalf("expected per-op staleness 10, got %d", got)
	}
	if cfg.CertTTL != 120*time.Second || cfg.ReplayTTL != 5*time.Minute {
		t.Fatalf("unexpected ttl fallbacks: cert=%s replay=%s", cfg.CertTTL, cfg.ReplayTTL)
	}
	if cfg.RequestTimeout != 5*time.Second {
		t.Fatalf("unexpected timeout fallback: %s", cfg.RequestTimeout)
	}
	if cfg.MissingRollbackForceEscrow {
		t.Fatalf("expected rollback-force-escrow false when env=off")
	}
	if _, ok := cfg.SideEffectFreeOps["health"]; !ok {
		t.Fatalf("missing side effect free op: health")
	}
	if _, ok := cfg.SideEffectFreeOps["read"]; !ok {
		t.Fatalf("missing side effect free op: read")
	}
	if _, ok := cfg.EscrowOnOps["send"]; !ok {
		t.Fatalf("missing escrow op: send")
	}
	if cfg.AuthHeader != "X-Token" || cfg.AuthToken != "secret-token" {
		t.Fatalf("unexpected auth settings: %q/%q", cfg.AuthHeader, cfg.AuthToken)
	}
	if normalizeSafetyMode("bad-mode") != "NORMAL" {
		t.Fatalf("unexpected safety normalize fallback")
	}
	if normalizeActionType("bad-action") != "TOOL_CALL" {
		t.Fatalf("unexpected action normalize fallback")
	}
}

func TestParseInvokeRequestAliases(t *testing.T) {
	raw := []byte(`{
		"toolName":"openclaw.send",
		"operation":"openclaw.send",
		"arguments":{"to":"+1555"},
		"parameters":{"message":"hi"},
		"idempotencyKey":"idem-1",
		"agentId":"agent-1",
		"workspace":"tenant-a",
		"requestTime":"2026-02-22T10:00:00Z",
		"eventTime":"2026-02-22T10:00:01Z",
		"safetyMode":"STRICT",
		"actionType":"TOOL_CALL",
		"nonce":"nonce-1",
		"expiresAt":"2026-02-22T10:02:00Z",
		"rollbackPlan":{"type":"COMPENSATING_ACTION","steps":["{\"op\":\"undo\"}"]},
		"maxStalenessSec":42,
		"sideEffecting":true,
		"tool_payload":{"op":"simulate"}
	}`)
	req, err := ParseInvokeRequest(raw)
	if err != nil {
		t.Fatalf("parse invoke request: %v", err)
	}
	if req.Tool != "openclaw.send" || req.Command != "openclaw.send" {
		t.Fatalf("unexpected tool/command: %q/%q", req.Tool, req.Command)
	}
	if req.IdempotencyKey != "idem-1" || req.ActorID != "agent-1" {
		t.Fatalf("unexpected id/actor: %q/%q", req.IdempotencyKey, req.ActorID)
	}
	if req.Tenant != "tenant-a" || req.Workspace != "tenant-a" {
		t.Fatalf("unexpected tenant/workspace: %q/%q", req.Tenant, req.Workspace)
	}
	if req.RequestTime == "" || req.EventTime == "" || req.SafetyMode != "STRICT" {
		t.Fatalf("unexpected time/safety fields: %#v", req)
	}
	if req.ActionType != "TOOL_CALL" || req.Nonce != "nonce-1" || req.ExpiresAt == "" {
		t.Fatalf("unexpected action/nonce/expiry: %#v", req)
	}
	if req.MaxStalenessSec == nil || *req.MaxStalenessSec != 42 {
		t.Fatalf("unexpected max staleness: %#v", req.MaxStalenessSec)
	}
	if req.SideEffecting == nil || !*req.SideEffecting {
		t.Fatalf("unexpected side_effecting: %#v", req.SideEffecting)
	}
	if req.RollbackPlan == nil || req.RollbackPlan.Type != "COMPENSATING_ACTION" {
		t.Fatalf("unexpected rollback: %#v", req.RollbackPlan)
	}
	if string(req.Payload) == "" || !strings.Contains(string(req.Payload), "simulate") {
		t.Fatalf("unexpected payload: %s", string(req.Payload))
	}
	if string(req.Args) == "" || !strings.Contains(string(req.Args), "+1555") {
		t.Fatalf("unexpected args: %s", string(req.Args))
	}
	if string(req.Params) == "" || !strings.Contains(string(req.Params), "hi") {
		t.Fatalf("unexpected params: %s", string(req.Params))
	}

	if _, err := ParseInvokeRequest([]byte(`{"tool":`)); err == nil {
		t.Fatalf("expected invalid json parse error")
	}
}

func TestEncodeInvokeResponse(t *testing.T) {
	resp := InvokeResponse{
		OK:         true,
		Verdict:    rta.VerdictAllow,
		ReasonCode: "OK",
		Result:     json.RawMessage(`{"ok":true}`),
	}
	encoded := EncodeInvokeResponse(resp)
	if !json.Valid(encoded) {
		t.Fatalf("encoded response is not valid json: %s", string(encoded))
	}
	if !strings.Contains(string(encoded), `"verdict":"ALLOW"`) {
		t.Fatalf("encoded response missing verdict: %s", string(encoded))
	}
}

func TestHTTPGatewayClientSuccessAndFailures(t *testing.T) {
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Auth") == "token-123" {
			sawAuth = true
		}
		switch r.URL.Path {
		case "/v1/tool/execute":
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			_, _ = w.Write([]byte(`{"verdict":"ALLOW","reason_code":"OK","result":{"ok":true}}`))
		case "/v1/escrows":
			if r.URL.Query().Get("limit") != "5" || r.URL.Query().Get("status") != "PENDING" {
				http.Error(w, "bad query", http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"items":[{"escrow_id":"e1"}]}`))
		case "/v1/escrow/approve":
			_, _ = w.Write([]byte(`{"status":"APPROVED"}`))
		case "/v1/escrow/execute":
			_, _ = w.Write([]byte(`{"status":"CLOSED"}`))
		case "/fail":
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := Config{
		GatewayURL:     srv.URL + "/",
		RequestTimeout: time.Second,
		AuthHeader:     "X-Test-Auth",
		AuthToken:      "token-123",
	}
	client := NewHTTPGatewayClient(cfg)

	allow, err := client.ExecuteTool(context.Background(), GatewayExecuteRequest{
		Intent: json.RawMessage(`{"intent_id":"i1"}`),
		Cert:   json.RawMessage(`{"cert_id":"c1"}`),
	})
	if err != nil {
		t.Fatalf("execute tool: %v", err)
	}
	if allow.Verdict != rta.VerdictAllow || allow.ReasonCode != "OK" {
		t.Fatalf("unexpected gateway response: %#v", allow)
	}
	if !sawAuth {
		t.Fatalf("expected auth header to be forwarded")
	}

	escrows, err := client.ListEscrows(context.Background(), 5, "PENDING")
	if err != nil {
		t.Fatalf("list escrows: %v", err)
	}
	if !strings.Contains(string(escrows), `"escrow_id":"e1"`) {
		t.Fatalf("unexpected escrows response: %s", string(escrows))
	}

	approved, err := client.ApproveEscrow(context.Background(), "e1", "manager-1")
	if err != nil {
		t.Fatalf("approve escrow: %v", err)
	}
	if !strings.Contains(string(approved), "APPROVED") {
		t.Fatalf("unexpected approve response: %s", string(approved))
	}

	executed, err := client.ExecuteEscrow(context.Background(), "e1")
	if err != nil {
		t.Fatalf("execute escrow: %v", err)
	}
	if !strings.Contains(string(executed), "CLOSED") {
		t.Fatalf("unexpected execute response: %s", string(executed))
	}

	client.BaseURL = srv.URL
	_, status, err := client.doJSON(context.Background(), http.MethodGet, srv.URL+"/fail", nil)
	if err != nil {
		t.Fatalf("doJSON error for 500 response should be nil, got: %v", err)
	}
	if status != http.StatusInternalServerError {
		t.Fatalf("unexpected status from doJSON: %d", status)
	}

	client.BaseURL = "://bad-url"
	_, err = client.ExecuteTool(context.Background(), GatewayExecuteRequest{Intent: json.RawMessage(`{}`), Cert: json.RawMessage(`{}`)})
	if err == nil {
		t.Fatalf("expected execute tool error for invalid base url")
	}
}

func TestAdapterMetricsAccessor(t *testing.T) {
	adapter := NewAdapter(Config{}, nil, Signer{}, nil)
	if adapter.Metrics() == nil {
		t.Fatalf("expected metrics registry")
	}
}
