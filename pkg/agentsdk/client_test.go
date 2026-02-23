package agentsdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/models"
)

func TestComputeIntentHashDeterministic(t *testing.T) {
	intent := models.ActionIntent{
		IntentID:       "i1",
		IdempotencyKey: "k1",
		Actor:          models.Actor{ID: "a", Roles: []string{"r"}, Tenant: "t"},
		ActionType:     "TOOL_CALL",
		Target: models.Target{
			Domain:      "finance",
			ObjectTypes: []string{"Invoice"},
			ObjectIDs:   []string{"inv-1"},
			Scope:       "single",
		},
		Operation: models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"1.00"}`)},
	}
	h1, err := ComputeIntentHash(intent, "v1", "n1")
	if err != nil {
		t.Fatalf("hash1: %v", err)
	}
	h2, err := ComputeIntentHash(intent, "v1", "n1")
	if err != nil {
		t.Fatalf("hash2: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("hash mismatch %s vs %s", h1, h2)
	}
}

func TestBindAndSignCert(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := Signer{Kid: "kid-1", SignerName: "agent-1", PrivateKey: priv}
	intent := models.ActionIntent{
		IntentID:       "i1",
		IdempotencyKey: "k1",
		Actor:          models.Actor{ID: "a", Roles: []string{"r"}, Tenant: "t"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"1.00"}`)},
	}
	cert := models.ActionCert{
		PolicySetID:   "finance",
		PolicyVersion: "v1",
		Nonce:         "nonce-1",
	}
	now := time.Date(2026, 2, 4, 12, 0, 0, 0, time.UTC)
	if err := BindAndSignCert(intent, &cert, signer, 120*time.Second, now); err != nil {
		t.Fatalf("bind sign: %v", err)
	}
	if cert.IntentHash == "" {
		t.Fatal("intent hash is empty")
	}
	if cert.Signature.Kid != "kid-1" || cert.Signature.Alg != "ed25519" || cert.Signature.Sig == "" {
		t.Fatalf("unexpected signature payload: %+v", cert.Signature)
	}
	if cert.ExpiresAt != "2026-02-04T12:02:00Z" {
		t.Fatalf("unexpected expires_at: %s", cert.ExpiresAt)
	}
	if err := auth.VerifyEd25519(priv.Public().(ed25519.PublicKey), cert); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
}

func TestNewSignerFromBase64(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := NewSignerFromBase64("kid-1", "agent", base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	if s.Kid != "kid-1" {
		t.Fatalf("kid mismatch: %s", s.Kid)
	}
}

func TestExecuteTool(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tool/execute" {
			t.Fatalf("unexpected route %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(models.GatewayResponse{Verdict: "ALLOW", ReasonCode: "OK"})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, time.Second)
	resp, err := c.ExecuteTool(context.Background(), ExecuteRequest{})
	if err != nil {
		t.Fatalf("execute tool: %v", err)
	}
	if resp.Verdict != "ALLOW" {
		t.Fatalf("unexpected verdict: %s", resp.Verdict)
	}
}

func TestComputeIntentHashRejectsFloatTokens(t *testing.T) {
	intent := models.ActionIntent{
		IntentID:       "i1",
		IdempotencyKey: "k1",
		Actor:          models.Actor{ID: "a", Roles: []string{"r"}, Tenant: "t"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":1.1}`)},
	}
	if _, err := ComputeIntentHash(intent, "v1", "nonce"); err == nil {
		t.Fatal("expected error for floating JSON number token")
	}
}

func TestNewSignerFromBase64Errors(t *testing.T) {
	if _, err := NewSignerFromBase64("kid-1", "agent", "%%%"); err == nil {
		t.Fatal("expected base64 decode error")
	}
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := NewSignerFromBase64("kid-1", "agent", short); err == nil {
		t.Fatal("expected private key length error")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := NewSignerFromBase64("", "agent", base64.StdEncoding.EncodeToString(priv)); err == nil {
		t.Fatal("expected missing kid error")
	}
}

func TestBindAndSignCertErrors(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := Signer{Kid: "kid-1", SignerName: "agent-1", PrivateKey: priv}
	intent := models.ActionIntent{
		IntentID:       "i1",
		IdempotencyKey: "k1",
		Actor:          models.Actor{ID: "a", Roles: []string{"r"}, Tenant: "t"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"1.00"}`)},
	}

	if err := BindAndSignCert(intent, nil, signer, 0, time.Time{}); err == nil {
		t.Fatal("expected nil cert error")
	}
	cert := models.ActionCert{PolicyVersion: "", PolicySetID: "finance", Nonce: "n1"}
	if err := BindAndSignCert(intent, &cert, signer, 0, time.Time{}); err == nil {
		t.Fatal("expected missing policy version error")
	}
	cert = models.ActionCert{PolicyVersion: "v1", PolicySetID: "", Nonce: "n1"}
	if err := BindAndSignCert(intent, &cert, signer, 0, time.Time{}); err == nil {
		t.Fatal("expected missing policy set id error")
	}
	cert = models.ActionCert{PolicyVersion: "v1", PolicySetID: "finance", Nonce: ""}
	if err := BindAndSignCert(intent, &cert, signer, 0, time.Time{}); err == nil {
		t.Fatal("expected missing nonce error")
	}
}

func TestExecuteOntologyVerifyApproveAndErrorPaths(t *testing.T) {
	var sawApproveWithoutAuth bool
	var sawApproveWithAuth bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ontology/actions/execute":
			if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
				t.Fatalf("expected auth header, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(models.GatewayResponse{Verdict: "ALLOW", ReasonCode: "OK"})
		case "/v1/verify":
			if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
				t.Fatalf("expected auth header, got %q", got)
			}
			_ = json.NewEncoder(w).Encode(models.VerifierResponse{Verdict: "ALLOW", ReasonCode: "OK"})
		case "/v1/escrow/approve":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode approve payload: %v", err)
			}
			if r.Header.Get("Authorization") == "" {
				if payload["approver"] != "alice" {
					t.Fatalf("expected approver in payload when auth missing")
				}
				sawApproveWithoutAuth = true
			} else {
				if _, ok := payload["approver"]; ok {
					t.Fatalf("approver must be omitted when auth token is set")
				}
				sawApproveWithAuth = true
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "APPROVED"})
		case "/v1/fail":
			http.Error(w, "boom", http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := NewClient(ts.URL, time.Second)
	client.AuthToken = "token-1"

	resp, err := client.ExecuteOntology(context.Background(), ExecuteRequest{})
	if err != nil {
		t.Fatalf("execute ontology: %v", err)
	}
	if resp.Verdict != "ALLOW" {
		t.Fatalf("unexpected execute ontology verdict: %s", resp.Verdict)
	}

	verifyResp, err := client.Verify(context.Background(), models.ActionIntent{}, models.ActionCert{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verifyResp.Verdict != "ALLOW" {
		t.Fatalf("unexpected verify verdict: %s", verifyResp.Verdict)
	}

	if _, err := client.ApproveEscrow(context.Background(), "e1", "alice"); err != nil {
		t.Fatalf("approve with auth token: %v", err)
	}
	if !sawApproveWithAuth {
		t.Fatal("expected approve with auth branch")
	}

	clientNoAuth := NewClient(ts.URL, time.Second)
	if _, err := clientNoAuth.ApproveEscrow(context.Background(), "e1", "alice"); err != nil {
		t.Fatalf("approve without auth token: %v", err)
	}
	if !sawApproveWithoutAuth {
		t.Fatal("expected approve without auth branch")
	}

	_, err = client.execute(context.Background(), "/v1/fail", ExecuteRequest{})
	if err == nil || !strings.Contains(err.Error(), "status=400") {
		t.Fatalf("expected execute status error, got %v", err)
	}
}

func TestHTTPClientFallbackAndInvalidJSONResponses(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tool/execute":
			_, _ = w.Write([]byte("{invalid-json"))
		case "/v1/verify":
			_, _ = w.Write([]byte("{invalid-json"))
		case "/v1/escrow/approve":
			_, _ = w.Write([]byte("{invalid-json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := &Client{BaseURL: ts.URL}
	if c.httpClient() == nil {
		t.Fatal("expected fallback http client")
	}
	if _, err := c.ExecuteTool(context.Background(), ExecuteRequest{}); err == nil {
		t.Fatal("expected execute tool JSON unmarshal error")
	}
	if _, err := c.Verify(context.Background(), models.ActionIntent{}, models.ActionCert{}); err == nil {
		t.Fatal("expected verify JSON unmarshal error")
	}
	if _, err := c.ApproveEscrow(context.Background(), "e1", "approver"); err == nil {
		t.Fatal("expected approve JSON unmarshal error")
	}
}

func TestVerifyRequestBuildError(t *testing.T) {
	c := &Client{BaseURL: "://bad"}
	_, err := c.Verify(context.Background(), models.ActionIntent{}, models.ActionCert{})
	if err == nil {
		t.Fatal("expected request build error for bad base url")
	}
	if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "missing protocol scheme") {
		t.Fatalf("expected url/request error, got %v", err)
	}
}
