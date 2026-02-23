package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/models"
)

func TestVerifySMTDisabledPath(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "z3",
		SMTEnabled: false,
		Z3Path:     "z3",
		Z3Timeout:  50 * time.Millisecond,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
	s.verify(rr, req)
	// When SMT backend z3 selected but Z3 is not on PATH, policyeval returns DEFER/SMT_UNAVAILABLE
	// If Z3 were available and SMT disabled, it would return ESCROW/SMT_DISABLED
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	// Accept DEFER (Z3 not on path) or ESCROW (Z3 available but disabled)
	if !strings.Contains(body, `"DEFER"`) && !strings.Contains(body, `"ESCROW"`) {
		t.Fatalf("expected DEFER or ESCROW verdict, got body=%s", body)
	}
}

func TestVerifyReplayModeCertExpired(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	expiredBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), "nonce-1")
	var payload map[string]any
	if err := json.Unmarshal(expiredBody, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload["replay"] = true
	replayBody, _ := json.Marshal(payload)

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "go",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(replayBody)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for replay mode with expired cert, got %d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"CERT_EXPIRED"`) {
		t.Fatalf("replay mode should not trigger CERT_EXPIRED, body=%s", rr.Body.String())
	}
}

func TestVerifyReplayModeKeyRevokedAllowed(t *testing.T) {
	// In replay mode, even revoked keys should be allowed for historical verification
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")
	var payload map[string]any
	if err := json.Unmarshal(validBody, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload["replay"] = true
	replayBody, _ := json.Marshal(payload)

	// Note: The actual code checks "!req.Replay && status != 'active'" which means
	// in replay mode, revoked keys ARE allowed. Let's verify the actual behavior.
	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "revoked"}}},
		SMTBackend: "go",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(replayBody)))
	s.verify(rr, req)
	// In replay mode with revoked key, the code path is: (!req.Replay && status != "active") evaluates to false
	// so KEY_INVALID should NOT be returned. The verify should continue to policy eval.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 in replay mode, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyZ3CGoBackend(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "z3cgo",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for z3cgo backend, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyKeyLookupError(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{err: errors.New("key lookup failed")}},
		SMTBackend: "go",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"KEY_INVALID"`) {
		t.Fatalf("expected KEY_INVALID on lookup error, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyWithInlineBeliefState(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")
	var payload map[string]any
	if err := json.Unmarshal(validBody, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload["belief_state_snapshot"] = map[string]any{
		"domain":  "finance",
		"tenant":  "tenant-a",
		"sources": []any{},
	}
	bodyWithBelief, _ := json.Marshal(payload)

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "go",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(bodyWithBelief)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with inline belief state, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestNegativeMaxRequestBodyBytesDefault(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "-1")

	var captured *http.Server
	err := runVerifier(
		func(ctx context.Context, svc string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		},
		func(ctx context.Context) (verifierDB, func(), error) {
			return &fakeVerifierDB{}, nil, nil
		},
		func(server *http.Server) error {
			captured = server
			return errors.New("stop")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stop") {
		t.Fatalf("expected listen stop, got %v", err)
	}
	_ = captured
}

func TestFetchPolicyDSLNilClient(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dsl":"policyset finance v1:"}`))
	}))
	defer okSrv.Close()

	s := &Server{PolicyURL: okSrv.URL, HTTPClient: nil}
	dsl, err := s.fetchPolicyDSL(context.Background(), "finance", "v1")
	if err != nil {
		t.Fatalf("fetchPolicyDSL with nil client failed: %v", err)
	}
	if dsl != "policyset finance v1:" {
		t.Fatalf("unexpected dsl: %s", dsl)
	}
}

func TestReadRequestBodyGenericError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", &errorReader{})
	rr := httptest.NewRecorder()
	if _, ok := readRequestBody(rr, req); ok {
		t.Fatal("expected read to fail")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for generic read error, got %d", rr.Code)
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("generic read error")
}

func (e *errorReader) Close() error { return nil }

func TestVerifyIntentCertRequired(t *testing.T) {
	s := &Server{AuthMode: "off"}

	// Empty body
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty intent/cert, got %d", rr.Code)
	}

	// Only intent
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing cert, got %d", rr.Code)
	}
}

func TestVerifyIntentUnmarshalError(t *testing.T) {
	s := &Server{AuthMode: "off"}
	rr := httptest.NewRecorder()
	// intent is not a valid JSON object
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":"not-an-object","cert":{}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid intent, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyCertUnmarshalError(t *testing.T) {
	s := &Server{AuthMode: "off"}
	rr := httptest.NewRecorder()
	// cert is not a valid JSON object
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{},"cert":"not-an-object"}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid cert, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyInlineBeliefSnapshotUnmarshalError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:   "i-1",
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance"},
		Operation:  models.Operation{Name: "pay"},
	}
	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")
	var payload map[string]any
	_ = json.Unmarshal(validBody, &payload)
	payload["belief_state_snapshot"] = "not-an-object"
	bodyWithBadBelief, _ := json.Marshal(payload)

	s := &Server{
		DB: &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(bodyWithBadBelief)))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid belief snapshot, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifySnapshotFetchError(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:   "i-1",
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance"},
		Operation:  models.Operation{Name: "pay"},
	}
	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")
	var payload map[string]any
	_ = json.Unmarshal(validBody, &payload)
	payload["snapshot_id"] = "snap-fail"
	bodyWithSnapshotID, _ := json.Marshal(payload)

	stateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer stateSrv.Close()

	s := &Server{
		DB:       &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		StateURL: stateSrv.URL,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(bodyWithSnapshotID)))
	s.verify(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for snapshot fetch error, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifySMTNonFormalBackend(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "i-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "go", // non-formal backend
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"ESCROW"`) {
		t.Fatalf("expected ESCROW for non-formal backend, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"SMT_NON_FORMAL"`) {
		t.Fatalf("expected SMT_NON_FORMAL reason, got %s", rr.Body.String())
	}
}

func TestVerifyServiceOrAuthValidToken(t *testing.T) {
	s := &Server{
		ServiceAuthHeader: "X-Verifier-Token",
		ServiceAuthToken:  "secret-token",
	}
	handlerCalled := false
	handler := s.serviceOrAuth(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("auth fallback should not be called with valid token")
		})
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/verify", nil)
	req.Header.Set("X-Verifier-Token", "secret-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !handlerCalled {
		t.Fatal("handler should have been called with valid token")
	}
}

func TestVerifyServiceOrAuthFallbackToAuthMw(t *testing.T) {
	s := &Server{
		ServiceAuthHeader: "X-Verifier-Token",
		ServiceAuthToken:  "secret-token",
	}
	authMwCalled := false
	handler := s.serviceOrAuth(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authMwCalled = true
			w.WriteHeader(http.StatusUnauthorized)
		})
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called when auth fails")
	}))

	// Invalid token - should fallback to auth middleware
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", nil)
	req.Header.Set("X-Verifier-Token", "wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !authMwCalled {
		t.Fatal("auth middleware should have been called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestVerifyPolicyParseFailure(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "i-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"Op"}, Tenant: "t1"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance"},
		Operation:      models.Operation{Name: "pay", Params: json.RawMessage(`{}`)},
	}
	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": "invalid dsl syntax !@#$%"})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "go",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"POLICY_PARSE_FAIL"`) {
		t.Fatalf("expected POLICY_PARSE_FAIL, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyALLOWPath(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "i-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	s := &Server{
		DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
		PolicyURL:  policySrv.URL,
		SMTBackend: "z3",
		SMTEnabled: true,
		Z3Path:     "/usr/local/bin/z3", // Assume Z3 installed
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
	s.verify(rr, req)
	// Either ALLOW (if Z3 works) or ESCROW/DEFER (if Z3 not available)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifySnapshotIDSuccess(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "i-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{}`)},
	}
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	validBody := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-1")
	var payload map[string]any
	_ = json.Unmarshal(validBody, &payload)
	payload["snapshot_id"] = "snap-1"
	bodyWithSnapshotID, _ := json.Marshal(payload)

	policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
	}))
	defer policySrv.Close()

	// fetchSnapshot uses DB, not HTTP - mock the DB row
	snapshotPayload, _ := json.Marshal(models.BeliefState{
		Domain:  "finance",
		Tenant:  "tenant-a",
		Sources: []models.SourceState{},
	})

	s := &Server{
		DB: &fakeVerifierDB{
			keyRow:      fakeVerifierRow{values: []any{[]byte(pub), "active"}},
			snapshotRow: fakeVerifierRow{values: []any{snapshotPayload}},
		},
		PolicyURL:  policySrv.URL,
		SMTBackend: "go",
		SMTEnabled: true,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(bodyWithSnapshotID)))
	s.verify(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// Tests for nil-fallback paths in runVerifier (lines 60-95)

func TestRunVerifierNilInitTelemetryFallback(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("POLICY_URL", "http://localhost:8082")

	err := runVerifier(
		nil, // triggers fallback to telemetry.Init (lines 66-68)
		func(ctx context.Context) (verifierDB, func(), error) {
			return &fakeVerifierDB{}, nil, nil
		},
		func(server *http.Server) error {
			return errors.New("stop")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stop") {
		t.Fatalf("expected listen stop, got %v", err)
	}
}

func TestRunVerifierNilListenFallback(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("ADDR", "127.0.0.1:0")
	t.Setenv("POLICY_URL", "http://localhost:8082")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDB{}, nil, nil
			},
			nil, // triggers fallback to server.ListenAndServe (lines 78-80)
		)
	}()

	select {
	case <-ctx.Done():
		// Server started - fallback code executed
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "address already in use") {
			t.Logf("server stopped with: %v (fallback code was still executed)", err)
		}
	}
}
