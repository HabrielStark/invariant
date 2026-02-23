package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/models"
	"axiom/pkg/policyeval"
	"axiom/pkg/policyir"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeVerifierDB struct {
	execErr      error
	snapshotRow  pgx.Row
	policyRow    pgx.Row
	keyRow       pgx.Row
	lastQuerySQL string
	lastArgs     []any
}

func (f *fakeVerifierDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	_ = ctx
	_ = sql
	_ = args
	return pgconn.NewCommandTag("INSERT 0 1"), f.execErr
}

func (f *fakeVerifierDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	_ = ctx
	f.lastQuerySQL = sql
	f.lastArgs = append([]any(nil), args...)
	if strings.Contains(sql, "belief_snapshots") {
		if f.snapshotRow != nil {
			return f.snapshotRow
		}
		return fakeVerifierRow{err: errors.New("snapshot row not configured")}
	}
	if strings.Contains(sql, "policy_versions") {
		if f.policyRow != nil {
			return f.policyRow
		}
		return fakeVerifierRow{err: errors.New("policy row not configured")}
	}
	if f.keyRow != nil {
		return f.keyRow
	}
	return fakeVerifierRow{err: errors.New("key row not configured")}
}

type fakeVerifierKeyStore struct {
	record *auth.KeyRecord
	err    error
}

func (f fakeVerifierKeyStore) GetKey(ctx context.Context, kid string) (*auth.KeyRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.record, nil
}

type fakeVerifierRow struct {
	values []any
	err    error
}

func (r fakeVerifierRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("scan arity mismatch: got=%d want=%d", len(dest), len(r.values))
	}
	for i := range dest {
		if err := assignVerifierScan(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

func assignVerifierScan(dest any, value any) error {
	switch d := dest.(type) {
	case *[]byte:
		switch v := value.(type) {
		case []byte:
			*d = append((*d)[:0], v...)
		case string:
			*d = append((*d)[:0], []byte(v)...)
		default:
			return fmt.Errorf("expected []byte/string, got %T", value)
		}
		return nil
	case *string:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		*d = v
		return nil
	case **time.Time:
		switch v := value.(type) {
		case nil:
			*d = nil
		case time.Time:
			vv := v
			*d = &vv
		case *time.Time:
			if v == nil {
				*d = nil
			} else {
				vv := *v
				*d = &vv
			}
		default:
			return fmt.Errorf("expected time.Time/*time.Time/nil, got %T", value)
		}
		return nil
	default:
		return fmt.Errorf("unsupported destination %T", dest)
	}
}

func buildSignedVerifyBody(t *testing.T, priv ed25519.PrivateKey, intent models.ActionIntent, policySetID, policyVersion, kid, expiresAt, nonce string) []byte {
	t.Helper()
	intentRaw, err := json.Marshal(intent)
	if err != nil {
		t.Fatalf("marshal intent: %v", err)
	}
	canonical, err := models.CanonicalizeJSON(intentRaw)
	if err != nil {
		t.Fatalf("canonicalize intent: %v", err)
	}
	cert := models.ActionCert{
		PolicySetID:   policySetID,
		PolicyVersion: policyVersion,
		ExpiresAt:     expiresAt,
		Nonce:         nonce,
		IntentHash:    models.IntentHash(canonical, policyVersion, nonce),
		Signature: models.Signature{
			Kid:    kid,
			Signer: "verifier-test",
			Alg:    "ed25519",
		},
	}
	payload, err := auth.SignaturePayload(cert)
	if err != nil {
		t.Fatalf("signature payload: %v", err)
	}
	cert.Signature.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	reqBody, err := json.Marshal(map[string]any{
		"intent": intent,
		"cert":   cert,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return reqBody
}

func TestFindShield(t *testing.T) {
	ax := policyir.Axiom{
		ID:         "Batch_safety",
		ElseShield: `shield("SMALL_BATCH", max=100)`,
	}
	sh := policyeval.ShieldFromAxiom(ax)
	if sh == nil {
		t.Fatal("expected shield")
	}
	if sh.Type != "SMALL_BATCH" {
		t.Fatalf("expected SMALL_BATCH, got %s", sh.Type)
	}
}

func TestFindShieldNil(t *testing.T) {
	ax := policyir.Axiom{
		ID:         "Role_guard",
		ElseShield: "",
	}
	if policyeval.ShieldFromAxiom(ax) != nil {
		t.Fatal("expected nil")
	}
}

func TestFetchPolicyDSLTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(25 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"dsl":"policyset finance v1:"}`))
	}))
	defer srv.Close()

	s := &Server{
		PolicyURL:  srv.URL,
		HTTPClient: &http.Client{Timeout: 5 * time.Millisecond},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := s.fetchPolicyDSL(ctx, "finance", "v1"); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestFetchPolicyDSLNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing", http.StatusNotFound)
	}))
	defer srv.Close()

	s := &Server{PolicyURL: srv.URL, HTTPClient: &http.Client{Timeout: 50 * time.Millisecond}}
	if _, err := s.fetchPolicyDSL(context.Background(), "finance", "v9"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestCertExpiredEdges(t *testing.T) {
	now := time.Date(2026, 2, 5, 10, 0, 0, 0, time.UTC)
	expired, err := certExpired(now, now.Add(-time.Second).Format(time.RFC3339))
	if err != nil || !expired {
		t.Fatalf("expected expired=true, err=%v", err)
	}
	expired, err = certExpired(now, now.Format(time.RFC3339))
	if err != nil || expired {
		t.Fatalf("expected expired=false for equal time, err=%v", err)
	}
	expired, err = certExpired(now, now.Add(time.Second).Format(time.RFC3339))
	if err != nil || expired {
		t.Fatalf("expected expired=false for future, err=%v", err)
	}
}

func TestServiceTokenValid(t *testing.T) {
	s := &Server{
		ServiceAuthHeader: "X-Test-Token",
		ServiceAuthToken:  "secret-token",
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", nil)
	req.Header.Set("X-Test-Token", "secret-token")
	if !s.serviceTokenValid(req) {
		t.Fatal("expected service token to be valid")
	}
	req.Header.Set("X-Test-Token", "wrong")
	if s.serviceTokenValid(req) {
		t.Fatal("expected mismatched token to be rejected")
	}
}

func TestServiceTokenValidMissingConfigAndHeader(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", nil)
	if s.serviceTokenValid(req) {
		t.Fatal("expected token invalid when service auth config is missing")
	}

	s = &Server{
		ServiceAuthHeader: "X-Test-Token",
		ServiceAuthToken:  "secret-token",
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", nil)
	if s.serviceTokenValid(req) {
		t.Fatal("expected token invalid when request header is missing")
	}
}

func TestReadRequestBodyTooLarge(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", io.NopCloser(strings.NewReader(`{"x":"`+strings.Repeat("a", 2048)+`"}`)))
	rr := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rr, req.Body, 128)
	if _, ok := readRequestBody(rr, req); ok {
		t.Fatal("expected oversized body to be rejected")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestFetchPolicyDSLOkAndInvalidJSON(t *testing.T) {
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dsl":"policyset finance v1:"}`))
	}))
	defer okSrv.Close()

	s := &Server{PolicyURL: okSrv.URL}
	dsl, err := s.fetchPolicyDSL(context.Background(), "finance", "v1")
	if err != nil {
		t.Fatalf("fetchPolicyDSL failed: %v", err)
	}
	if dsl != "policyset finance v1:" {
		t.Fatalf("unexpected dsl: %s", dsl)
	}

	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer badSrv.Close()
	s.PolicyURL = badSrv.URL
	if _, err := s.fetchPolicyDSL(context.Background(), "finance", "v1"); err == nil {
		t.Fatal("expected decode error for invalid json")
	}
}

func TestFetchPolicyDSLFromDBWindowEnforcement(t *testing.T) {
	now := time.Date(2026, 2, 10, 12, 0, 0, 0, time.UTC)
	future := now.Add(2 * time.Hour)
	db := &fakeVerifierDB{
		policyRow: fakeVerifierRow{values: []any{"policyset finance v1:", "PUBLISHED", future, nil}},
	}
	s := &Server{DB: db}
	if _, err := s.fetchPolicyDSLAt(context.Background(), "finance", "v1", now, false); !errors.Is(err, errPolicyNotActive) {
		t.Fatalf("expected errPolicyNotActive, got %v", err)
	}
	dsl, err := s.fetchPolicyDSLAt(context.Background(), "finance", "v1", now, true)
	if err != nil {
		t.Fatalf("expected replay to allow inactive policy, got %v", err)
	}
	if dsl != "policyset finance v1:" {
		t.Fatalf("unexpected dsl: %s", dsl)
	}
}

func TestServiceOrAuth(t *testing.T) {
	s := &Server{
		ServiceAuthHeader: "X-Verifier-Token",
		ServiceAuthToken:  "secret",
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", nil)
	req.Header.Set("X-Verifier-Token", "secret")
	var called bool
	authMw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	handler := s.serviceOrAuth(authMw)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || !called {
		t.Fatalf("expected service-token bypass, code=%d called=%v", rr.Code, called)
	}
}

func TestVerifierMiddlewareAndEnvHelpers(t *testing.T) {
	s := &Server{MaxRequestBodyBytes: 8}
	handler := s.limitRequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"x":"0123456789"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}

	t.Setenv("VERIFIER_TEST_ENV", "x")
	if got := env("VERIFIER_TEST_ENV", "y"); got != "x" {
		t.Fatalf("unexpected env: %s", got)
	}
	if got := env("VERIFIER_TEST_MISSING", "y"); got != "y" {
		t.Fatalf("unexpected env fallback: %s", got)
	}
	t.Setenv("VERIFIER_TEST_INT", "5")
	if got := envInt("VERIFIER_TEST_INT", 1); got != 5 {
		t.Fatalf("unexpected envInt: %d", got)
	}
	t.Setenv("VERIFIER_TEST_INT_BAD", "bad")
	if got := envInt("VERIFIER_TEST_INT_BAD", 7); got != 7 {
		t.Fatalf("unexpected envInt fallback: %d", got)
	}
	t.Setenv("VERIFIER_TEST_DUR", "3")
	if got := envDurationSec("VERIFIER_TEST_DUR", 1); got != 3*time.Second {
		t.Fatalf("unexpected envDurationSec: %s", got)
	}
}

func TestRunVerifier(t *testing.T) {
	t.Run("telemetry_init_error", func(t *testing.T) {
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return nil, errors.New("otel failed")
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDB{}, func() {}, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "otel failed") {
			t.Fatalf("expected telemetry init error, got %v", err)
		}
	})

	t.Run("db_open_error", func(t *testing.T) {
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return nil, nil, errors.New("db failed")
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "db failed") {
			t.Fatalf("expected db open error, got %v", err)
		}
	})

	t.Run("auth_off_blocked_without_override", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "false")
		closed := false
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDB{}, func() { closed = true }, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "AUTH_MODE=off is disabled") {
			t.Fatalf("expected auth-off guard error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback to run on auth guard failure")
		}
	})

	t.Run("auth_off_forbidden_in_production_like_env", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("ENVIRONMENT", "production")
		closed := false
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDB{}, func() { closed = true }, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "production-like") {
			t.Fatalf("expected production-like auth-off guard error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback to run on startup guard failure")
		}
	})

	t.Run("strict_production_hardening_requires_db_tls", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "oidc_hs256")
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("STRICT_PROD_SECURITY", "true")
		t.Setenv("DATABASE_REQUIRE_TLS", "false")
		closed := false
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDB{}, func() { closed = true }, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "DATABASE_REQUIRE_TLS=true") {
			t.Fatalf("expected strict prod DB TLS error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback to run on startup hardening failure")
		}
	})

	t.Run("server_config_and_routes", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "oidc_hs256")
		t.Setenv("ADDR", ":19081")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "7")
		t.Setenv("HTTP_READ_TIMEOUT_SEC", "11")
		t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "13")
		t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "17")
		t.Setenv("VERIFIER_AUTH_HEADER", "X-Internal-Token")
		t.Setenv("VERIFIER_AUTH_TOKEN", "internal-secret")

		closed := false
		captured := &http.Server{}
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDB{}, func() { closed = true }, nil
			},
			func(server *http.Server) error {
				captured = server
				return errors.New("listen stop")
			},
		)
		if err == nil || !strings.Contains(err.Error(), "listen stop") {
			t.Fatalf("expected listen error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback after listen returns")
		}
		if captured.Addr != ":19081" {
			t.Fatalf("expected addr :19081, got %q", captured.Addr)
		}
		if captured.ReadHeaderTimeout != 7*time.Second ||
			captured.ReadTimeout != 11*time.Second ||
			captured.WriteTimeout != 13*time.Second ||
			captured.IdleTimeout != 17*time.Second {
			t.Fatalf("unexpected timeout config: %+v", captured)
		}

		healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		healthRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(healthRR, healthReq)
		if healthRR.Code != http.StatusOK || !strings.Contains(healthRR.Body.String(), `"service":"verifier"`) {
			t.Fatalf("expected healthz response, got %d body=%s", healthRR.Code, healthRR.Body.String())
		}

		verifyReq := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{bad`))
		verifyReq.Header.Set("X-Internal-Token", "internal-secret")
		verifyRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(verifyRR, verifyReq)
		if verifyRR.Code != http.StatusBadRequest {
			t.Fatalf("expected verify invalid-json response via service auth path, got %d body=%s", verifyRR.Code, verifyRR.Body.String())
		}
	})
}

func TestCertExpiredErrors(t *testing.T) {
	if _, err := certExpired(time.Now(), ""); err == nil {
		t.Fatal("expected error for empty expires_at")
	}
	if _, err := certExpired(time.Now(), "not-a-date"); err == nil {
		t.Fatal("expected error for invalid expires_at")
	}
}

func TestVerifyValidationPaths(t *testing.T) {
	s := &Server{}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{bad`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{},"cert":{}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing intent/cert raw content, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay","params":{"amount":1.25}}},"cert":{"policy_set_id":"ps","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z","nonce":"n1"}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for numeric json in intent, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"","policy_version":"","expires_at":"","nonce":""}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing required cert fields, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"ps","policy_version":"v1","expires_at":"bad","nonce":"n1"}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid expires_at, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"ps","policy_version":"v1","expires_at":"2020-01-01T00:00:00Z","nonce":"n1"}}`))
	s.verify(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"CERT_EXPIRED"`) {
		t.Fatalf("expected CERT_EXPIRED response, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestVerifyBeliefSnapshotAndHashMismatch(t *testing.T) {
	s := &Server{}
	intent := json.RawMessage(`{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}}`)
	cert := json.RawMessage(`{"policy_set_id":"ps","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z","nonce":"nonce-1","intent_hash":"mismatch"}`)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":`+string(intent)+`,"cert":`+string(cert)+`,"belief_state_snapshot":"bad"}`))
	s.verify(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid belief snapshot, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":`+string(intent)+`,"cert":`+string(cert)+`}`))
	s.verify(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"INTENT_HASH_MISMATCH"`) {
		t.Fatalf("expected hash mismatch deny, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestFetchSnapshotAndLookupKey(t *testing.T) {
	now := time.Date(2026, 2, 6, 10, 0, 0, 0, time.UTC)
	payload, _ := json.Marshal(models.BeliefState{
		SnapshotID: "snap-1",
		Tenant:     "tenant-a",
		Domain:     "finance",
		Sources: []models.SourceState{
			{Source: "bank", AgeSec: 1, HealthScore: 0.99, LagSec: 1, JitterSec: 0},
		},
		CreatedAt: now.Format(time.RFC3339),
	})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	db := &fakeVerifierDB{
		snapshotRow: fakeVerifierRow{values: []any{payload}},
		keyRow:      fakeVerifierRow{values: []any{[]byte(pub), "active"}},
	}
	s := &Server{DB: db}
	got, err := s.fetchSnapshot(context.Background(), "snap-1")
	if err != nil {
		t.Fatalf("fetchSnapshot: %v", err)
	}
	if got.Domain != "finance" || got.SnapshotID != "snap-1" {
		t.Fatalf("unexpected snapshot: %+v", got)
	}
	pk, status, err := s.lookupKey(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("lookupKey: %v", err)
	}
	if status != "active" || len(pk) == 0 {
		t.Fatalf("unexpected key lookup result: status=%s len(pk)=%d", status, len(pk))
	}
	extPub := make([]byte, ed25519.PublicKeySize)
	extPub[0] = 9
	s.ExternalKeyStore = fakeVerifierKeyStore{
		record: &auth.KeyRecord{
			Kid:       "kid-vault",
			PublicKey: extPub,
			Status:    "active",
		},
	}
	db.keyRow = fakeVerifierRow{err: pgx.ErrNoRows}
	pk, status, err = s.lookupKey(context.Background(), "kid-vault")
	if err != nil || status != "active" || len(pk) != ed25519.PublicKeySize || pk[0] != 9 {
		t.Fatalf("external key lookup failed status=%s len=%d err=%v", status, len(pk), err)
	}

	db.snapshotRow = fakeVerifierRow{values: []any{[]byte("{bad-json")}}
	if _, err := s.fetchSnapshot(context.Background(), "snap-bad"); err == nil {
		t.Fatal("expected snapshot json decode error")
	}
	db.snapshotRow = fakeVerifierRow{err: errors.New("missing")}
	if _, err := s.fetchSnapshot(context.Background(), "snap-missing"); err == nil {
		t.Fatal("expected snapshot db error")
	}
	if _, _, err := s.lookupKey(context.Background(), ""); err == nil {
		t.Fatal("expected kid required error")
	}
}

func TestVerifyRuntimeBranches(t *testing.T) {
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
	goodDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	t.Run("key_invalid", func(t *testing.T) {
		s := &Server{
			DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "revoked"}}},
			SMTBackend: "go",
			SMTEnabled: true,
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
		s.verify(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"KEY_INVALID"`) {
			t.Fatalf("expected KEY_INVALID, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_signature", func(t *testing.T) {
		var payload map[string]any
		if err := json.Unmarshal(validBody, &payload); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		cert := payload["cert"].(map[string]any)
		signature := cert["signature"].(map[string]any)
		signature["sig"] = "invalid-signature"
		badSigBody, _ := json.Marshal(payload)

		s := &Server{
			DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
			SMTBackend: "go",
			SMTEnabled: true,
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(badSigBody)))
		s.verify(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"BAD_SIGNATURE"`) {
			t.Fatalf("expected BAD_SIGNATURE, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("policy_unavailable", func(t *testing.T) {
		policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "missing", http.StatusNotFound)
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
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"POLICY_UNAVAILABLE"`) {
			t.Fatalf("expected POLICY_UNAVAILABLE, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("policy_parse_fail", func(t *testing.T) {
		policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"dsl":"not a valid policy dsl"}`))
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
	})

	t.Run("smt_non_formal", func(t *testing.T) {
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
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
		s.verify(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"SMT_NON_FORMAL"`) {
			t.Fatalf("expected SMT_NON_FORMAL, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("smt_unavailable", func(t *testing.T) {
		policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
		}))
		defer policySrv.Close()
		s := &Server{
			DB:         &fakeVerifierDB{keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
			PolicyURL:  policySrv.URL,
			SMTBackend: "z3",
			SMTEnabled: true,
			Z3Path:     "/definitely/missing/z3",
			Z3Timeout:  10 * time.Millisecond,
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(validBody)))
		s.verify(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"SMT_UNAVAILABLE"`) {
			t.Fatalf("expected SMT_UNAVAILABLE, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("snapshot_fetch_failed", func(t *testing.T) {
		policySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{"dsl": goodDSL})
		}))
		defer policySrv.Close()
		var payload map[string]any
		if err := json.Unmarshal(validBody, &payload); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		payload["snapshot_id"] = "snap-missing"
		bodyWithSnapshot, _ := json.Marshal(payload)

		s := &Server{
			DB:         &fakeVerifierDB{snapshotRow: fakeVerifierRow{err: errors.New("missing")}, keyRow: fakeVerifierRow{values: []any{[]byte(pub), "active"}}},
			PolicyURL:  policySrv.URL,
			SMTBackend: "go",
			SMTEnabled: true,
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(bodyWithSnapshot)))
		s.verify(rr, req)
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "snapshot fetch failed") {
			t.Fatalf("expected snapshot fetch failure, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestBuildExternalKeyStore(t *testing.T) {
	t.Run("db_provider", func(t *testing.T) {
		ks, err := buildExternalKeyStore(http.DefaultClient, "db", "", "", "", "", "", time.Second, 0, 0)
		if err != nil || ks != nil {
			t.Fatalf("expected nil keystore for db provider, ks=%v err=%v", ks, err)
		}
	})
	t.Run("vault_provider_requires_addr_and_token", func(t *testing.T) {
		if _, err := buildExternalKeyStore(http.DefaultClient, "vault_transit", "", "tok", "", "transit", "", time.Second, 0, 0); err == nil {
			t.Fatal("expected VAULT_ADDR validation error")
		}
		if _, err := buildExternalKeyStore(http.DefaultClient, "vault_transit", "http://vault", "", "", "transit", "", time.Second, 0, 0); err == nil {
			t.Fatal("expected VAULT_TOKEN validation error")
		}
	})
	t.Run("unsupported_provider", func(t *testing.T) {
		if _, err := buildExternalKeyStore(http.DefaultClient, "unsupported", "", "", "", "", "", time.Second, 0, 0); err == nil {
			t.Fatal("expected unsupported provider error")
		}
	})
}

func TestVerifyPolicyStatusAndWindowReasons(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	intent := models.ActionIntent{
		IntentID:       "intent-policy",
		IdempotencyKey: "idem-policy",
		Actor:          models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", Scope: "single"},
		Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	body := buildSignedVerifyBody(t, priv, intent, "finance", "v1", "kid-1", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), "nonce-policy")

	t.Run("policy_unpublished", func(t *testing.T) {
		db := &fakeVerifierDB{
			keyRow:    fakeVerifierRow{values: []any{[]byte(pub), "active"}},
			policyRow: fakeVerifierRow{values: []any{"policyset finance v1:", "DRAFT", nil, nil}},
		}
		s := &Server{DB: db, SMTBackend: "z3", SMTEnabled: true}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(body)))
		s.verify(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"POLICY_UNPUBLISHED"`) {
			t.Fatalf("expected POLICY_UNPUBLISHED, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("policy_inactive", func(t *testing.T) {
		future := time.Now().Add(2 * time.Hour).UTC()
		db := &fakeVerifierDB{
			keyRow:    fakeVerifierRow{values: []any{[]byte(pub), "active"}},
			policyRow: fakeVerifierRow{values: []any{"policyset finance v1:", "PUBLISHED", future, nil}},
		}
		s := &Server{DB: db, SMTBackend: "z3", SMTEnabled: true}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(string(body)))
		s.verify(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"POLICY_INACTIVE"`) {
			t.Fatalf("expected POLICY_INACTIVE, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}
