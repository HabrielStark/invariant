package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/escrowfsm"
	"axiom/pkg/models"
	"axiom/pkg/store"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type failingSetNXCache struct {
	inner store.Cache
}

func (c failingSetNXCache) SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	return false, errors.New("redis unavailable")
}

func (c failingSetNXCache) Get(ctx context.Context, key string) (string, error) {
	return c.inner.Get(ctx, key)
}

func (c failingSetNXCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return c.inner.Set(ctx, key, value, ttl)
}

func (c failingSetNXCache) Del(ctx context.Context, key string) error {
	return c.inner.Del(ctx, key)
}

func TestHandleExecuteEarlyValidationBranches(t *testing.T) {
	s := &Server{AuthMode: "off", Cache: store.NewMemoryCache(), DB: &fakeGatewayDB{}}

	t.Run("missing_intent_or_cert", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{}}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "intent and cert required") {
			t.Fatalf("expected missing intent/cert validation, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("numeric_token_rejected", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{
			"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay","params":{"amount":1.25}}},
			"cert":{"policy_set_id":"ps-1","policy_version":"v1"}
		}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected numeric-token validation failure, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid_intent_payload", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{
			"intent":"not-an-object",
			"cert":{"policy_set_id":"ps-1","policy_version":"v1"}
		}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid intent") {
			t.Fatalf("expected invalid intent branch, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid_cert_payload", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{
			"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},
			"cert":"bad-cert"
		}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid cert") {
			t.Fatalf("expected invalid cert branch, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("policy_fields_required", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{
			"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},
			"cert":{"policy_set_id":"","policy_version":""}
		}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "policy_set_id and policy_version required") {
			t.Fatalf("expected policy field validation, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("expires_and_kid_required", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{
			"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},
			"cert":{"policy_set_id":"ps-1","policy_version":"v1"}
		}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "expires_at required") {
			t.Fatalf("expected expires_at validation, got %d body=%s", rr.Code, rr.Body.String())
		}

		rr = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{
			"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},
			"cert":{"policy_set_id":"ps-1","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z","nonce":"n1"}
		}`))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "signature.kid required") {
			t.Fatalf("expected signature.kid validation, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandleExecuteAdditionalBranches(t *testing.T) {
	baseIntent := json.RawMessage(`{
		"intent_id":"i-branch",
		"idempotency_key":"idem-branch",
		"action_type":"TOOL_CALL",
		"actor":{"id":"actor-1","tenant":"tenant-a"},
		"target":{"domain":"finance"},
		"operation":{"name":"pay","params":{"mode":"safe"}}
	}`)
	canonical, err := models.CanonicalizeJSON(baseIntent)
	if err != nil {
		t.Fatalf("canonicalize intent: %v", err)
	}

	makeServer := func() *Server {
		return &Server{
			AuthMode: "off",
			Cache:    store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
		}
	}

	t.Run("abac_policy_unavailable_defer", func(t *testing.T) {
		s := makeServer()
		s.ABACEnabled = true
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			Nonce:         "abac-nonce",
			Signature:     models.Signature{Kid: "kid-1"},
		}
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"ABAC_POLICY_UNAVAILABLE"`) || !strings.Contains(rr.Body.String(), `"verdict":"DEFER"`) {
			t.Fatalf("expected ABAC_POLICY_UNAVAILABLE defer, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("subject_control_unavailable_defer", func(t *testing.T) {
		s := makeServer()
		s.DB = &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM subject_restrictions") {
					return fakeGatewayRow{err: errors.New("db down")}
				}
				return fakeGatewayRow{err: pgx.ErrNoRows}
			},
		}
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			Nonce:         "subject-control-down",
			Signature:     models.Signature{Kid: "kid-1"},
		}
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verdict":"DEFER"`) || !strings.Contains(rr.Body.String(), `"reason_code":"SUBJECT_CONTROL_UNAVAILABLE"`) {
			t.Fatalf("expected SUBJECT_CONTROL_UNAVAILABLE defer, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("expires_at_parse_error", func(t *testing.T) {
		s := makeServer()
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     "bad-time",
			Nonce:         "n1",
			Signature:     models.Signature{Kid: "kid-1"},
		}
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "expires_at must be RFC3339") {
			t.Fatalf("expected expires_at parse validation, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cert_expired_deny", func(t *testing.T) {
		s := makeServer()
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(-time.Minute).Format(time.RFC3339),
			Nonce:         "expired-nonce",
			Signature:     models.Signature{Kid: "kid-1"},
		}
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"CERT_EXPIRED"`) {
			t.Fatalf("expected CERT_EXPIRED deny, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("nonce_required_after_hash_validation", func(t *testing.T) {
		s := makeServer()
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			Nonce:         "",
			IntentHash:    models.IntentHash(canonical, "v1", ""),
			Signature:     models.Signature{Kid: "kid-1"},
		}
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "nonce required") {
			t.Fatalf("expected nonce required validation, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("replay_detected_before_signature_check", func(t *testing.T) {
		s := makeServer()
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			Nonce:         "replay-nonce",
			IntentHash:    models.IntentHash(canonical, "v1", "replay-nonce"),
			Signature:     models.Signature{Kid: "kid-1"},
		}
		_ = s.Cache.Set(context.Background(), scopedNonceKey("tenant-a", "actor-1", cert.Nonce), "1", time.Minute)
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"REPLAY_DETECTED"`) {
			t.Fatalf("expected REPLAY_DETECTED deny, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("replay_store_unavailable_defer", func(t *testing.T) {
		s := makeServer()
		s.Cache = failingSetNXCache{inner: store.NewMemoryCache()}
		cert := models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			Nonce:         "replay-cache-down",
			IntentHash:    models.IntentHash(canonical, "v1", "replay-cache-down"),
			Signature:     models.Signature{Kid: "kid-1"},
		}
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: baseIntent, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"simulate"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verdict":"DEFER"`) || !strings.Contains(rr.Body.String(), `"reason_code":"REPLAY_UNAVAILABLE"`) {
			t.Fatalf("expected REPLAY_UNAVAILABLE defer, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestEscrowAdditionalBranches(t *testing.T) {
	now := time.Now().UTC()

	t.Run("approve_status_not_pending_returns_current", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{values: []any{
					escrowfsm.Executed,
					now.Add(time.Hour),
					1,
					1,
					[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
					[]byte(`{"policy_set_id":"ps-1","policy_version":"v1","signature":{"kid":"k1"}}`),
					[]byte(`{"op":"x"}`),
					"TOOL_CALL",
				}}
			},
		}
		s := &Server{AuthMode: "off", DB: db, Cache: store.NewMemoryCache()}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"mgr-1"}`)))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), escrowfsm.Executed) {
			t.Fatalf("expected passthrough status for non-pending escrow, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_invalid_stored_intent", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{values: []any{
					escrowfsm.Pending,
					now.Add(time.Hour),
					1,
					0,
					[]byte(`{bad`),
					[]byte(`{"policy_set_id":"ps-1","policy_version":"v1","signature":{"kid":"k1"}}`),
					[]byte(`{"op":"x"}`),
					"TOOL_CALL",
				}}
			},
		}
		s := &Server{AuthMode: "off", DB: db, Cache: store.NewMemoryCache()}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"mgr-1"}`)))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "invalid stored intent") {
			t.Fatalf("expected invalid stored intent branch, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_invalid_stored_cert", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{values: []any{
					escrowfsm.Pending,
					now.Add(time.Hour),
					1,
					0,
					[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
					[]byte(`{bad`),
					[]byte(`{"op":"x"}`),
					"TOOL_CALL",
				}}
			},
		}
		s := &Server{AuthMode: "off", DB: db, Cache: store.NewMemoryCache()}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"mgr-1"}`)))
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "invalid stored cert") {
			t.Fatalf("expected invalid stored cert branch, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_sod_violation", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{values: []any{
					escrowfsm.Pending,
					now.Add(time.Hour),
					1,
					0,
					[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
					[]byte(`{"policy_set_id":"ps-1","policy_version":"v1","signature":{"kid":"k1"}}`),
					[]byte(`{"op":"x"}`),
					"TOOL_CALL",
				}}
			},
		}
		s := &Server{AuthMode: "off", DB: db, Cache: store.NewMemoryCache()}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"actor-1"}`)))
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "approver cannot be actor") {
			t.Fatalf("expected SoD denial, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_auth_mode_mismatch", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{values: []any{
					escrowfsm.Pending,
					now.Add(time.Hour),
					1,
					0,
					[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
					[]byte(`{"policy_set_id":"ps-1","policy_version":"v1","signature":{"kid":"k1"}}`),
					[]byte(`{"op":"x"}`),
					"TOOL_CALL",
				}}
			},
		}
		s := &Server{AuthMode: "oidc_hs256", DB: db, Cache: store.NewMemoryCache()}
		req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"alice"}`))
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "bob", Roles: []string{"approver"}, Tenant: "tenant-a"}))
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, req)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "approver must match principal") {
			t.Fatalf("expected approver/principal mismatch denial, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_role_not_permitted_in_auth_mode", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "FROM escrows WHERE tenant=$1 AND escrow_id=$2"):
					return fakeGatewayRow{values: []any{
						escrowfsm.Pending,
						now.Add(time.Hour),
						1,
						0,
						[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
						[]byte(`{"policy_set_id":"ps-1","policy_version":"v1","signature":{"kid":"k1"}}`),
						[]byte(`{"op":"x"}`),
						"TOOL_CALL",
					}}
				case strings.Contains(sql, "SELECT dsl, status FROM policy_versions"):
					return fakeGatewayRow{values: []any{`policyset finance v1:
approvals roles [FinanceManager]
approvals required 1`, "PUBLISHED"}}
				default:
					return fakeGatewayRow{err: pgx.ErrNoRows}
				}
			},
		}
		s := &Server{
			AuthMode:               "oidc_hs256",
			DB:                     db,
			Cache:                  store.NewMemoryCache(),
			PolicyCache:            newPolicyCache(time.Minute),
			PolicyRequirePublished: true,
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"bob"}`))
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "bob",
			Tenant:  "tenant-a",
			Roles:   []string{"operator"},
		}))
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, req)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "approver role not permitted") {
			t.Fatalf("expected approver role denial, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("get_escrow_scoped_success", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{values: []any{
					"esc-1",
					escrowfsm.Pending,
					now,
					now.Add(time.Hour),
					2,
					1,
				}}
			},
		}
		s := &Server{AuthMode: "oidc_hs256", DB: db}
		req := withGatewayURLParams(httptest.NewRequest(http.MethodGet, "/v1/escrow/esc-1", nil), map[string]string{"escrow_id": "esc-1"})
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "u1",
			Tenant:  "tenant-a",
			Roles:   []string{"operator"},
		}))
		rr := httptest.NewRecorder()
		s.getEscrow(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"escrow_id":"esc-1"`) {
			t.Fatalf("expected scoped escrow fetch success, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestParseCIDRsAndAsInt64AdditionalBranches(t *testing.T) {
	cidrs := parseCIDRs(" 10.0.0.0/24, ,2001:db8::1,invalid,172.16.0.1 ")
	if len(cidrs) != 3 {
		t.Fatalf("expected 3 parsed CIDR/IP entries, got %d", len(cidrs))
	}

	if v, ok := asInt64(int64(42)); !ok || v != 42 {
		t.Fatalf("expected int64 conversion success, got v=%d ok=%v", v, ok)
	}
	if _, ok := asInt64("42"); ok {
		t.Fatal("expected unsupported type conversion to fail")
	}
}

func TestRetentionLoopTickBranch(t *testing.T) {
	db := &fakeGatewayDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		},
	}
	s := &Server{
		DB:                db,
		RetentionEnabled:  true,
		RetentionDays:     7,
		RetentionInterval: 5 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.retentionLoop(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retentionLoop did not stop after context cancellation")
	}
}

func TestCancelEscrowScopedBranch(t *testing.T) {
	now := time.Now().UTC()
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			if strings.Contains(sql, "SELECT status FROM escrows WHERE tenant=$1 AND escrow_id=$2") {
				return fakeGatewayRow{values: []any{escrowfsm.Pending}}
			}
			return fakeGatewayRow{err: pgx.ErrNoRows}
		},
	}
	s := &Server{AuthMode: "oidc_hs256", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/cancel", strings.NewReader(`{"escrow_id":"esc-1","actor":"u1"}`))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "u1",
		Tenant:  "tenant-a",
		Roles:   []string{"operator"},
	}))
	rr := httptest.NewRecorder()
	s.cancelEscrow(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), escrowfsm.Cancelled) {
		t.Fatalf("expected scoped cancel success, got %d body=%s", rr.Code, rr.Body.String())
	}

	_ = now
}
