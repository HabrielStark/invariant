package main

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

	"axiom/pkg/adapters/palantir"
	"axiom/pkg/auth"
	"axiom/pkg/escrowfsm"
	"axiom/pkg/metrics"
	"axiom/pkg/models"
	"axiom/pkg/policyir"
	"axiom/pkg/ratelimit"
	"axiom/pkg/rta"
	"axiom/pkg/store"
	"axiom/pkg/stream"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestGatewayLoadPolicyBranches(t *testing.T) {
	t.Run("query_error", func(t *testing.T) {
		s := &Server{
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
		}
		if _, err := s.loadPolicy(context.Background(), "ps-1", "v1"); err == nil {
			t.Fatal("expected query error")
		}
	})

	t.Run("requires_published", func(t *testing.T) {
		s := &Server{
			PolicyRequirePublished: true,
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeGatewayRow{values: []any{"policyset finance v1:", "DRAFT"}}
				},
			},
		}
		if _, err := s.loadPolicy(context.Background(), "ps-1", "v1"); err == nil {
			t.Fatal("expected not published error")
		}
	})

	t.Run("dsl_parse_error", func(t *testing.T) {
		s := &Server{
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeGatewayRow{values: []any{"not a valid dsl", "PUBLISHED"}}
				},
			},
		}
		if _, err := s.loadPolicy(context.Background(), "ps-1", "v1"); err == nil {
			t.Fatal("expected dsl parse error")
		}
	})

	t.Run("success_and_cache_hit", func(t *testing.T) {
		queries := 0
		s := &Server{
			PolicyCache: newPolicyCache(time.Minute),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					queries++
					return fakeGatewayRow{values: []any{"policyset finance v1:", "PUBLISHED"}}
				},
			},
		}
		p1, err := s.loadPolicy(context.Background(), "ps-1", "v1")
		if err != nil || p1 == nil {
			t.Fatalf("expected policy load success, err=%v policy=%#v", err, p1)
		}
		p2, err := s.loadPolicy(context.Background(), "ps-1", "v1")
		if err != nil || p2 == nil {
			t.Fatalf("expected cached policy success, err=%v policy=%#v", err, p2)
		}
		if queries != 1 {
			t.Fatalf("expected single db query due cache hit, got %d", queries)
		}
	})
}

func TestGatewayCheckIdempotencyBranches(t *testing.T) {
	t.Run("empty_key", func(t *testing.T) {
		s := &Server{Cache: store.NewMemoryCache(), DB: &fakeGatewayDB{}}
		if _, ok := s.checkIdempotency(context.Background(), "tenant-a", ""); ok {
			t.Fatal("empty key must not hit idempotency")
		}
	})

	t.Run("cache_invalid_json_falls_back_to_db", func(t *testing.T) {
		s := &Server{
			Cache: store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "SELECT response_json FROM decisions") {
						return fakeGatewayRow{values: []any{[]byte(`{"verdict":"ALLOW","reason_code":"OK"}`)}}
					}
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
		}
		_ = s.Cache.Set(context.Background(), decisionCacheKey("tenant-a", "idem-1"), "{", time.Minute)
		resp, ok := s.checkIdempotency(context.Background(), "tenant-a", "idem-1")
		if !ok || resp.Verdict != "ALLOW" || resp.ReasonCode != "OK" {
			t.Fatalf("expected db fallback response, ok=%v resp=%#v", ok, resp)
		}
	})

	t.Run("db_defer_not_persisted", func(t *testing.T) {
		s := &Server{
			Cache: store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "SELECT response_json FROM decisions") {
						return fakeGatewayRow{values: []any{[]byte(`{"verdict":"DEFER","reason_code":"WAIT"}`)}}
					}
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
		}
		if _, ok := s.checkIdempotency(context.Background(), "tenant-a", "idem-2"); ok {
			t.Fatal("DEFER response must not be reused for idempotency")
		}
	})

	t.Run("db_invalid_json", func(t *testing.T) {
		s := &Server{
			Cache: store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "SELECT response_json FROM decisions") {
						return fakeGatewayRow{values: []any{[]byte("{")}}
					}
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
		}
		if _, ok := s.checkIdempotency(context.Background(), "tenant-a", "idem-3"); ok {
			t.Fatal("invalid stored json must not be treated as idempotent hit")
		}
	})
}

func TestHandleOntologyExecuteBranches(t *testing.T) {
	t.Run("action_type_mismatch", func(t *testing.T) {
		s := &Server{AuthMode: "off", Cache: store.NewMemoryCache(), DB: &fakeGatewayDB{}}
		body := `{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"ps","policy_version":"v1"}}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ontology/execute", strings.NewReader(body))
		s.handleOntologyExecute(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 action_type mismatch, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("idempotency_required", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			Cache:    store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "SELECT dsl, status FROM policy_versions") {
						return fakeGatewayRow{values: []any{"policyset finance v1:", "PUBLISHED"}}
					}
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
		}
		body := `{"intent":{"intent_id":"i-1","action_type":"ONTOLOGY_ACTION","actor":{"id":"actor-1","tenant":"tenant-a"},"target":{"domain":"finance"},"operation":{"name":"update","params":{"mode":"safe"}}},"cert":{"policy_set_id":"ps","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z","signature":{"kid":"kid-1"}},"action_payload":{"op":"update"}}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ontology/execute", strings.NewReader(body))
		s.handleOntologyExecute(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "idempotency_key required") {
			t.Fatalf("expected idempotency validation error, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("key_invalid", func(t *testing.T) {
		intentRaw := json.RawMessage(`{"intent_id":"i-1","idempotency_key":"idem-1","action_type":"ONTOLOGY_ACTION","actor":{"id":"actor-1","tenant":"tenant-a"},"target":{"domain":"finance"},"operation":{"name":"update","params":{"mode":"safe"}}}`)
		cert := buildSignedCert(t, intentRaw, "kid-1", "nonce-key-invalid")

		s := &Server{
			AuthMode: "off",
			Cache:    store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "SELECT dsl, status FROM policy_versions"):
						return fakeGatewayRow{values: []any{"policyset finance v1:", "PUBLISHED"}}
					case strings.Contains(sql, "SELECT response_json FROM decisions"):
						return fakeGatewayRow{err: pgx.ErrNoRows}
					case strings.Contains(sql, "SELECT public_key, status FROM key_registry"):
						return fakeGatewayRow{err: pgx.ErrNoRows}
					default:
						return fakeGatewayRow{err: pgx.ErrNoRows}
					}
				},
			},
		}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ontology/execute", strings.NewReader(buildExecuteBody(intentRaw, cert, json.RawMessage(`{"op":"update"}`))))
		s.handleOntologyExecute(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"KEY_INVALID"`) {
			t.Fatalf("expected KEY_INVALID deny, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_signature", func(t *testing.T) {
		intentRaw := json.RawMessage(`{"intent_id":"i-1","idempotency_key":"idem-2","action_type":"ONTOLOGY_ACTION","actor":{"id":"actor-1","tenant":"tenant-a"},"target":{"domain":"finance"},"operation":{"name":"update","params":{"mode":"safe"}}}`)
		cert := buildSignedCert(t, intentRaw, "kid-1", "nonce-bad-signature")
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}

		s := &Server{
			AuthMode: "off",
			Cache:    store.NewMemoryCache(),
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					switch {
					case strings.Contains(sql, "SELECT dsl, status FROM policy_versions"):
						return fakeGatewayRow{values: []any{"policyset finance v1:", "PUBLISHED"}}
					case strings.Contains(sql, "SELECT response_json FROM decisions"):
						return fakeGatewayRow{err: pgx.ErrNoRows}
					case strings.Contains(sql, "SELECT public_key, status FROM key_registry"):
						return fakeGatewayRow{values: []any{[]byte(pub), "active"}}
					default:
						return fakeGatewayRow{err: pgx.ErrNoRows}
					}
				},
			},
		}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/ontology/execute", strings.NewReader(buildExecuteBody(intentRaw, cert, json.RawMessage(`{"op":"update"}`))))
		s.handleOntologyExecute(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"BAD_SIGNATURE"`) {
			t.Fatalf("expected BAD_SIGNATURE deny, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandleExecuteAllowAndDefer(t *testing.T) {
	newBaseServer := func(verifierBody string, verifierStatus int) (*Server, func()) {
		verifySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(verifierStatus)
			_, _ = w.Write([]byte(verifierBody))
		}))
		stateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"snapshot_id":"snap-1","domain":"finance","sources":[{"source":"bank","age_sec":0}]}`))
		}))
		toolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		cleanup := func() {
			verifySrv.Close()
			stateSrv.Close()
			toolSrv.Close()
		}
		s := &Server{
			AuthMode:     "off",
			Cache:        store.NewMemoryCache(),
			Metrics:      metrics.NewRegistry(),
			Audit:        fakeAuditStore{},
			HTTPClient:   verifySrv.Client(),
			VerifierURL:  verifySrv.URL,
			StateURL:     stateSrv.URL,
			ToolExecutor: palantir.HTTPExecutor{Endpoint: toolSrv.URL, Client: toolSrv.Client()},
			Config: rta.Config{
				MaxVerifyTime: 200 * time.Millisecond,
				MaxEscrowTTL:  30 * time.Minute,
			},
		}
		return s, cleanup
	}

	t.Run("allow_persists_idempotency", func(t *testing.T) {
		intentRaw := json.RawMessage(`{"intent_id":"i-allow","idempotency_key":"idem-allow","action_type":"TOOL_CALL","actor":{"id":"actor-1","tenant":"tenant-a"},"target":{"domain":"finance"},"operation":{"name":"pay","params":{"mode":"safe"}}}`)
		cert, pub := buildSignedCertWithKey(t, intentRaw, "kid-allow", "nonce-allow")

		s, cleanup := newBaseServer(`{"verdict":"ALLOW","reason_code":"OK"}`, http.StatusOK)
		defer cleanup()
		s.DB = &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "SELECT dsl, status FROM policy_versions"):
					return fakeGatewayRow{values: []any{"policyset finance v1:", "PUBLISHED"}}
				case strings.Contains(sql, "SELECT response_json FROM decisions"):
					return fakeGatewayRow{err: pgx.ErrNoRows}
				case strings.Contains(sql, "SELECT public_key, status FROM key_registry"):
					return fakeGatewayRow{values: []any{[]byte(pub), "active"}}
				default:
					return fakeGatewayRow{err: pgx.ErrNoRows}
				}
			},
		}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(buildToolExecuteBody(intentRaw, cert, json.RawMessage(`{"op":"simulate"}`))))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verdict":"ALLOW"`) || !strings.Contains(rr.Body.String(), `"result"`) {
			t.Fatalf("expected ALLOW with result, got %d body=%s", rr.Code, rr.Body.String())
		}

		if _, ok := s.checkIdempotency(context.Background(), "tenant-a", "tenant-a|actor-1|idem-allow"); !ok {
			t.Fatal("expected ALLOW response to be persisted for idempotency")
		}
	})

	t.Run("defer_not_persisted_and_nonce_released", func(t *testing.T) {
		intentRaw := json.RawMessage(`{"intent_id":"i-defer","idempotency_key":"idem-defer","action_type":"TOOL_CALL","actor":{"id":"actor-1","tenant":"tenant-a"},"target":{"domain":"finance"},"operation":{"name":"pay","params":{"mode":"safe"}}}`)
		cert, pub := buildSignedCertWithKey(t, intentRaw, "kid-defer", "nonce-defer")

		s, cleanup := newBaseServer(`{"verdict":"DEFER","reason_code":"WAIT_FOR_STATE","retry_after_ms":1234}`, http.StatusOK)
		defer cleanup()
		s.DB = &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "SELECT dsl, status FROM policy_versions"):
					return fakeGatewayRow{values: []any{"policyset finance v1:", "PUBLISHED"}}
				case strings.Contains(sql, "SELECT response_json FROM decisions"):
					return fakeGatewayRow{err: pgx.ErrNoRows}
				case strings.Contains(sql, "SELECT public_key, status FROM key_registry"):
					return fakeGatewayRow{values: []any{[]byte(pub), "active"}}
				default:
					return fakeGatewayRow{err: pgx.ErrNoRows}
				}
			},
		}

		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(buildToolExecuteBody(intentRaw, cert, json.RawMessage(`{"op":"simulate"}`))))
		s.handleToolExecute(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verdict":"DEFER"`) || !strings.Contains(rr.Body.String(), `"retry_after_ms":1234`) {
			t.Fatalf("expected DEFER with retry_after, got %d body=%s", rr.Code, rr.Body.String())
		}

		if _, ok := s.checkIdempotency(context.Background(), "tenant-a", "tenant-a|actor-1|idem-defer"); ok {
			t.Fatal("DEFER response must not be persisted for idempotency")
		}
		if _, err := s.Cache.Get(context.Background(), scopedNonceKey("tenant-a", "actor-1", "nonce-defer")); err == nil {
			t.Fatal("nonce must be removed after DEFER")
		}
	})
}

func TestEscrowHandlersAdditionalBranches(t *testing.T) {
	now := time.Now().UTC()

	t.Run("approve_expired", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM escrows WHERE escrow_id=$1") {
					return fakeGatewayRow{values: []any{
						escrowfsm.Pending,
						now.Add(-time.Minute),
						1,
						0,
						[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
						[]byte(`{"policy_set_id":"ps","policy_version":"v1"}`),
						[]byte(`{"op":"x"}`),
						"TOOL_CALL",
					}}
				}
				return fakeGatewayRow{err: pgx.ErrNoRows}
			},
		}
		s := &Server{AuthMode: "off", DB: db, Cache: store.NewMemoryCache()}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrows/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"mgr-1"}`)))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), escrowfsm.Expired) {
			t.Fatalf("expected expired escrow response, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_pending_requires_approver", func(t *testing.T) {
		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM escrows WHERE escrow_id=$1") {
					return fakeGatewayRow{values: []any{
						escrowfsm.Pending,
						now.Add(time.Hour),
						1,
						0,
						[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
						[]byte(`{"policy_set_id":"ps","policy_version":"v1"}`),
						[]byte(`{"op":"x"}`),
						"TOOL_CALL",
					}}
				}
				return fakeGatewayRow{err: pgx.ErrNoRows}
			},
		}
		s := &Server{AuthMode: "off", DB: db, Cache: store.NewMemoryCache()}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrows/approve", strings.NewReader(`{"escrow_id":"e-1"}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected missing approver validation, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approve_quorum_reached_executes_and_closes", func(t *testing.T) {
		execSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer execSrv.Close()

		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "FROM escrows WHERE escrow_id=$1"):
					return fakeGatewayRow{values: []any{
						escrowfsm.Pending,
						now.Add(time.Hour),
						1,
						0,
						[]byte(`{"actor":{"id":"actor-1","tenant":"tenant-a"}}`),
						[]byte(`{"policy_set_id":"ps","policy_version":"v1"}`),
						[]byte(`{"op":"execute"}`),
						"TOOL_CALL",
					}}
				case strings.Contains(sql, "SELECT COUNT(*) FROM escrow_approvals"):
					return fakeGatewayRow{values: []any{1}}
				default:
					return fakeGatewayRow{err: pgx.ErrNoRows}
				}
			},
		}
		s := &Server{
			AuthMode:     "off",
			DB:           db,
			Cache:        store.NewMemoryCache(),
			ToolExecutor: palantir.HTTPExecutor{Endpoint: execSrv.URL, Client: execSrv.Client()},
		}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrows/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"mgr-1"}`)))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), escrowfsm.Closed) {
			t.Fatalf("expected closed escrow after execution, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("cancel_and_rollback", func(t *testing.T) {
		execSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer execSrv.Close()

		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "SELECT status FROM escrows WHERE escrow_id=$1"):
					return fakeGatewayRow{values: []any{escrowfsm.Pending}}
				case strings.Contains(sql, "SELECT status, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE escrow_id=$1"):
					return fakeGatewayRow{values: []any{
						escrowfsm.Executed,
						[]byte(`{"intent_id":"i-1","actor":{"id":"actor-1","tenant":"tenant-a"},"target":{"domain":"finance"}}`),
						[]byte(`{"rollback_plan":{"type":"COMPENSATING_ACTION","steps":["undo-op"]}}`),
						[]byte(`{"op":"execute"}`),
						"TOOL_CALL",
					}}
				default:
					return fakeGatewayRow{err: pgx.ErrNoRows}
				}
			},
		}
		s := &Server{
			AuthMode:     "off",
			DB:           db,
			Cache:        store.NewMemoryCache(),
			ToolExecutor: palantir.HTTPExecutor{Endpoint: execSrv.URL, Client: execSrv.Client()},
		}

		cancelRR := httptest.NewRecorder()
		s.cancelEscrow(cancelRR, httptest.NewRequest(http.MethodPost, "/v1/escrows/cancel", strings.NewReader(`{"escrow_id":"e-1","actor":"operator"}`)))
		if cancelRR.Code != http.StatusOK || !strings.Contains(cancelRR.Body.String(), escrowfsm.Cancelled) {
			t.Fatalf("expected cancelled status, got %d body=%s", cancelRR.Code, cancelRR.Body.String())
		}

		rollbackRR := httptest.NewRecorder()
		s.rollbackEscrow(rollbackRR, httptest.NewRequest(http.MethodPost, "/v1/escrows/rollback", strings.NewReader(`{"escrow_id":"e-1","actor":"operator"}`)))
		if rollbackRR.Code != http.StatusOK || !strings.Contains(rollbackRR.Body.String(), escrowfsm.RolledBack) {
			t.Fatalf("expected rolled back status, got %d body=%s", rollbackRR.Code, rollbackRR.Body.String())
		}
	})
}

func TestStreamEventsLive(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		s := &Server{}
		rr := httptest.NewRecorder()
		s.streamEvents(rr, httptest.NewRequest(http.MethodGet, "/v1/stream", nil))
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 when stream hub missing, got %d", rr.Code)
		}
	})

	t.Run("ready_and_event_delivery", func(t *testing.T) {
		hub := stream.NewHub()
		s := &Server{Events: hub}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.streamEvents(w, r)
		}))
		defer srv.Close()

		wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, _, err := websocket.Dial(ctx, wsURL, nil)
		if err != nil {
			t.Fatalf("dial websocket: %v", err)
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")

		var ready stream.Event
		if err := wsjson.Read(ctx, conn, &ready); err != nil {
			t.Fatalf("read ready event: %v", err)
		}
		if ready.Type != "ready" {
			t.Fatalf("expected ready event, got %#v", ready)
		}

		hub.Publish(stream.NewEvent("refresh", map[string]string{"source": "test"}))
		var evt stream.Event
		if err := wsjson.Read(ctx, conn, &evt); err != nil {
			t.Fatalf("read refresh event: %v", err)
		}
		if evt.Type != "refresh" {
			t.Fatalf("expected refresh event, got %#v", evt)
		}
	})
}

type staticLimiter struct {
	decision ratelimit.Decision
	keys     []string
	limits   []int
}

func (l *staticLimiter) Allow(key string, limit int) ratelimit.Decision {
	l.keys = append(l.keys, key)
	l.limits = append(l.limits, limit)
	return l.decision
}

func TestCheckRateLimitAdditionalBranches(t *testing.T) {
	t.Run("disabled_or_no_limiter", func(t *testing.T) {
		s := &Server{RateLimitEnabled: false}
		intent := models.ActionIntent{ActionType: "TOOL_CALL", Target: models.Target{Domain: "finance"}}
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
		blocked, retryAfter := s.checkRateLimit(req, intent, nil)
		if blocked || retryAfter != 0 {
			t.Fatalf("expected no rate limit when disabled, blocked=%v retry=%d", blocked, retryAfter)
		}

		s = &Server{RateLimitEnabled: true, RateLimiter: nil}
		blocked, retryAfter = s.checkRateLimit(req, intent, nil)
		if blocked || retryAfter != 0 {
			t.Fatalf("expected no rate limit when limiter missing, blocked=%v retry=%d", blocked, retryAfter)
		}
	})

	t.Run("limit_non_positive_bypass", func(t *testing.T) {
		lim := &staticLimiter{decision: ratelimit.Decision{Allowed: false, ResetAt: time.Now().UTC().Add(time.Minute)}}
		s := &Server{
			RateLimitEnabled:   true,
			RateLimiter:        lim,
			RateLimitPerMinute: 0,
			RateLimitWindow:    time.Minute,
		}
		intent := models.ActionIntent{ActionType: "TOOL_CALL", Target: models.Target{Domain: "finance"}}
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
		blocked, retryAfter := s.checkRateLimit(req, intent, nil)
		if blocked || retryAfter != 0 {
			t.Fatalf("expected bypass when limit<=0, blocked=%v retry=%d", blocked, retryAfter)
		}
		if len(lim.keys) != 0 {
			t.Fatalf("limiter should not be called when limit<=0, calls=%d", len(lim.keys))
		}
	})

	t.Run("tenant_scope_and_principal_override", func(t *testing.T) {
		lim := &staticLimiter{decision: ratelimit.Decision{Allowed: false, ResetAt: time.Now().UTC().Add(2 * time.Second)}}
		s := &Server{
			RateLimitEnabled:   true,
			RateLimiter:        lim,
			RateLimitPerMinute: 1,
			RateLimitWindow:    time.Minute,
		}
		intent := models.ActionIntent{
			ActionType: "TOOL_CALL",
			Actor:      models.Actor{ID: "intent-actor", Tenant: "intent-tenant"},
			Target:     models.Target{Domain: "Finance"},
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "principal-actor",
			Tenant:  "principal-tenant",
		}))
		policy := &policyir.PolicySetIR{RateLimit: &policyir.RateLimit{Limit: 2, Scope: "tenant"}}
		blocked, retryAfter := s.checkRateLimit(req, intent, policy)
		if !blocked || retryAfter <= 0 {
			t.Fatalf("expected blocked tenant-scoped decision, blocked=%v retry=%d", blocked, retryAfter)
		}
		if len(lim.keys) != 1 || len(lim.limits) != 1 {
			t.Fatalf("expected one limiter call, keys=%d limits=%d", len(lim.keys), len(lim.limits))
		}
		if lim.limits[0] != 2 {
			t.Fatalf("expected policy limit override 2, got %d", lim.limits[0])
		}
		if !strings.Contains(lim.keys[0], ":tenant:principal-tenant:") {
			t.Fatalf("expected tenant scope key, got %q", lim.keys[0])
		}
	})

	t.Run("global_scope_retry_after_from_window", func(t *testing.T) {
		lim := &staticLimiter{decision: ratelimit.Decision{Allowed: false, ResetAt: time.Now().UTC().Add(-time.Second)}}
		s := &Server{
			RateLimitEnabled:   true,
			RateLimiter:        lim,
			RateLimitPerMinute: 1,
			RateLimitWindow:    3 * time.Second,
		}
		intent := models.ActionIntent{
			ActionType: "TOOL_CALL",
			Actor:      models.Actor{},
			Target:     models.Target{Domain: "finance"},
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
		req.RemoteAddr = ""
		policy := &policyir.PolicySetIR{RateLimit: &policyir.RateLimit{Scope: "global"}}
		blocked, retryAfter := s.checkRateLimit(req, intent, policy)
		if !blocked {
			t.Fatal("expected blocked for static limiter deny")
		}
		if retryAfter != int((3 * time.Second).Milliseconds()) {
			t.Fatalf("expected retry from window fallback, got %d", retryAfter)
		}
		if len(lim.keys) != 1 || !strings.Contains(lim.keys[0], ":global:global:unknown") {
			t.Fatalf("expected global scope key with unknown ip, got %#v", lim.keys)
		}
	})
}

func TestAuthorizeIntentAdditionalBranches(t *testing.T) {
	intent := models.ActionIntent{
		Actor:  models.Actor{ID: "u1", Tenant: "acme"},
		Target: models.Target{Domain: "finance"},
	}

	t.Run("unauthenticated", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256"}
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
		ok, reason := s.authorizeIntent(req, intent, models.ActionCert{}, nil)
		if ok || reason != "ACCESS_UNAUTHENTICATED" {
			t.Fatalf("expected unauthenticated deny, ok=%v reason=%s", ok, reason)
		}
	})

	t.Run("tenant_required", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256"}
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "u1", Roles: []string{"operator"}}))
		ok, reason := s.authorizeIntent(req, intent, models.ActionCert{}, nil)
		if ok || reason != "ACCESS_TENANT_REQUIRED" {
			t.Fatalf("expected tenant-required deny, ok=%v reason=%s", ok, reason)
		}
	})

	t.Run("domain_missing", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256"}
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "u1", Tenant: "acme", Roles: []string{"operator"}}))
		noDomain := intent
		noDomain.Target.Domain = ""
		ok, reason := s.authorizeIntent(req, noDomain, models.ActionCert{}, nil)
		if ok || reason != "ACCESS_DOMAIN_MISSING" {
			t.Fatalf("expected domain-missing deny, ok=%v reason=%s", ok, reason)
		}
	})

	t.Run("domain_role_mismatch", func(t *testing.T) {
		s := &Server{
			AuthMode:        "oidc_hs256",
			DomainRoleAllow: parseDomainRoleAllow("finance:financeoperator"),
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "u1", Tenant: "acme", Roles: []string{"viewer"}}))
		ok, reason := s.authorizeIntent(req, intent, models.ActionCert{}, nil)
		if ok || reason != "ACCESS_DOMAIN_MISMATCH" {
			t.Fatalf("expected domain mismatch deny, ok=%v reason=%s", ok, reason)
		}
	})

	t.Run("abac_no_match", func(t *testing.T) {
		s := &Server{
			AuthMode:    "oidc_hs256",
			ABACEnabled: true,
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "u1", Tenant: "acme", Roles: []string{"operator"}}))
		policy := &policyir.PolicySetIR{
			ABACRules: []policyir.ABACRule{
				{Effect: "ALLOW", When: `principal.role contains "ComplianceOfficer"`},
			},
		}
		ok, reason := s.authorizeIntent(req, intent, models.ActionCert{}, policy)
		if ok || reason != "ABAC_NO_MATCH" {
			t.Fatalf("expected ABAC deny/no-match, ok=%v reason=%s", ok, reason)
		}
	})
}

func TestPatchIncidentAdditionalBranches(t *testing.T) {
	now := time.Now().UTC()
	baseReq := func(body string) *http.Request {
		req := withGatewayURLParams(
			httptest.NewRequest(http.MethodPatch, "/v1/incidents/inc-1", strings.NewReader(body)),
			map[string]string{"incident_id": "inc-1"},
		)
		return req
	}

	incidentRow := func(status string) fakeGatewayRow {
		return fakeGatewayRow{values: []any{
			"inc-1", "dec-1", "HIGH", "SECURITY_POLICY", "SOD_FAIL", status, "title", []byte(`{"actor_id":"a1"}`), "alice", "", now, now, nil,
		}}
	}

	t.Run("invalid_status", func(t *testing.T) {
		s := &Server{AuthMode: "off", DB: &fakeGatewayDB{}}
		rr := httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"OPEN","actor":"alice"}`))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid status, got %d", rr.Code)
		}
	})

	t.Run("auth_mode_unauthenticated_and_mismatch", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256", DB: &fakeGatewayDB{}}
		rr := httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"ACKNOWLEDGED"}`))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 unauthenticated, got %d", rr.Code)
		}

		req := baseReq(`{"status":"ACKNOWLEDGED","actor":"alice"}`)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "bob", Tenant: "acme", Roles: []string{"operator"}}))
		rr = httptest.NewRecorder()
		s.patchIncident(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 actor mismatch, got %d", rr.Code)
		}
	})

	t.Run("ack_update_error_and_conflict", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: &fakeGatewayDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					return pgconn.CommandTag{}, errors.New("db fail")
				},
			},
		}
		rr := httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"ACKNOWLEDGED","actor":"alice"}`))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on update error, got %d", rr.Code)
		}

		s.DB = &fakeGatewayDB{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 0"), nil
			},
		}
		rr = httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"ACKNOWLEDGED","actor":"alice"}`))
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 on non-open incident, got %d", rr.Code)
		}
	})

	t.Run("resolve_conflict_and_not_found", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: &fakeGatewayDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 0"), nil
				},
			},
		}
		rr := httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"RESOLVED","actor":"alice"}`))
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 for already resolved path, got %d", rr.Code)
		}

		s.DB = &fakeGatewayDB{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{err: pgx.ErrNoRows}
			},
		}
		rr = httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"RESOLVED","actor":"alice"}`))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 when incident row missing after update, got %d", rr.Code)
		}
	})

	t.Run("resolve_success", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: &fakeGatewayDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return incidentRow(incidentStatusResolved)
				},
			},
		}
		rr := httptest.NewRecorder()
		s.patchIncident(rr, baseReq(`{"status":"RESOLVED","actor":"alice"}`))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"status":"RESOLVED"`) {
			t.Fatalf("expected resolved incident response, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func buildExecuteBody(intentRaw json.RawMessage, cert models.ActionCert, actionPayload json.RawMessage) string {
	certRaw, _ := json.Marshal(cert)
	req := executeRequest{
		Intent:        intentRaw,
		Cert:          certRaw,
		ActionPayload: actionPayload,
	}
	body, _ := json.Marshal(req)
	return string(body)
}

func buildSignedCert(t *testing.T, intentRaw json.RawMessage, kid, nonce string) models.ActionCert {
	t.Helper()
	cert, _ := buildSignedCertWithKey(t, intentRaw, kid, nonce)
	return cert
}

func buildSignedCertWithKey(t *testing.T, intentRaw json.RawMessage, kid, nonce string) (models.ActionCert, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	canonical, err := models.CanonicalizeJSON(intentRaw)
	if err != nil {
		t.Fatalf("canonicalize intent: %v", err)
	}
	cert := models.ActionCert{
		CertID:        "cert-1",
		IntentHash:    models.IntentHash(canonical, "v1", nonce),
		PolicySetID:   "ps-1",
		PolicyVersion: "v1",
		RollbackPlan: models.Rollback{
			Type:  "ESCROW",
			Steps: []string{"await-approval"},
		},
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339),
		Nonce:     nonce,
		Signature: models.Signature{
			Signer: "agent-1",
			Alg:    "ed25519",
			Kid:    kid,
		},
	}
	payload, err := auth.SignaturePayload(cert)
	if err != nil {
		t.Fatalf("signature payload: %v", err)
	}
	cert.Signature.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return cert, pub
}

func buildToolExecuteBody(intentRaw json.RawMessage, cert models.ActionCert, toolPayload json.RawMessage) string {
	certRaw, _ := json.Marshal(cert)
	req := executeRequest{
		Intent:      intentRaw,
		Cert:        certRaw,
		ToolPayload: toolPayload,
	}
	body, _ := json.Marshal(req)
	return string(body)
}
