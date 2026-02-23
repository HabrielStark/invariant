package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/audit"
	"axiom/pkg/auth"
	"axiom/pkg/escrowfsm"
	"axiom/pkg/metrics"
	"axiom/pkg/models"
	"axiom/pkg/ratelimit"
	"axiom/pkg/rta"
	"axiom/pkg/store"
	"axiom/pkg/stream"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type deepErrBody struct{}

func (deepErrBody) Read(_ []byte) (int, error) { return 0, errors.New("read-fail") }
func (deepErrBody) Close() error               { return nil }

type execFunc func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error)

func (f execFunc) Execute(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	return f(ctx, payload)
}

func TestHandleExecuteBodyReadFailure(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
	req.Body = deepErrBody{}
	rr := httptest.NewRecorder()
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid request body") {
		t.Fatalf("expected invalid body 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleExecuteIdempotencyAndRateLimitBranches(t *testing.T) {
	makeIntent := func(idem string) json.RawMessage {
		return json.RawMessage(`{
			"intent_id":"i-1",
			"idempotency_key":"` + idem + `",
			"action_type":"TOOL_CALL",
			"actor":{"id":"actor-1","tenant":"tenant-a"},
			"target":{"domain":"finance"},
			"operation":{"name":"pay","params":{"mode":"safe"}}
		}`)
	}
	makeCert := func() models.ActionCert {
		return models.ActionCert{
			PolicySetID:   "ps-1",
			PolicyVersion: "v1",
			ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			Nonce:         "n-1",
			Signature:     models.Signature{Kid: "kid-1"},
		}
	}

	t.Run("idempotency_hit_returns_cached_response", func(t *testing.T) {
		cache := store.NewMemoryCache()
		key := scopedIdempotencyKey("tenant-a", "actor-1", "idem-hit")
		_ = cache.Set(context.Background(), decisionCacheKey("tenant-a", key), `{"verdict":"ALLOW","reason_code":"CACHE_HIT"}`, time.Minute)
		s := &Server{
			AuthMode: "off",
			DB: &fakeGatewayDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeGatewayRow{err: pgx.ErrNoRows}
				},
			},
			Cache: cache,
		}
		certRaw, _ := json.Marshal(makeCert())
		body, _ := json.Marshal(executeRequest{Intent: makeIntent("idem-hit"), Cert: certRaw})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"CACHE_HIT"`) {
			t.Fatalf("expected cached idempotency response, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("rate_limited_branch", func(t *testing.T) {
		lim := &staticLimiter{decision: ratelimitDecisionDeniedAfter(2 * time.Second)}
		s := &Server{
			AuthMode:            "off",
			DB:                  &fakeGatewayDB{},
			Cache:               store.NewMemoryCache(),
			RateLimitEnabled:    true,
			RateLimiter:         lim,
			RateLimitPerMinute:  1,
			RateLimitWindow:     time.Minute,
			Audit:               fakeAuditStore{},
			Metrics:             metrics.NewRegistry(),
			HTTPClient:          &http.Client{Timeout: 2 * time.Second},
			Config:              defaultGatewayConfigForTests(),
			UpstreamRetryDelay:  time.Millisecond,
			UpstreamRetries:     0,
			MaxRequestBodyBytes: 1 << 20,
		}
		certRaw, _ := json.Marshal(makeCert())
		body, _ := json.Marshal(executeRequest{Intent: makeIntent("idem-rate"), Cert: certRaw})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"RATE_LIMITED"`) {
			t.Fatalf("expected rate-limited response, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandleExecuteAdvancedVerdictBranches(t *testing.T) {
	stateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"snapshot_id":"snap-1","domain":"finance","sources":[{"source":"bank","age_sec":0}]}`))
	}))
	defer stateSrv.Close()

	makeServer := func(t *testing.T, intentRaw json.RawMessage, verifierBody string, verifierStatus int, keyPub ed25519.PublicKey, execFn func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)) (*Server, func()) {
		t.Helper()
		verifierSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(verifierStatus)
			_, _ = w.Write([]byte(verifierBody))
		}))
		db := &fakeGatewayDB{
			execFn: execFn,
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				switch {
				case strings.Contains(sql, "FROM key_registry"):
					return fakeGatewayRow{values: []any{[]byte(keyPub), "active"}}
				case strings.Contains(sql, "SELECT response_json FROM decisions"):
					return fakeGatewayRow{err: pgx.ErrNoRows}
				default:
					return fakeGatewayRow{err: pgx.ErrNoRows}
				}
			},
		}
		s := &Server{
			AuthMode: "off",
			DB:       db,
			Cache:    store.NewMemoryCache(),
			Audit:    fakeAuditStore{},
			Metrics:  metrics.NewRegistry(),
			Config:   defaultGatewayConfigForTests(),
			HTTPClient: &http.Client{
				Timeout: 2 * time.Second,
			},
			VerifierURL: verifierSrv.URL,
			StateURL:    stateSrv.URL,
		}
		return s, verifierSrv.Close
	}

	t.Run("allow_with_upstream_failure_converts_to_shield", func(t *testing.T) {
		intentRaw := json.RawMessage(`{
			"intent_id":"i-upstream-fail",
			"idempotency_key":"idem-upstream-fail",
			"action_type":"TOOL_CALL",
			"actor":{"id":"actor-1","tenant":"tenant-a"},
			"target":{"domain":"finance"},
			"operation":{"name":"pay_invoice","params":{"mode":"safe"}},
			"data_requirements":{"max_staleness_sec":30,"required_sources":["bank"]}
		}`)
		cert, pub := buildSignedCertWithKey(t, intentRaw, "kid-upstream-fail", "nonce-upstream-fail")
		s, cleanup := makeServer(t, intentRaw, `{"verdict":"ALLOW","reason_code":"OK"}`, http.StatusOK, pub, nil)
		defer cleanup()
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: intentRaw, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"write"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"UPSTREAM_FAIL"`) || !strings.Contains(rr.Body.String(), `"verdict":"SHIELD"`) {
			t.Fatalf("expected SHIELD/UPSTREAM_FAIL, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("shield_require_approval_escrow_fail_returns_deny", func(t *testing.T) {
		intentRaw := json.RawMessage(`{
			"intent_id":"i-shield-approval",
			"idempotency_key":"idem-shield-approval",
			"action_type":"TOOL_CALL",
			"actor":{"id":"actor-1","tenant":"tenant-a"},
			"target":{"domain":"finance"},
			"operation":{"name":"pay_invoice","params":{"mode":"safe"}},
			"data_requirements":{"max_staleness_sec":30,"required_sources":["bank"]}
		}`)
		cert, pub := buildSignedCertWithKey(t, intentRaw, "kid-shield-approval", "nonce-shield-approval")
		execFn := func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			if strings.Contains(sql, "INSERT INTO escrows") {
				return pgconn.CommandTag{}, errors.New("insert failed")
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		s, cleanup := makeServer(t, intentRaw, `{"verdict":"SHIELD","reason_code":"MANUAL_REQUIRED","suggested_shield":{"type":"REQUIRE_APPROVAL","params":{}}}`, http.StatusOK, pub, execFn)
		defer cleanup()
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{Intent: intentRaw, Cert: certRaw, ToolPayload: json.RawMessage(`{"op":"write"}`)})
		rr := httptest.NewRecorder()
		s.handleToolExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"ESCROW_FAIL"`) || !strings.Contains(rr.Body.String(), `"verdict":"DENY"`) {
			t.Fatalf("expected DENY/ESCROW_FAIL, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("shield_small_batch_executes_chunks", func(t *testing.T) {
		intentRaw := json.RawMessage(`{
			"intent_id":"i-small-batch",
			"idempotency_key":"idem-small-batch",
			"action_type":"ONTOLOGY_ACTION",
			"actor":{"id":"actor-1","tenant":"tenant-a"},
			"target":{"domain":"finance","scope":"batch","object_ids":["a","b","c","d","e"]},
			"operation":{"name":"bulk_update","params":{"mode":"safe"}},
			"data_requirements":{"max_staleness_sec":30,"required_sources":["bank"]}
		}`)
		cert, pub := buildSignedCertWithKey(t, intentRaw, "kid-small-batch", "nonce-small-batch")
		s, cleanup := makeServer(t, intentRaw, `{"verdict":"SHIELD","reason_code":"BATCH_SAFETY","suggested_shield":{"type":"SMALL_BATCH","params":{"max":2}}}`, http.StatusOK, pub, nil)
		defer cleanup()
		s.OntologyExecutor = execFunc(func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
			var body map[string]interface{}
			_ = json.Unmarshal(payload, &body)
			ids, _ := body["ids"].([]interface{})
			out, _ := json.Marshal(map[string]any{"count": len(ids)})
			return out, nil
		})
		certRaw, _ := json.Marshal(cert)
		body, _ := json.Marshal(executeRequest{
			Intent:        intentRaw,
			Cert:          certRaw,
			ActionPayload: json.RawMessage(`{"op":"bulk_update","ids":["a","b","c","d","e"]}`),
		})
		rr := httptest.NewRecorder()
		s.handleOntologyExecute(rr, httptest.NewRequest(http.MethodPost, "/v1/ontology/actions/execute", strings.NewReader(string(body))))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"verdict":"SHIELD"`) || !strings.Contains(rr.Body.String(), `"chunks"`) {
			t.Fatalf("expected shielded small-batch response, got %d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestGatewayAuxiliaryBranches(t *testing.T) {
	t.Run("with_roles_forbidden", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_rs256", DB: &fakeGatewayDB{}}
		req := httptest.NewRequest(http.MethodGet, "/v1/verdicts", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "user-1",
			Tenant:  "tenant-a",
			Roles:   []string{"viewer"},
		}))
		rr := httptest.NewRecorder()
		s.withRoles(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}, "operator")(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected forbidden branch, got %d", rr.Code)
		}
	})

	t.Run("run_retention_now_success", func(t *testing.T) {
		s := &Server{
			DB: &fakeGatewayDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					return pgconn.NewCommandTag("DELETE 0"), nil
				},
			},
			RetentionDays: 7,
		}
		rr := httptest.NewRecorder()
		s.runRetentionNow(rr, httptest.NewRequest(http.MethodPost, "/v1/compliance/retention/run", nil))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"tables"`) {
			t.Fatalf("expected retention report, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("get_audit_not_found_and_replay_invalid_cert", func(t *testing.T) {
		s := &Server{
			Audit: fakeAuditStore{
				getFn: func(ctx context.Context, decisionID, tenant string) (audit.Record, error) {
					if decisionID == "missing" {
						return audit.Record{}, pgx.ErrNoRows
					}
					return audit.Record{
						DecisionID: decisionID,
						IntentRaw:  json.RawMessage(`{"intent_id":"i-1"}`),
						CertRaw:    json.RawMessage(`{bad`),
						Verdict:    "ALLOW",
						ReasonCode: "OK",
					}, nil
				},
			},
		}

		rr := httptest.NewRecorder()
		req := withGatewayURLParams(httptest.NewRequest(http.MethodGet, "/v1/audit/missing", nil), map[string]string{"decision_id": "missing"})
		s.getAudit(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected getAudit not found, got %d", rr.Code)
		}

		rr = httptest.NewRecorder()
		req = withGatewayURLParams(httptest.NewRequest(http.MethodPost, "/v1/audit/dec-1/replay", nil), map[string]string{"decision_id": "dec-1"})
		s.replayAudit(rr, req)
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "invalid stored cert") {
			t.Fatalf("expected replay invalid cert error, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("resolve_tenant_empty_and_scoped_key_tenant_only", func(t *testing.T) {
		if got := resolveTenant(models.ActionIntent{}, auth.Principal{}); got != "" {
			t.Fatalf("expected empty tenant, got %q", got)
		}
		if got := scopedIdempotencyKey("tenant-a", "", "idem"); got != "tenant-a|idem" {
			t.Fatalf("expected tenant-only scoped key, got %q", got)
		}
	})

	t.Run("fetch_snapshot_non_created_and_invalid_json", func(t *testing.T) {
		statusSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{}`))
		}))
		defer statusSrv.Close()
		s := &Server{HTTPClient: statusSrv.Client(), StateURL: statusSrv.URL}
		if _, unknown := s.fetchSnapshot(context.Background(), "tenant-a", "finance"); !unknown {
			t.Fatal("expected unknown when snapshot endpoint is not 201")
		}

		badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{bad`))
		}))
		defer badSrv.Close()
		s = &Server{HTTPClient: badSrv.Client(), StateURL: badSrv.URL}
		if _, unknown := s.fetchSnapshot(context.Background(), "tenant-a", "finance"); !unknown {
			t.Fatal("expected unknown on invalid snapshot body")
		}
	})

	t.Run("execute_upstream_and_small_batch_validation", func(t *testing.T) {
		s := &Server{}
		if _, err := s.executeUpstream(context.Background(), "UNKNOWN", nil, nil); err == nil {
			t.Fatal("expected unknown action type error")
		}
		if _, err := s.executeUpstream(context.Background(), "TOOL_CALL", json.RawMessage(`{}`), nil); err == nil {
			t.Fatal("expected missing upstream adapter error")
		}
		if _, err := s.executeSmallBatch(context.Background(), "TOOL_CALL", json.RawMessage(`{}`), 10); err == nil {
			t.Fatal("expected non-ontology small-batch rejection")
		}
		if _, err := s.executeSmallBatch(context.Background(), "ONTOLOGY_ACTION", json.RawMessage(`{bad`), 10); err == nil {
			t.Fatal("expected invalid payload parse error")
		}
		if _, err := s.executeSmallBatch(context.Background(), "ONTOLOGY_ACTION", json.RawMessage(`{"ids":[]}`), 10); err == nil {
			t.Fatal("expected empty ids error")
		}
	})

	t.Run("execute_two_phase_empty_prepare_rollback", func(t *testing.T) {
		s := &Server{
			ToolExecutor: execFunc(func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
				return json.RawMessage(`{"ok":true}`), nil
			}),
		}
		out, err := s.executeWithTwoPhase(context.Background(), "TOOL_CALL", json.RawMessage(`{"two_phase":{"commit":{"step":"commit"}}}`))
		if err != nil {
			t.Fatalf("expected two-phase success with implicit prepare/rollback no-op, got %v", err)
		}
		if !strings.Contains(string(out), `"ok":true`) {
			t.Fatalf("unexpected two-phase output: %s", string(out))
		}
	})

	t.Run("cancel_and_rollback_missing_ids", func(t *testing.T) {
		s := &Server{DB: &fakeGatewayDB{}, AuthMode: "off"}
		rr := httptest.NewRecorder()
		s.cancelEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/cancel", strings.NewReader(`{"actor":"u1"}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected cancel missing id 400, got %d", rr.Code)
		}
		rr = httptest.NewRecorder()
		s.rollbackEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/rollback", strings.NewReader(`{"actor":"u1"}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected rollback missing id 400, got %d", rr.Code)
		}

		db := &fakeGatewayDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeGatewayRow{err: pgx.ErrNoRows}
			},
		}
		s = &Server{DB: db, AuthMode: "off"}
		rr = httptest.NewRecorder()
		s.cancelEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/cancel", strings.NewReader(`{"escrow_id":"e404","actor":"u1"}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected cancel not found 404, got %d", rr.Code)
		}
		rr = httptest.NewRecorder()
		s.rollbackEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/rollback", strings.NewReader(`{"escrow_id":"e404","actor":"u1"}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected rollback not found 404, got %d", rr.Code)
		}
	})

	t.Run("approve_missing_id", func(t *testing.T) {
		s := &Server{DB: &fakeGatewayDB{}, AuthMode: "off"}
		rr := httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"approver":"u1"}`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected approve missing id 400, got %d", rr.Code)
		}

		now := time.Now().UTC()
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
		s = &Server{DB: db, AuthMode: "oidc_rs256", Cache: store.NewMemoryCache()}
		rr = httptest.NewRecorder()
		s.approveEscrow(rr, httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"u1"}`)))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected approve unauthenticated 401, got %d body=%s", rr.Code, rr.Body.String())
		}
		rr = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"e-1","approver":"u2"}`))
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "u3",
			Tenant:  "tenant-a",
			Roles:   []string{"financemanager"},
		}))
		s.approveEscrow(rr, req)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "approver must match principal") {
			t.Fatalf("expected approve mismatch 403, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("export_compliance_scoped_and_query_errors", func(t *testing.T) {
		now := time.Now().UTC()
		successDB := &fakeGatewayDB{
			queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
				switch {
				case strings.Contains(sql, "FROM audit_records"):
					return &fakeGatewayRows{rows: [][]any{{"dec-1", "v1", "ALLOW", "OK", now}}}, nil
				case strings.Contains(sql, "FROM escrows"):
					return &fakeGatewayRows{rows: [][]any{{"esc-1", "PENDING", 1, 0, now}}}, nil
				case strings.Contains(sql, "FROM incidents"):
					return &fakeGatewayRows{rows: [][]any{{"inc-1", "HIGH", "SECURITY_POLICY", "SOD_FAIL", "OPEN", now}}}, nil
				default:
					return &fakeGatewayRows{}, nil
				}
			},
		}
		s := &Server{DB: successDB, AuthMode: "oidc_rs256", RetentionDays: 30}
		req := httptest.NewRequest(http.MethodGet, "/v1/compliance/export?actor_id=a1&limit=3", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "op-1",
			Tenant:  "tenant-a",
			Roles:   []string{"operator"},
		}))
		rr := httptest.NewRecorder()
		s.exportComplianceData(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"record_counts"`) {
			t.Fatalf("expected scoped export success, got %d body=%s", rr.Code, rr.Body.String())
		}

		auditErrDB := &fakeGatewayDB{
			queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
				return nil, errors.New("audit down")
			},
		}
		s = &Server{DB: auditErrDB, AuthMode: "oidc_rs256"}
		rr = httptest.NewRecorder()
		s.exportComplianceData(rr, req)
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "failed to query audit records") {
			t.Fatalf("expected audit query error, got %d body=%s", rr.Code, rr.Body.String())
		}

		call := 0
		escrowErrDB := &fakeGatewayDB{
			queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
				call++
				if call == 1 {
					return &fakeGatewayRows{rows: [][]any{{"dec-1", "v1", "ALLOW", "OK", now}}}, nil
				}
				return nil, errors.New("escrow down")
			},
		}
		s = &Server{DB: escrowErrDB, AuthMode: "oidc_rs256"}
		rr = httptest.NewRecorder()
		s.exportComplianceData(rr, req)
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "failed to query escrows") {
			t.Fatalf("expected escrow query error, got %d body=%s", rr.Code, rr.Body.String())
		}

		call = 0
		incidentErrDB := &fakeGatewayDB{
			queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
				call++
				switch call {
				case 1:
					return &fakeGatewayRows{rows: [][]any{{"dec-1", "v1", "ALLOW", "OK", now}}}, nil
				case 2:
					return &fakeGatewayRows{rows: [][]any{{"esc-1", "PENDING", 1, 0, now}}}, nil
				default:
					return nil, errors.New("incident down")
				}
			},
		}
		s = &Server{DB: incidentErrDB, AuthMode: "oidc_rs256"}
		rr = httptest.NewRecorder()
		s.exportComplianceData(rr, req)
		if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "failed to query incidents") {
			t.Fatalf("expected incident query error, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("stream_events_with_origin_policy", func(t *testing.T) {
		t.Setenv("WS_ALLOWED_ORIGINS", "https://console.example.com")
		hub := stream.NewHub()
		s := &Server{Events: hub}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.streamEvents(w, r)
		}))
		defer srv.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
		conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			HTTPHeader: http.Header{"Origin": []string{"https://console.example.com"}},
		})
		if err != nil {
			t.Fatalf("websocket dial failed: %v", err)
		}
		var ready stream.Event
		if err := wsjson.Read(ctx, conn, &ready); err != nil {
			t.Fatalf("read ready event: %v", err)
		}
		if ready.Type != "ready" {
			t.Fatalf("unexpected ready payload: %#v", ready)
		}
		_ = conn.Close(websocket.StatusNormalClosure, "done")
	})
}

func ratelimitDecisionDeniedAfter(after time.Duration) ratelimit.Decision {
	return ratelimit.Decision{Allowed: false, ResetAt: time.Now().UTC().Add(after)}
}

func defaultGatewayConfigForTests() rta.Config {
	return rta.Config{
		MaxVerifyTime:   250 * time.Millisecond,
		MaxDeferTotal:   time.Second,
		MaxEscrowTTL:    time.Hour,
		DegradedNoAllow: true,
	}
}
