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
	"axiom/pkg/policyir"
	"axiom/pkg/rta"
	"axiom/pkg/store"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeExternalKeyStore struct {
	record *auth.KeyRecord
	err    error
}

func (f fakeExternalKeyStore) GetKey(ctx context.Context, kid string) (*auth.KeyRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.record, nil
}

type fakeGatewayDB struct {
	execFn     func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	execSQL    []string
}

func (f *fakeGatewayDB) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	f.execSQL = append(f.execSQL, sql)
	if f.execFn != nil {
		return f.execFn(ctx, sql, arguments...)
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (f *fakeGatewayDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, sql, args...)
	}
	return &fakeGatewayRows{}, nil
}

func (f *fakeGatewayDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.queryRowFn != nil {
		return f.queryRowFn(ctx, sql, args...)
	}
	return fakeGatewayRow{err: pgx.ErrNoRows}
}

type fakeGatewayRow struct {
	values []any
	err    error
}

func (r fakeGatewayRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("scan arity mismatch")
	}
	for i := range dest {
		if err := assignGatewayScan(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

type fakeGatewayRows struct {
	rows [][]any
	idx  int
	err  error
}

func (r *fakeGatewayRows) Close() {}

func (r *fakeGatewayRows) Err() error { return r.err }

func (r *fakeGatewayRows) CommandTag() pgconn.CommandTag { return pgconn.NewCommandTag("SELECT 1") }

func (r *fakeGatewayRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (r *fakeGatewayRows) Next() bool {
	if r.err != nil {
		return false
	}
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeGatewayRows) Scan(dest ...any) error {
	if r.idx == 0 || r.idx > len(r.rows) {
		return errors.New("no current row")
	}
	current := r.rows[r.idx-1]
	if len(dest) != len(current) {
		return errors.New("scan arity mismatch")
	}
	for i := range dest {
		if err := assignGatewayScan(dest[i], current[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *fakeGatewayRows) Values() ([]any, error) {
	if r.idx == 0 || r.idx > len(r.rows) {
		return nil, errors.New("no current row")
	}
	return append([]any(nil), r.rows[r.idx-1]...), nil
}

func (r *fakeGatewayRows) RawValues() [][]byte { return nil }

func (r *fakeGatewayRows) Conn() *pgx.Conn { return nil }

func assignGatewayScan(dest any, value any) error {
	switch d := dest.(type) {
	case *string:
		v, ok := value.(string)
		if !ok {
			return errors.New("value is not string")
		}
		*d = v
	case *[]byte:
		v, ok := value.([]byte)
		if !ok {
			return errors.New("value is not []byte")
		}
		*d = append((*d)[:0], v...)
	case *json.RawMessage:
		v, ok := value.([]byte)
		if !ok {
			return errors.New("value is not json raw")
		}
		*d = append((*d)[:0], v...)
	case *int:
		switch v := value.(type) {
		case int:
			*d = v
		case int32:
			*d = int(v)
		case int64:
			*d = int(v)
		default:
			return errors.New("value is not int")
		}
	case *float64:
		switch v := value.(type) {
		case float64:
			*d = v
		case int:
			*d = float64(v)
		case int64:
			*d = float64(v)
		default:
			return errors.New("value is not float64")
		}
	case *time.Time:
		v, ok := value.(time.Time)
		if !ok {
			return errors.New("value is not time.Time")
		}
		*d = v
	case **time.Time:
		if value == nil {
			*d = nil
			return nil
		}
		v, ok := value.(time.Time)
		if !ok {
			return errors.New("value is not *time.Time")
		}
		tmp := v
		*d = &tmp
	default:
		return errors.New("unsupported scan destination")
	}
	return nil
}

type fakeAuditStore struct {
	appendFn func(ctx context.Context, rec audit.Record) error
	getFn    func(ctx context.Context, decisionID, tenant string) (audit.Record, error)
}

func (f fakeAuditStore) Append(ctx context.Context, rec audit.Record) error {
	if f.appendFn != nil {
		return f.appendFn(ctx, rec)
	}
	return nil
}

func (f fakeAuditStore) Get(ctx context.Context, decisionID, tenant string) (audit.Record, error) {
	if f.getFn != nil {
		return f.getFn(ctx, decisionID, tenant)
	}
	return audit.Record{}, pgx.ErrNoRows
}

func withGatewayURLParams(req *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestGatewayDBCoreHelpers(t *testing.T) {
	respJSON, _ := json.Marshal(models.GatewayResponse{Verdict: "ALLOW", ReasonCode: "OK"})
	db := &fakeGatewayDB{}
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		if strings.Contains(sql, "FROM key_registry") {
			pk := make([]byte, ed25519.PublicKeySize)
			pk[0] = 1
			return fakeGatewayRow{values: []any{pk, "active"}}
		}
		if strings.Contains(sql, "SELECT response_json FROM decisions") {
			return fakeGatewayRow{values: []any{respJSON}}
		}
		return fakeGatewayRow{err: pgx.ErrNoRows}
	}
	s := &Server{
		DB:     db,
		Cache:  store.NewMemoryCache(),
		Config: rta.Config{MaxEscrowTTL: 2 * time.Hour},
	}
	intent := models.ActionIntent{ActionType: "TOOL_CALL", Target: models.Target{Domain: "finance"}}
	req := executeRequest{Intent: json.RawMessage(`{"intent_id":"i-1"}`), Cert: json.RawMessage(`{"cert_id":"c-1"}`), ToolPayload: json.RawMessage(`{"op":"write"}`)}
	cert := models.ActionCert{Claims: []models.Claim{{Type: "TwoPersonRule", Statement: "approvals_required >= 2"}}}
	policy := &policyir.PolicySetIR{Approvals: &policyir.ApprovalPolicy{Required: 3, ExpiresIn: 30 * time.Minute}}

	escrowID, err := s.createEscrow(context.Background(), "tenant-a", intent, req, cert, policy)
	if err != nil || escrowID == "" {
		t.Fatalf("createEscrow failed: id=%s err=%v", escrowID, err)
	}
	if _, err := s.updateEscrowStatus(context.Background(), escrowID, escrowfsm.Pending, escrowfsm.Closed); err == nil {
		t.Fatal("expected invalid transition error")
	}
	affected, err := s.updateEscrowStatus(context.Background(), escrowID, escrowfsm.Pending, escrowfsm.Approved)
	if err != nil || affected == 0 {
		t.Fatalf("expected successful status update, affected=%d err=%v", affected, err)
	}
	pk, status, err := s.lookupKey(context.Background(), "kid-1")
	if err != nil || status != "active" || len(pk) == 0 {
		t.Fatalf("lookupKey failed: status=%s len(pk)=%d err=%v", status, len(pk), err)
	}
	extPub := make([]byte, ed25519.PublicKeySize)
	extPub[0] = 7
	s.ExternalKeyStore = fakeExternalKeyStore{
		record: &auth.KeyRecord{
			Kid:       "kid-vault",
			Status:    "active",
			PublicKey: extPub,
		},
	}
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		return fakeGatewayRow{err: pgx.ErrNoRows}
	}
	pk, status, err = s.lookupKey(context.Background(), "kid-vault")
	if err != nil || status != "active" || len(pk) != ed25519.PublicKeySize || pk[0] != 7 {
		t.Fatalf("external lookupKey failed: status=%s len(pk)=%d err=%v", status, len(pk), err)
	}
	s.storeDecision(context.Background(), "tenant-a", "dec-1", "idemp-1", models.GatewayResponse{Verdict: "ALLOW", ReasonCode: "OK"})
	if out, ok := s.checkIdempotency(context.Background(), "tenant-a", "idemp-1"); !ok || out.Verdict != "ALLOW" {
		t.Fatalf("expected cached idempotency response, got ok=%v out=%#v", ok, out)
	}
	_ = s.Cache.Set(context.Background(), decisionCacheKey("tenant-a", "idemp-defer"), `{"verdict":"DEFER","reason_code":"WAIT"}`, time.Hour)
	if _, ok := s.checkIdempotency(context.Background(), "tenant-a", "idemp-defer"); ok {
		t.Fatal("DEFER should not be considered persisted idempotency response")
	}
	if _, err := s.acceptSequence(context.Background(), "kid", "tenant-a", "actor", "policy", -1, time.Minute); err == nil {
		t.Fatal("expected negative sequence to fail")
	}
	accepted, err := s.acceptSequence(context.Background(), "kid", "tenant-a", "actor", "policy", 4, time.Minute)
	if err != nil || !accepted {
		t.Fatalf("expected sequence accept, accepted=%v err=%v", accepted, err)
	}
	if got, err := s.Cache.Get(context.Background(), "seq:kid|tenant-a|actor|policy"); err != nil || got != "4" {
		t.Fatalf("expected cached sequence value, got=%q err=%v", got, err)
	}
}

func TestGatewayHandlerValidationAndProxy(t *testing.T) {
	s := &Server{DB: &fakeGatewayDB{}, AuthMode: "off"}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/escrows/approve", strings.NewReader(`{bad`))
	s.approveEscrow(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected approveEscrow invalid json 400, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/escrows/cancel", strings.NewReader(`{"actor":"u1"}`))
	s.cancelEscrow(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected cancelEscrow missing id 400, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/escrows/rollback", strings.NewReader(`{"actor":"u1"}`))
	s.rollbackEscrow(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected rollbackEscrow missing id 400, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = withGatewayURLParams(httptest.NewRequest(http.MethodGet, "/v1/escrows/e-1", nil), map[string]string{"escrow_id": "e-1"})
	s.getEscrow(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected getEscrow 404, got %d", rr.Code)
	}

	errDB := &fakeGatewayDB{queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
		return nil, errors.New("db down")
	}}
	s.DB = errDB
	rr = httptest.NewRecorder()
	s.listEscrows(rr, httptest.NewRequest(http.MethodGet, "/v1/escrows", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected listEscrows 500, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.listVerdicts(rr, httptest.NewRequest(http.MethodGet, "/v1/verdicts", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected listVerdicts 500, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.listIncidents(rr, httptest.NewRequest(http.MethodGet, "/v1/incidents", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected listIncidents 500, got %d", rr.Code)
	}

	s.DB = &fakeGatewayDB{}
	rr = httptest.NewRecorder()
	req = withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incidents/inc-1", strings.NewReader(`{"status":"ACKNOWLEDGED"}`)), map[string]string{"incident_id": "inc-1"})
	s.patchIncident(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected patchIncident actor required 400 in auth off mode, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.exportComplianceData(rr, httptest.NewRequest(http.MethodGet, "/v1/compliance/export", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected exportComplianceData actor required 400, got %d", rr.Code)
	}

	s.DB = &fakeGatewayDB{execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
		return pgconn.CommandTag{}, errors.New("retention fail")
	}}
	rr = httptest.NewRecorder()
	s.runRetentionNow(rr, httptest.NewRequest(http.MethodPost, "/v1/retention/run", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected runRetentionNow 500, got %d", rr.Code)
	}

	s.VerifierURL = "http://127.0.0.1:1"
	rr = httptest.NewRecorder()
	s.proxyVerify(rr, httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"x":1}`)))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected proxyVerify 502 on verifier down, got %d", rr.Code)
	}

	verifierSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"verdict":"DEFER"}`))
	}))
	defer verifierSrv.Close()
	s.VerifierURL = verifierSrv.URL
	outReq := httptest.NewRequest(http.MethodPost, "/v1/verify", strings.NewReader(`{"intent":{}}`))
	out := httptest.NewRecorder()
	s.proxyVerify(out, outReq)
	if out.Code != http.StatusAccepted || !strings.Contains(out.Body.String(), "DEFER") {
		t.Fatalf("expected proxied verifier response, got %d body=%s", out.Code, out.Body.String())
	}
}

func TestGatewayListPatchExportAndAuditReplay(t *testing.T) {
	now := time.Now().UTC()
	db := &fakeGatewayDB{}
	db.queryFn = func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
		switch {
		case strings.Contains(sql, "FROM escrows"):
			return &fakeGatewayRows{rows: [][]any{{"esc-1", "PENDING", now, now.Add(time.Hour), 2, 1}}}, nil
		case strings.Contains(sql, "FROM decisions"):
			return &fakeGatewayRows{rows: [][]any{{"dec-1", "idemp-1", "ALLOW", "OK", now}}}, nil
		case strings.Contains(sql, "FROM incidents"):
			return &fakeGatewayRows{rows: [][]any{{"inc-1", "dec-1", "HIGH", "SECURITY_POLICY", "SOD_FAIL", "OPEN", "title", []byte(`{"actor_id":"a1"}`), "", "", now, now, nil}}}, nil
		case strings.Contains(sql, "FROM audit_records"):
			return &fakeGatewayRows{rows: [][]any{{"dec-1", "v1", "ALLOW", "OK", now}}}, nil
		}
		return &fakeGatewayRows{}, nil
	}
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		switch {
		case strings.Contains(sql, "FROM escrows WHERE escrow_id"):
			return fakeGatewayRow{values: []any{"esc-1", "PENDING", now, now.Add(time.Hour), 2, 1}}
		case strings.Contains(sql, "FROM incidents WHERE incident_id"):
			return fakeGatewayRow{values: []any{"inc-1", "dec-1", "HIGH", "SECURITY_POLICY", "SOD_FAIL", "ACKNOWLEDGED", "title", []byte(`{"actor_id":"a1"}`), "alice", "", now, now, nil}}
		}
		return fakeGatewayRow{err: pgx.ErrNoRows}
	}
	db.execFn = func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
		if strings.Contains(sql, "UPDATE incidents") {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}

	aud := fakeAuditStore{getFn: func(ctx context.Context, decisionID, tenant string) (audit.Record, error) {
		return audit.Record{
			DecisionID:    decisionID,
			PolicyVersion: "v1",
			IntentRaw:     json.RawMessage(`{"intent_id":"i-1","actor":{"id":"a1"},"action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}}`),
			CertRaw:       json.RawMessage(`{"policy_set_id":"ps","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z","nonce":"n1","signature":{"kid":"k1"}}`),
			Verdict:       "ALLOW",
			ReasonCode:    "OK",
		}, nil
	}}

	s := &Server{DB: db, AuthMode: "off", Audit: aud, RetentionDays: 30, HTTPClient: &http.Client{Timeout: 2 * time.Second}, Config: rta.Config{MaxVerifyTime: 2 * time.Second}}

	rr := httptest.NewRecorder()
	s.listEscrows(rr, httptest.NewRequest(http.MethodGet, "/v1/escrows?limit=2", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "esc-1") {
		t.Fatalf("expected listEscrows success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.listVerdicts(rr, httptest.NewRequest(http.MethodGet, "/v1/verdicts?limit=2", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "dec-1") {
		t.Fatalf("expected listVerdicts success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.listIncidents(rr, httptest.NewRequest(http.MethodGet, "/v1/incidents?limit=2", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "inc-1") {
		t.Fatalf("expected listIncidents success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req := withGatewayURLParams(httptest.NewRequest(http.MethodGet, "/v1/escrows/esc-1", nil), map[string]string{"escrow_id": "esc-1"})
	s.getEscrow(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "esc-1") {
		t.Fatalf("expected getEscrow success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incidents/inc-1", strings.NewReader(`{"status":"ACKNOWLEDGED","actor":"alice"}`)), map[string]string{"incident_id": "inc-1"})
	s.patchIncident(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "ACKNOWLEDGED") {
		t.Fatalf("expected patchIncident success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.exportComplianceData(rr, httptest.NewRequest(http.MethodGet, "/v1/compliance/export?actor_id=a1&limit=10", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "actor_hash") {
		t.Fatalf("expected exportComplianceData success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withGatewayURLParams(httptest.NewRequest(http.MethodGet, "/v1/audit/dec-1", nil), map[string]string{"decision_id": "dec-1"})
	s.getAudit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "policy_version") {
		t.Fatalf("expected getAudit success, got %d body=%s", rr.Code, rr.Body.String())
	}

	verifierSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(models.VerifierResponse{Verdict: "ALLOW", ReasonCode: "OK"})
	}))
	defer verifierSrv.Close()
	s.VerifierURL = verifierSrv.URL
	rr = httptest.NewRecorder()
	req = withGatewayURLParams(httptest.NewRequest(http.MethodGet, "/v1/audit/dec-1/replay", nil), map[string]string{"decision_id": "dec-1"})
	s.replayAudit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"drift":false`) {
		t.Fatalf("expected replayAudit success with no drift, got %d body=%s", rr.Code, rr.Body.String())
	}

	s.VerifierURL = "http://127.0.0.1:1"
	rr = httptest.NewRecorder()
	s.replayAudit(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "REPLAY_UNAVAILABLE") {
		t.Fatalf("expected replayAudit degraded response, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestGatewayRetentionMetricsAndIncidentsHelpers(t *testing.T) {
	now := time.Now().UTC()
	db := &fakeGatewayDB{}
	db.execFn = func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
		switch {
		case strings.Contains(sql, "DELETE FROM decisions"):
			return pgconn.NewCommandTag("DELETE 2"), nil
		case strings.Contains(sql, "DELETE FROM escrows"):
			return pgconn.NewCommandTag("DELETE 1"), nil
		case strings.Contains(sql, "DELETE FROM incidents"):
			return pgconn.NewCommandTag("DELETE 3"), nil
		case strings.Contains(sql, "DELETE FROM belief_snapshots"):
			return pgconn.NewCommandTag("DELETE 4"), nil
		default:
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
	}
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		switch {
		case strings.Contains(sql, "COUNT(*) FROM escrows") && strings.Contains(sql, "status=$1 OR status=$2"):
			return fakeGatewayRow{values: []any{5}}
		case strings.Contains(sql, "MAX(EXTRACT(EPOCH") && strings.Contains(sql, "FROM escrows"):
			return fakeGatewayRow{values: []any{12.0}}
		case strings.Contains(sql, "FROM policy_versions WHERE status='PENDING_APPROVAL'"):
			return fakeGatewayRow{values: []any{2, 18.0}}
		case strings.Contains(sql, "FROM incidents") && strings.Contains(sql, "acknowledged_by IS NULL"):
			return fakeGatewayRow{values: []any{1}}
		}
		return fakeGatewayRow{err: pgx.ErrNoRows}
	}
	s := &Server{DB: db, RetentionDays: 14, Metrics: metrics.NewRegistry(), Cache: store.NewMemoryCache(), AuthMode: "off"}

	report, err := s.applyRetention(context.Background())
	if err != nil {
		t.Fatalf("applyRetention failed: %v", err)
	}
	tables := report["tables"].(map[string]int64)
	if tables["decisions"] != 2 || tables["escrows"] != 1 || tables["incidents"] != 3 || tables["belief_snapshots"] != 4 {
		t.Fatalf("unexpected retention report: %#v", report)
	}

	s.updateOperationalMetrics(context.Background())
	snap := s.Metrics.Snapshot()
	if snap.Gauges["escrow_pending"] != 5 || snap.Gauges["incidents_unack_critical"] != 1 {
		t.Fatalf("unexpected gauges: %#v", snap.Gauges)
	}

	stateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(models.BeliefState{SnapshotID: "snap-1", Domain: "finance"})
	}))
	defer stateSrv.Close()
	s.StateURL = stateSrv.URL
	belief, unknown := s.fetchSnapshot(context.Background(), "tenant-a", "finance")
	if unknown || belief.SnapshotID != "snap-1" {
		t.Fatalf("expected fetchSnapshot success, unknown=%v belief=%#v", unknown, belief)
	}

	s.StateURL = "http://127.0.0.1:1"
	if _, unknown := s.fetchSnapshot(context.Background(), "tenant-a", "finance"); !unknown {
		t.Fatal("expected fetchSnapshot unknown on upstream error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.expireEscrowsLoop(ctx)
	s.retentionLoop(ctx)
	s.metricsLoop(ctx)

	intent := models.ActionIntent{Actor: models.Actor{ID: "actor-1", Tenant: "tenant-a"}, Target: models.Target{Domain: "finance"}, Operation: models.Operation{Name: "pay"}}
	cert := models.ActionCert{PolicySetID: "ps", PolicyVersion: "v1"}
	rr := httptest.NewRecorder()
	s.writeDeny(rr, context.Background(), "SOD_FAIL", intent, cert, &models.Counterexample{MinimalFacts: []string{"x"}, FailedAxioms: []string{"A"}})
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "DENY") {
		t.Fatalf("expected deny response, got %d body=%s", rr.Code, rr.Body.String())
	}

	s.raiseRateLimitIncident(context.Background(), "dec-1", intent)
	s.raiseRateLimitIncident(context.Background(), "dec-1", intent)
	s.raiseAuthIncident(context.Background(), "UNAUTHENTICATED")
	if len(db.execSQL) == 0 {
		t.Fatal("expected incident-related DB writes")
	}

	unavailable := httptest.NewRecorder()
	s.Events = nil
	s.streamEvents(unavailable, httptest.NewRequest(http.MethodGet, "/v1/stream", nil))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected stream unavailable 503, got %d", unavailable.Code)
	}

	s.raiseIncident(context.Background(), "dec-1", "SECURITY_POLICY", "SOD_FAIL", "DENY", intent, cert, nil)
	if len(db.execSQL) == 0 || db.execSQL[len(db.execSQL)-1] == "" {
		t.Fatal("expected raiseIncident DB write")
	}

	_ = now
}

func TestGatewaySubjectRestrictionsAndBeliefProxy(t *testing.T) {
	now := time.Now().UTC()
	actorHash := hashIdentity("actor-1")
	db := &fakeGatewayDB{}
	db.execFn = func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	db.queryFn = func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
		if strings.Contains(sql, "FROM subject_restrictions") {
			return &fakeGatewayRows{rows: [][]any{{"tenant-a", actorHash, "gdpr-restriction", "compliance-1", now, "", nil}}}, nil
		}
		return &fakeGatewayRows{}, nil
	}
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		switch {
		case strings.Contains(sql, "SELECT reason") && strings.Contains(sql, "FROM subject_restrictions"):
			return fakeGatewayRow{values: []any{"gdpr-restriction"}}
		case strings.Contains(sql, "FROM subject_restrictions"):
			return fakeGatewayRow{values: []any{"tenant-a", actorHash, "gdpr-restriction", "compliance-1", now, "", nil}}
		}
		return fakeGatewayRow{err: pgx.ErrNoRows}
	}
	s := &Server{DB: db, AuthMode: "off", HTTPClient: &http.Client{Timeout: 2 * time.Second}}

	rr := httptest.NewRecorder()
	s.restrictSubject(rr, httptest.NewRequest(http.MethodPost, "/v1/compliance/subjects/restrict", strings.NewReader(`{"actor_id":"actor-1","reason":"gdpr-restriction","requested_by":"compliance-1","tenant":"tenant-a"}`)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), actorHash) {
		t.Fatalf("expected restrictSubject success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.listSubjectRestrictions(rr, httptest.NewRequest(http.MethodGet, "/v1/compliance/subjects/restrictions?actor_id=actor-1", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), actorHash) {
		t.Fatalf("expected listSubjectRestrictions success, got %d body=%s", rr.Code, rr.Body.String())
	}

	restricted, reason, err := s.isSubjectRestricted(context.Background(), "tenant-a", "actor-1")
	if err != nil || !restricted || reason != "gdpr-restriction" {
		t.Fatalf("expected isSubjectRestricted hit, restricted=%v reason=%q err=%v", restricted, reason, err)
	}

	rr = httptest.NewRecorder()
	s.unrestrictSubject(rr, httptest.NewRequest(http.MethodPost, "/v1/compliance/subjects/unrestrict", strings.NewReader(`{"actor_id":"actor-1","requested_by":"compliance-1","tenant":"tenant-a"}`)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), actorHash) {
		t.Fatalf("expected unrestrictSubject success, got %d body=%s", rr.Code, rr.Body.String())
	}

	stateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(models.BeliefState{
			Tenant:    "tenant-a",
			Domain:    "finance",
			Sources:   []models.SourceState{{Source: "bank", AgeSec: 4, HealthScore: 0.99, LagSec: 1, JitterSec: 1}},
			CreatedAt: now.Format(time.RFC3339),
		})
	}))
	defer stateSrv.Close()
	s.StateURL = stateSrv.URL
	rr = httptest.NewRecorder()
	s.proxyBeliefState(rr, httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"domain":"finance"`) {
		t.Fatalf("expected proxyBeliefState success, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleExecuteDeniedWhenSubjectRestricted(t *testing.T) {
	now := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	actorHash := hashIdentity("actor-1")
	db := &fakeGatewayDB{}
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		switch {
		case strings.Contains(sql, "SELECT response_json FROM decisions"):
			return fakeGatewayRow{err: pgx.ErrNoRows}
		case strings.Contains(sql, "SELECT reason") && strings.Contains(sql, "FROM subject_restrictions"):
			return fakeGatewayRow{values: []any{"gdpr-restriction"}}
		default:
			return fakeGatewayRow{err: pgx.ErrNoRows}
		}
	}
	s := &Server{
		DB:       db,
		Cache:    store.NewMemoryCache(),
		AuthMode: "off",
	}
	body := `{
		"intent": {
			"intent_id": "i-1",
			"idempotency_key": "idem-1",
			"actor": {"id": "actor-1", "roles": ["FinanceOperator"], "tenant": "tenant-a"},
			"action_type": "TOOL_CALL",
			"target": {"domain": "finance", "object_types": ["Invoice"], "object_ids": ["inv-1"], "scope": "single"},
			"operation": {"name": "pay_invoice", "params": {"amount": "10.00", "currency": "EUR"}},
			"time": {"event_time": "2026-02-10T10:00:00Z", "request_time": "2026-02-10T10:00:01Z"},
			"data_requirements": {"max_staleness_sec": 30, "required_sources": ["bank"], "uncertainty_budget": {"amount_abs": "1.00"}},
			"safety_mode": "NORMAL"
		},
		"cert": {
			"cert_id": "c-1",
			"intent_hash": "unused",
			"policy_set_id": "finance",
			"policy_version": "v17",
			"claims": [],
			"assumptions": {"open_system_terms": [], "uncertainty_budget": {}, "allowed_time_skew_sec": 10},
			"evidence": {"state_snapshot_refs": [], "attestations": []},
			"rollback_plan": {"type": "ESCROW", "steps": ["noop"]},
			"expires_at": "` + now + `",
			"nonce": "n-1",
			"signature": {"kid": "kid-1", "signer": "agent-key-1", "alg": "ed25519", "sig": "x"}
		},
		"tool_payload": {"op":"write"}
	}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(body))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"reason_code":"SUBJECT_RESTRICTED"`) || !strings.Contains(rr.Body.String(), actorHash) {
		t.Fatalf("expected SUBJECT_RESTRICTED deny, got %d body=%s", rr.Code, rr.Body.String())
	}
}
