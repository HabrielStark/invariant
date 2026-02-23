package main

import (
	"axiom/pkg/audit"
	"axiom/pkg/auth"
	"axiom/pkg/escrowfsm"
	"axiom/pkg/models"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ============================================================================
// APPROVE ESCROW TESTS - Target: 76.1% -> 100%
// ============================================================================

func TestApproveEscrowInvalidJSONBranch(t *testing.T) {
	s := &Server{AuthMode: "off", DB: &fakeGatewayDB{}}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{invalid`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected 400 invalid json, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowMissingEscrowIDBranch(t *testing.T) {
	s := &Server{AuthMode: "off", DB: &fakeGatewayDB{}}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "escrow_id required") {
		t.Fatalf("expected 400 escrow_id required, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowNotFoundBranch(t *testing.T) {
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeGatewayRow{err: pgx.ErrNoRows}
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1","approver":"user1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestApproveEscrowExpiredBranch(t *testing.T) {
	pastTime := time.Now().Add(-1 * time.Hour)
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "actor1"}})
			certRaw, _ := json.Marshal(models.ActionCert{})
			return fakeGatewayRow{values: []any{escrowfsm.Pending, pastTime, 1, 0, intentRaw, certRaw, []byte("{}"), "execute"}}
		},
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1","approver":"user1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "EXPIRED") {
		t.Fatalf("expected 200 EXPIRED, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowAlreadyApprovedBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "actor1"}})
			certRaw, _ := json.Marshal(models.ActionCert{})
			return fakeGatewayRow{values: []any{escrowfsm.Approved, futureTime, 1, 1, intentRaw, certRaw, []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1","approver":"user1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "APPROVED") {
		t.Fatalf("expected 200 APPROVED, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowInvalidStoredIntentBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeGatewayRow{values: []any{escrowfsm.Pending, futureTime, 1, 0, []byte(`{invalid`), []byte("{}"), []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1","approver":"user1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), "invalid stored intent") {
		t.Fatalf("expected 500 invalid stored intent, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowInvalidStoredCertBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "actor1"}})
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeGatewayRow{values: []any{escrowfsm.Pending, futureTime, 1, 0, intentRaw, []byte(`{invalid`), []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1","approver":"user1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), "invalid stored cert") {
		t.Fatalf("expected 500 invalid stored cert, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowMissingApproverBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "actor1"}})
	certRaw, _ := json.Marshal(models.ActionCert{})
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeGatewayRow{values: []any{escrowfsm.Pending, futureTime, 1, 0, intentRaw, certRaw, []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "approver required") {
		t.Fatalf("expected 400 approver required, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowUnauthenticatedBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "actor1"}})
	certRaw, _ := json.Marshal(models.ActionCert{})
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeGatewayRow{values: []any{escrowfsm.Pending, futureTime, 1, 0, intentRaw, certRaw, []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "oidc", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1"}`))
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 401 {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestApproveEscrowApproverMismatchBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "actor1"}})
	certRaw, _ := json.Marshal(models.ActionCert{})
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeGatewayRow{values: []any{escrowfsm.Pending, futureTime, 1, 0, intentRaw, certRaw, []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "oidc", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1","approver":"different_user"}`))
	ctx := auth.WithPrincipal(req.Context(), auth.Principal{Subject: "real_user", Roles: []string{"approver"}})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 403 || !strings.Contains(rr.Body.String(), "approver must match") {
		t.Fatalf("expected 403 approver mismatch, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestApproveEscrowSoDViolationBranch(t *testing.T) {
	futureTime := time.Now().Add(1 * time.Hour)
	intentRaw, _ := json.Marshal(models.ActionIntent{Actor: models.Actor{ID: "same_user"}})
	certRaw, _ := json.Marshal(models.ActionCert{})
	callCount := 0
	db := &fakeGatewayDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			callCount++
			return fakeGatewayRow{values: []any{escrowfsm.Pending, futureTime, 1, 0, intentRaw, certRaw, []byte("{}"), "execute"}}
		},
	}
	s := &Server{AuthMode: "oidc", DB: db}
	req := httptest.NewRequest(http.MethodPost, "/v1/escrow/approve", strings.NewReader(`{"escrow_id":"esc-1"}`))
	ctx := auth.WithPrincipal(req.Context(), auth.Principal{Subject: "same_user", Roles: []string{"approver"}})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	s.approveEscrow(rr, req)
	if rr.Code != 403 || !strings.Contains(rr.Body.String(), "approver cannot be actor") {
		t.Fatalf("expected 403 SoD violation, got %d %s", rr.Code, rr.Body.String())
	}
}

// ============================================================================
// PATCH INCIDENT TESTS - Target: 88.9% -> 100%
// ============================================================================

func TestPatchIncidentInvalidJSONBranch(t *testing.T) {
	s := &Server{AuthMode: "off", DB: &fakeGatewayDB{}}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{invalid`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected 400 invalid json, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestPatchIncidentUnauthenticatedBranch(t *testing.T) {
	s := &Server{AuthMode: "oidc", DB: &fakeGatewayDB{}}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"ACKNOWLEDGED"}`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 401 {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestPatchIncidentActorMismatchBranch(t *testing.T) {
	s := &Server{AuthMode: "oidc", DB: &fakeGatewayDB{}}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"ACKNOWLEDGED","actor":"other_user"}`)), map[string]string{"incident_id": "inc-1"})
	ctx := auth.WithPrincipal(req.Context(), auth.Principal{Subject: "real_user"})
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 403 || !strings.Contains(rr.Body.String(), "actor must match") {
		t.Fatalf("expected 403 actor mismatch, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestPatchIncidentInvalidStatusBranch(t *testing.T) {
	s := &Server{AuthMode: "off", DB: &fakeGatewayDB{}}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"INVALID","actor":"user1"}`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 400 || !strings.Contains(rr.Body.String(), "status must be") {
		t.Fatalf("expected 400 invalid status, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestPatchIncidentAcknowledgeDBErrorBranch(t *testing.T) {
	db := &fakeGatewayDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("db error")
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"ACKNOWLEDGED","actor":"user1"}`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 500 {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

func TestPatchIncidentNotOpenBranch(t *testing.T) {
	db := &fakeGatewayDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"ACKNOWLEDGED","actor":"user1"}`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 409 || !strings.Contains(rr.Body.String(), "not open") {
		t.Fatalf("expected 409 not open, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestPatchIncidentResolveDBErrorBranch(t *testing.T) {
	db := &fakeGatewayDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("db error")
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"RESOLVED","actor":"user1"}`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 500 {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}

func TestPatchIncidentAlreadyResolvedBranch(t *testing.T) {
	db := &fakeGatewayDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		},
	}
	s := &Server{AuthMode: "off", DB: db}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPatch, "/v1/incident/inc-1", strings.NewReader(`{"status":"RESOLVED","actor":"user1"}`)), map[string]string{"incident_id": "inc-1"})
	rr := httptest.NewRecorder()
	s.patchIncident(rr, req)
	if rr.Code != 409 || !strings.Contains(rr.Body.String(), "already resolved") {
		t.Fatalf("expected 409 already resolved, got %d %s", rr.Code, rr.Body.String())
	}
}

// ============================================================================
// EXPIRE ESCROWS LOOP TESTS - Target: 62.5% -> 100%
// ============================================================================

func TestExpireEscrowsLoopContextCancelBranch(t *testing.T) {
	db := &fakeGatewayDB{}
	s := &Server{DB: db}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		s.expireEscrowsLoop(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expireEscrowsLoop did not exit on context cancel")
	}
}

// ============================================================================
// STREAM EVENTS TESTS - Target: 80.0% -> 100%
// ============================================================================

func TestStreamEventsNoEventBusBranch(t *testing.T) {
	s := &Server{Events: nil}
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rr := httptest.NewRecorder()
	s.streamEvents(rr, req)
	if rr.Code != 503 {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

// ============================================================================
// REPLAY AUDIT TESTS - Target: 83.3% -> 100%
// ============================================================================

func TestReplayAuditNotFoundBranch(t *testing.T) {
	s := &Server{
		AuthMode: "off",
		DB:       &fakeGatewayDB{},
		Audit:    &fakeAuditStoreBranch{err: errors.New("not found")},
	}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPost, "/v1/audit/replay/dec-1", nil), map[string]string{"decision_id": "dec-1"})
	rr := httptest.NewRecorder()
	s.replayAudit(rr, req)
	if rr.Code != 404 {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestReplayAuditInvalidStoredCertBranch(t *testing.T) {
	s := &Server{
		AuthMode: "off",
		DB:       &fakeGatewayDB{},
		Audit:    &fakeAuditStoreBranch{rec: audit.Record{CertRaw: []byte(`{invalid`)}},
	}
	req := withGatewayURLParams(httptest.NewRequest(http.MethodPost, "/v1/audit/replay/dec-1", nil), map[string]string{"decision_id": "dec-1"})
	rr := httptest.NewRecorder()
	s.replayAudit(rr, req)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), "invalid stored cert") {
		t.Fatalf("expected 500 invalid stored cert, got %d %s", rr.Code, rr.Body.String())
	}
}

// ============================================================================
// RUN COMPENSATION TESTS - Target: 83.3% -> 100%
// ============================================================================

func TestRunCompensationNilRollbackPlanBranch(t *testing.T) {
	s := &Server{DB: &fakeGatewayDB{}}
	cert := models.ActionCert{}
	err := s.runCompensation(context.Background(), "execute", models.ActionIntent{}, cert)
	// Empty rollback plan may return error - just ensure it doesn't panic
	_ = err
}

// ============================================================================
// IS CRITICAL REASON TESTS - Target: 83.3% -> 100%
// ============================================================================

func TestIsCriticalReasonAllCasesBranch(t *testing.T) {
	cases := []struct {
		reason   string
		expected bool
	}{
		{"SOD_FAIL", true},
		{"ACCESS_FAIL", true},
		{"BAD_SIGNATURE", true},
		{"KEY_INVALID", true},
		{"REPLAY_DETECTED", true},
		{"SEQUENCE_REPLAY", true},
		{"INTENT_HASH_MISMATCH", true},
		{"SOD_CUSTOM", true},    // starts with SOD_
		{"ACCESS_DENIED", true}, // starts with ACCESS_
		{"NORMAL_REASON", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isCriticalReason(tc.reason); got != tc.expected {
			t.Errorf("isCriticalReason(%q) = %v, want %v", tc.reason, got, tc.expected)
		}
	}
}

// ============================================================================
// AS INT64 TESTS - Target: 87.5% -> 100%
// ============================================================================

func TestAsInt64AllTypesBranch(t *testing.T) {
	if v, ok := asInt64(int64(42)); !ok || v != 42 {
		t.Error("int64 failed")
	}
	if v, ok := asInt64(int(42)); !ok || v != 42 {
		t.Error("int failed")
	}
	// int32 not supported by asInt64 - should return false
	if _, ok := asInt64(int32(42)); ok {
		t.Error("int32 should NOT be supported")
	}
	if v, ok := asInt64(uint64(42)); !ok || v != 42 {
		t.Error("uint64 failed")
	}
	if v, ok := asInt64(float64(42.0)); !ok || v != 42 {
		t.Error("float64 failed")
	}
	if _, ok := asInt64("not a number"); ok {
		t.Error("string should fail")
	}
	if _, ok := asInt64(nil); ok {
		t.Error("nil should fail")
	}
	// Test uint64 overflow
	if _, ok := asInt64(uint64(1<<63 + 1)); ok {
		t.Error("uint64 overflow should fail")
	}
}

// ============================================================================
// HELPER TYPES (unique names to avoid conflicts)
// ============================================================================

type fakeAuditStoreBranch struct {
	rec audit.Record
	err error
}

func (a *fakeAuditStoreBranch) Get(ctx context.Context, decisionID, tenant string) (audit.Record, error) {
	if a.err != nil {
		return audit.Record{}, a.err
	}
	return a.rec, nil
}

func (a *fakeAuditStoreBranch) Append(ctx context.Context, rec audit.Record) error {
	return nil
}
