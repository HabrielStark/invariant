package main

import (
	"bytes"
	"context"
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
	"axiom/pkg/statebus"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeStateDB struct {
	execErr   error
	queryErr  error
	row       pgx.Row
	rows      pgx.Rows
	execArgs  []any
	queryArgs []any
}

func (f *fakeStateDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	_ = ctx
	_ = sql
	f.execArgs = append([]any(nil), args...)
	return pgconn.NewCommandTag("INSERT 0 1"), f.execErr
}

func (f *fakeStateDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	_ = ctx
	_ = sql
	f.queryArgs = append([]any(nil), args...)
	return f.rows, f.queryErr
}

func (f *fakeStateDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	_ = ctx
	_ = sql
	f.queryArgs = append([]any(nil), args...)
	if f.row != nil {
		return f.row
	}
	return fakeStateRow{err: errors.New("row not configured")}
}

type fakeStateRow struct {
	values []any
	err    error
}

func (r fakeStateRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("scan arity mismatch: got=%d want=%d", len(dest), len(r.values))
	}
	for i := range dest {
		if err := assignStateScan(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

type fakeStateRows struct {
	rows [][]any
	idx  int
	err  error
}

func (r *fakeStateRows) Close() {}
func (r *fakeStateRows) Err() error {
	return r.err
}
func (r *fakeStateRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT 1")
}
func (r *fakeStateRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}
func (r *fakeStateRows) Next() bool {
	return r.idx < len(r.rows)
}
func (r *fakeStateRows) Scan(dest ...any) error {
	if r.idx >= len(r.rows) {
		return errors.New("no current row")
	}
	row := r.rows[r.idx]
	r.idx++
	if len(dest) != len(row) {
		return fmt.Errorf("scan arity mismatch: got=%d want=%d", len(dest), len(row))
	}
	for i := range dest {
		if err := assignStateScan(dest[i], row[i]); err != nil {
			return err
		}
	}
	return nil
}
func (r *fakeStateRows) Values() ([]any, error) {
	if r.idx == 0 || r.idx > len(r.rows) {
		return nil, errors.New("no current row")
	}
	return r.rows[r.idx-1], nil
}
func (r *fakeStateRows) RawValues() [][]byte {
	return nil
}
func (r *fakeStateRows) Conn() *pgx.Conn {
	return nil
}

func assignStateScan(dest any, value any) error {
	switch d := dest.(type) {
	case *string:
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		*d = v
		return nil
	case *[]byte:
		switch v := value.(type) {
		case []byte:
			*d = append((*d)[:0], v...)
		case string:
			*d = append((*d)[:0], []byte(v)...)
		default:
			return fmt.Errorf("expected bytes/string, got %T", value)
		}
		return nil
	case *time.Time:
		v, ok := value.(time.Time)
		if !ok {
			return fmt.Errorf("expected time.Time, got %T", value)
		}
		*d = v
		return nil
	case *float64:
		v, ok := value.(float64)
		if !ok {
			return fmt.Errorf("expected float64, got %T", value)
		}
		*d = v
		return nil
	case *int:
		v, ok := value.(int)
		if !ok {
			return fmt.Errorf("expected int, got %T", value)
		}
		*d = v
		return nil
	default:
		return fmt.Errorf("unsupported scan destination %T", dest)
	}
}

type fakeStateBus struct {
	messages []statebus.Message
	idx      int
}

func (b *fakeStateBus) ReadMessage(ctx context.Context) (statebus.Message, error) {
	if b.idx < len(b.messages) {
		msg := b.messages[b.idx]
		b.idx++
		return msg, nil
	}
	<-ctx.Done()
	return statebus.Message{}, ctx.Err()
}

func (b *fakeStateBus) Close() error { return nil }

func TestResolveTenantAuthOff(t *testing.T) {
	s := &Server{AuthMode: "off"}
	req := httptest.NewRequest("GET", "/v1/beliefstate?domain=finance", nil)
	tenant, err := s.resolveTenant(req, "tenant-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", tenant)
	}
}

func TestResolveTenantAuthOnRequiresPrincipal(t *testing.T) {
	s := &Server{AuthMode: "oidc_hs256"}
	req := httptest.NewRequest("GET", "/v1/beliefstate?domain=finance", nil)
	if _, err := s.resolveTenant(req, "tenant-a"); err == nil {
		t.Fatal("expected unauthenticated error")
	}
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "user-1",
		Tenant:  "tenant-a",
		Roles:   []string{"operator"},
	}))
	tenant, err := s.resolveTenant(req, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tenant != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", tenant)
	}
}

func TestResolveTenantServiceRole(t *testing.T) {
	s := &Server{AuthMode: "oidc_hs256"}
	req := httptest.NewRequest("GET", "/v1/beliefstate?domain=finance", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "service",
		Roles:   []string{"service"},
	}))
	tenant, err := s.resolveTenant(req, "tenant-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tenant != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", tenant)
	}
}

func TestResolveTenantAdditionalBranches(t *testing.T) {
	t.Run("auth_off_uses_principal_tenant_when_request_empty", func(t *testing.T) {
		s := &Server{AuthMode: "off"}
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "u1",
			Tenant:  "tenant-principal",
		}))
		tenant, err := s.resolveTenant(req, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tenant != "tenant-principal" {
			t.Fatalf("expected principal tenant, got %q", tenant)
		}
	})

	t.Run("auth_off_without_tenant_returns_empty", func(t *testing.T) {
		s := &Server{AuthMode: "off"}
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
		tenant, err := s.resolveTenant(req, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tenant != "" {
			t.Fatalf("expected empty tenant, got %q", tenant)
		}
	})

	t.Run("service_principal_requires_request_tenant", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256"}
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "service",
			Roles:   []string{"service"},
		}))
		if _, err := s.resolveTenant(req, ""); err == nil || !strings.Contains(err.Error(), "tenant required") {
			t.Fatalf("expected tenant required error, got %v", err)
		}
	})

	t.Run("auth_on_principal_without_tenant_rejected", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256"}
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "u1",
			Roles:   []string{"operator"},
		}))
		if _, err := s.resolveTenant(req, ""); err == nil || !strings.Contains(err.Error(), "tenant required") {
			t.Fatalf("expected tenant required error, got %v", err)
		}
	})

	t.Run("auth_on_mismatch_rejected", func(t *testing.T) {
		s := &Server{AuthMode: "oidc_hs256"}
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
			Subject: "u1",
			Tenant:  "tenant-a",
			Roles:   []string{"operator"},
		}))
		if _, err := s.resolveTenant(req, "tenant-b"); err == nil || !strings.Contains(err.Error(), "tenant mismatch") {
			t.Fatalf("expected tenant mismatch error, got %v", err)
		}
	})
}

func TestServiceTokenValidAndServiceOrAuth(t *testing.T) {
	noConfig := &Server{}
	noCfgReq := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
	if noConfig.serviceTokenValid(noCfgReq) {
		t.Fatal("expected service token invalid when auth header/token config is empty")
	}

	s := &Server{
		ServiceAuthHeader: "X-State-Token",
		ServiceAuthToken:  "secret",
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?domain=finance", nil)
	if s.serviceTokenValid(req) {
		t.Fatal("expected missing token to be invalid")
	}
	req.Header.Set("X-State-Token", "secret")
	if !s.serviceTokenValid(req) {
		t.Fatal("expected matching service token to be valid")
	}
	req.Header.Set("X-State-Token", "wrong")
	if s.serviceTokenValid(req) {
		t.Fatal("expected mismatched service token to be invalid")
	}

	req.Header.Set("X-State-Token", "secret")
	var called bool
	authFallback := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	wrapped := s.serviceOrAuth(authFallback)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || principal.Subject != "service" {
			t.Fatalf("expected service principal, got %#v ok=%v", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || !called {
		t.Fatalf("expected service token path to succeed, code=%d called=%v", rr.Code, called)
	}
}

func TestUpdateSourcesAndGetBeliefStateHandlers(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	body := []byte(`{
		"tenant":"tenant-a",
		"domain":"finance",
		"sources":[
			{"source":"bank","age_sec":2,"health_score":0.97,"lag_sec":2,"jitter_sec":1},
			{"source":"erp","age_sec":1,"health_score":0.99,"lag_sec":1,"jitter_sec":0}
		]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/state/sources", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.updateSources(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected updateSources 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?tenant=tenant-a&domain=finance", nil)
	getRR := httptest.NewRecorder()
	s.getBeliefState(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected getBeliefState 200, got %d body=%s", getRR.Code, getRR.Body.String())
	}
	var state models.BeliefState
	if err := json.Unmarshal(getRR.Body.Bytes(), &state); err != nil {
		t.Fatalf("invalid belief state response: %v", err)
	}
	if state.Domain != "finance" || len(state.Sources) != 2 {
		t.Fatalf("unexpected belief state: %#v", state)
	}
}

func TestIngestEventHandler(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	eventTime := time.Now().UTC().Add(-3 * time.Second).Format(time.RFC3339)
	body := `{"tenant":"tenant-a","domain":"security","source":"siem","event_time":"` + eventTime + `","health_score":0.91,"jitter_sec":2}`
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected ingestEvent 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var state models.BeliefState
	if err := json.Unmarshal(rr.Body.Bytes(), &state); err != nil {
		t.Fatalf("invalid ingest response: %v", err)
	}
	if state.Domain != "security" || len(state.Sources) != 1 || state.Sources[0].Source != "siem" {
		t.Fatalf("unexpected ingest state: %#v", state)
	}
}

func TestStateEnvAndBodyLimitHelpers(t *testing.T) {
	t.Setenv("STATE_TEST_ENV", "v")
	if got := env("STATE_TEST_ENV", "x"); got != "v" {
		t.Fatalf("unexpected env: %s", got)
	}
	if got := env("STATE_TEST_ENV_MISSING", "x"); got != "x" {
		t.Fatalf("unexpected env fallback: %s", got)
	}
	t.Setenv("STATE_TEST_INT", "9")
	if got := envInt("STATE_TEST_INT", 1); got != 9 {
		t.Fatalf("unexpected envInt: %d", got)
	}
	t.Setenv("STATE_TEST_INT_BAD", "nope")
	if got := envInt("STATE_TEST_INT_BAD", 3); got != 3 {
		t.Fatalf("unexpected envInt fallback: %d", got)
	}
	t.Setenv("STATE_TEST_DUR", "4")
	if got := envDurationSec("STATE_TEST_DUR", 1); got != 4*time.Second {
		t.Fatalf("unexpected envDurationSec: %s", got)
	}

	s := &Server{MaxRequestBodyBytes: 8}
	handler := s.limitRequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"x":"0123456789"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestStateHandlerValidationPaths(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate", nil)
	s.getBeliefState(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when domain is missing, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/sources", strings.NewReader(`{bad`))
	s.updateSources(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid updateSources json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/sources", strings.NewReader(`{"tenant":"t1","domain":"","sources":[]}`))
	s.updateSources(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when updateSources domain is empty, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"tenant":"t1","domain":"finance","source":"bank","event_time":"bad"}`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad event_time, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"tenant":"t1","domain":"finance","source":"bank","event_time":"2026-02-03T11:00:00Z","ingestion_time":"bad"}`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad ingestion_time, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{bad`))
	s.createSnapshot(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid snapshot json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{"tenant":"t1","domain":"finance"}`))
	s.createSnapshot(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for snapshot without state, got %d", rr.Code)
	}
}

func TestGetBeliefStateAdditionalErrorPaths(t *testing.T) {
	t.Run("tenant_resolution_error", func(t *testing.T) {
		s := &Server{
			states:   map[string]map[string]map[string]sourceRecord{},
			AuthMode: "oidc_hs256",
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?tenant=t1&domain=finance", nil)
		s.getBeliefState(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for unauthenticated tenant resolution, got %d", rr.Code)
		}
	})

	t.Run("not_found_when_state_absent", func(t *testing.T) {
		s := &Server{
			states:   map[string]map[string]map[string]sourceRecord{},
			AuthMode: "off",
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/beliefstate?tenant=t1&domain=finance", nil)
		s.getBeliefState(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 when belief state is absent, got %d", rr.Code)
		}
	})
}

func TestSnapshotHandlersAndLoadState(t *testing.T) {
	now := time.Date(2026, 2, 6, 10, 0, 0, 0, time.UTC)
	statePayload, _ := json.Marshal(models.BeliefState{
		SnapshotID: "snap-1",
		Tenant:     "tenant-a",
		Domain:     "finance",
		Sources: []models.SourceState{
			{Source: "bank", AgeSec: 1, HealthScore: 0.99, LagSec: 1, JitterSec: 0},
		},
		CreatedAt: now.Format(time.RFC3339),
	})
	db := &fakeStateDB{
		row: fakeStateRow{values: []any{statePayload}},
		rows: &fakeStateRows{rows: [][]any{
			{"tenant-a", "finance", "bank", now.Add(-time.Second), now, 0.99, 1, 0},
		}},
	}
	s := &Server{
		DB:       db,
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	if err := s.loadSourceState(context.Background()); err != nil {
		t.Fatalf("loadSourceState: %v", err)
	}
	if _, ok := s.states["tenant-a"]["finance"]["bank"]; !ok {
		t.Fatalf("expected source state loaded into memory map: %#v", s.states)
	}

	router := chi.NewRouter()
	router.Get("/v1/state/snapshot/{snapshot_id}", s.getSnapshot)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/state/snapshot/snap-1?tenant=tenant-a", nil)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected getSnapshot 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	_ = s.applyEvent(eventInput{
		Tenant:      "tenant-a",
		Domain:      "finance",
		Source:      "erp",
		EventTime:   now.Add(-2 * time.Second),
		Ingestion:   now,
		HealthScore: 0.95,
		LagSec:      2,
		JitterSec:   1,
	})
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{"tenant":"tenant-a","domain":"finance"}`))
	s.createSnapshot(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected createSnapshot 201, got %d body=%s", rr.Code, rr.Body.String())
	}
	if len(db.execArgs) == 0 {
		t.Fatal("expected snapshot insert query to be executed")
	}
}

func TestSnapshotAndLoadErrorPaths(t *testing.T) {
	s := &Server{
		DB:       &fakeStateDB{queryErr: errors.New("db down")},
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	if err := s.loadSourceState(context.Background()); err == nil {
		t.Fatal("expected loadSourceState query error")
	}

	s.DB = &fakeStateDB{
		rows: &fakeStateRows{rows: [][]any{{"tenant-a", "finance", "bank", "bad", time.Now(), 0.9, 1, 0}}},
	}
	if err := s.loadSourceState(context.Background()); err == nil {
		t.Fatal("expected scan error from invalid row types")
	}

	s.DB = &fakeStateDB{rows: &fakeStateRows{rows: [][]any{}, err: errors.New("cursor failed")}}
	if err := s.loadSourceState(context.Background()); err == nil {
		t.Fatal("expected rows.Err failure")
	}

	router := chi.NewRouter()
	router.Get("/v1/state/snapshot/{snapshot_id}", s.getSnapshot)

	s.DB = &fakeStateDB{row: fakeStateRow{err: errors.New("not found")}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/state/snapshot/snap-404?tenant=tenant-a", nil)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing snapshot, got %d", rr.Code)
	}

	s.DB = &fakeStateDB{row: fakeStateRow{values: []any{[]byte("{bad-json")}}}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/state/snapshot/snap-bad?tenant=tenant-a", nil)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for corrupt snapshot payload, got %d", rr.Code)
	}

	s.DB = &fakeStateDB{execErr: errors.New("write failed")}
	s.states = map[string]map[string]map[string]sourceRecord{
		"tenant-a": {
			"finance": {
				"bank": {Source: "bank", EventTime: time.Now().Add(-time.Second), Ingestion: time.Now(), HealthScore: 1},
			},
		},
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{"tenant":"tenant-a","domain":"finance"}`))
	s.createSnapshot(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on snapshot insert failure, got %d", rr.Code)
	}
}

func TestPersistSourceStateAndConsumeEvents(t *testing.T) {
	s := &Server{
		DB:       &fakeStateDB{execErr: errors.New("persist failed")},
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	err := s.persistSourceState(eventInput{
		Tenant:      "tenant-a",
		Domain:      "finance",
		Source:      "bank",
		EventTime:   time.Now().Add(-time.Second),
		Ingestion:   time.Now(),
		HealthScore: 0.9,
		LagSec:      1,
	})
	if err == nil {
		t.Fatal("expected persistSourceState error")
	}

	s.DB = nil
	err = s.applyEvent(eventInput{Tenant: "tenant-a", Domain: "finance", Source: "bank"})
	if err != nil {
		t.Fatalf("expected applyEvent with nil DB to succeed, got %v", err)
	}
	if err := s.applyEvent(eventInput{Domain: "finance"}); err == nil {
		t.Fatal("expected applyEvent validation error for missing source")
	}

	valid := `{"tenant":"tenant-a","domain":"risk","source":"siem","event_time":"` + time.Now().Add(-time.Second).UTC().Format(time.RFC3339) + `"}`
	s.bus = &fakeStateBus{messages: []statebus.Message{
		{Value: []byte("{bad-json")},
		{Value: []byte(`{"tenant":"tenant-a","domain":"risk","source":"siem","event_time":"bad-time"}`)},
		{Value: []byte(valid)},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.buildBeliefState("tenant-a", "risk"); ok {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("consumeEvents did not apply valid message in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeEvents did not stop after context cancellation")
	}
}

func TestRunState(t *testing.T) {
	t.Run("telemetry_init_error", func(t *testing.T) {
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return nil, errors.New("otel failed")
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{}, func() {}, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "otel failed") {
			t.Fatalf("expected telemetry error, got %v", err)
		}
	})

	t.Run("db_open_error", func(t *testing.T) {
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return nil, nil, errors.New("db failed")
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "db failed") {
			t.Fatalf("expected db error, got %v", err)
		}
	})

	t.Run("auth_off_blocked_without_override", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "false")
		t.Setenv("KAFKA_ENABLED", "false")
		closed := false
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{rows: &fakeStateRows{}}, func() { closed = true }, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "AUTH_MODE=off is disabled") {
			t.Fatalf("expected auth-off guard error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback to run on startup guard failure")
		}
	})

	t.Run("auth_off_forbidden_in_production_like_env", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("KAFKA_ENABLED", "false")
		closed := false
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{rows: &fakeStateRows{}}, func() { closed = true }, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "production-like") {
			t.Fatalf("expected production-like auth-off guard error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback on startup guard failure")
		}
	})

	t.Run("strict_production_hardening_requires_db_tls", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "oidc_hs256")
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("STRICT_PROD_SECURITY", "true")
		t.Setenv("DATABASE_REQUIRE_TLS", "false")
		t.Setenv("KAFKA_ENABLED", "false")
		closed := false
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{rows: &fakeStateRows{}}, func() { closed = true }, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "DATABASE_REQUIRE_TLS=true") {
			t.Fatalf("expected strict prod DB TLS error, got %v", err)
		}
		if !closed {
			t.Fatal("expected db close callback on startup hardening failure")
		}
	})

	t.Run("server_config_and_routes", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "oidc_hs256")
		t.Setenv("KAFKA_ENABLED", "false")
		t.Setenv("ADDR", ":19083")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "7")
		t.Setenv("HTTP_READ_TIMEOUT_SEC", "11")
		t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "13")
		t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "17")
		t.Setenv("STATE_AUTH_HEADER", "X-State-Token")
		t.Setenv("STATE_AUTH_TOKEN", "state-secret")

		closed := false
		captured := &http.Server{}
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{rows: &fakeStateRows{}}, func() { closed = true }, nil
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
		if captured.Addr != ":19083" {
			t.Fatalf("expected addr :19083, got %q", captured.Addr)
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
		if healthRR.Code != http.StatusOK || !strings.Contains(healthRR.Body.String(), `"service":"state"`) {
			t.Fatalf("expected healthz response, got %d body=%s", healthRR.Code, healthRR.Body.String())
		}

		eventReq := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{bad`))
		eventReq.Header.Set("X-State-Token", "state-secret")
		eventRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(eventRR, eventReq)
		if eventRR.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid json response from state events route, got %d body=%s", eventRR.Code, eventRR.Body.String())
		}
	})
}
