package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/auth"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakePolicyDB struct {
	execFn     func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
}

func (f fakePolicyDB) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	if f.execFn != nil {
		return f.execFn(ctx, sql, arguments...)
	}
	return pgconn.NewCommandTag("INSERT 1"), nil
}

func (f fakePolicyDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, sql, args...)
	}
	return &fakeRows{}, nil
}

func (f fakePolicyDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.queryRowFn != nil {
		return f.queryRowFn(ctx, sql, args...)
	}
	return fakeRow{err: pgx.ErrNoRows}
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("scan arity mismatch")
	}
	for i := range dest {
		if err := assignScan(dest[i], r.values[i]); err != nil {
			return err
		}
	}
	return nil
}

type fakeRows struct {
	rows [][]any
	idx  int
	err  error
}

func (r *fakeRows) Close() {}

func (r *fakeRows) Err() error { return r.err }

func (r *fakeRows) CommandTag() pgconn.CommandTag { return pgconn.NewCommandTag("SELECT 1") }

func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

func (r *fakeRows) Next() bool {
	if r.err != nil {
		return false
	}
	if r.idx >= len(r.rows) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.idx == 0 || r.idx > len(r.rows) {
		return errors.New("no current row")
	}
	current := r.rows[r.idx-1]
	if len(dest) != len(current) {
		return errors.New("scan arity mismatch")
	}
	for i := range dest {
		if err := assignScan(dest[i], current[i]); err != nil {
			return err
		}
	}
	return nil
}

func (r *fakeRows) Values() ([]any, error) {
	if r.idx == 0 || r.idx > len(r.rows) {
		return nil, errors.New("no current row")
	}
	return append([]any(nil), r.rows[r.idx-1]...), nil
}

func (r *fakeRows) RawValues() [][]byte { return nil }

func (r *fakeRows) Conn() *pgx.Conn { return nil }

func assignScan(dest any, value any) error {
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

func withURLParams(req *http.Request, params map[string]string) *http.Request {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestCreatePolicySetAndCreatePolicyVersion(t *testing.T) {
	s := &Server{
		AuthMode: "off",
		DB:       fakePolicyDB{},
	}

	rr := httptest.NewRecorder()
	s.createPolicySet(rr, httptest.NewRequest(http.MethodPost, "/v1/policysets", strings.NewReader(`{bad`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid policyset json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.createPolicySet(rr, httptest.NewRequest(http.MethodPost, "/v1/policysets", strings.NewReader(`{"id":"ps-1","name":"Finance","domain":"finance"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for createPolicySet, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req := withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1"}`)), map[string]string{"id": "ps-1"})
	s.createPolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing dsl, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"policyset finance v1:","created_by":"alice","approvals_required":0}`)), map[string]string{"id": "ps-1"})
	s.createPolicyVersion(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 for createPolicyVersion, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v2","dsl":"policyset finance v2:","created_by":"alice","approvals_required":9}`)), map[string]string{"id": "ps-1"})
	s.createPolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for approvals_required out of range, got %d", rr.Code)
	}
}

func TestSubmitAndApprovePolicyVersion(t *testing.T) {
	rowCall := 0
	s := &Server{
		AuthMode: "off",
		DB: fakePolicyDB{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "SET status='PENDING_APPROVAL'") {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				}
				if strings.Contains(sql, "INSERT INTO policy_version_approvals") {
					return pgconn.NewCommandTag("INSERT 1"), nil
				}
				if strings.Contains(sql, "SET status='PUBLISHED'") {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				}
				return pgconn.NewCommandTag("UPDATE 1"), nil
			},
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM policy_versions") {
					return fakeRow{values: []any{"PENDING_APPROVAL", 2, "creator"}}
				}
				if strings.Contains(sql, "COUNT(*) FROM policy_version_approvals") {
					rowCall++
					if rowCall == 1 {
						return fakeRow{values: []any{1}}
					}
					return fakeRow{values: []any{2}}
				}
				return fakeRow{err: pgx.ErrNoRows}
			},
		},
	}

	rr := httptest.NewRecorder()
	req := withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/submit", strings.NewReader(`{"submitter":"alice"}`)), map[string]string{
		"id":      "ps-1",
		"version": "v1",
	})
	s.submitPolicyVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for submitPolicyVersion, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/approvals", strings.NewReader(`{"approver":"manager-1"}`)), map[string]string{
		"id":      "ps-1",
		"version": "v1",
	})
	s.approvePolicyVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for first approval, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"PENDING_APPROVAL"`) {
		t.Fatalf("expected pending status after first approval, body=%s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/approvals", strings.NewReader(`{"approver":"manager-2"}`)), map[string]string{
		"id":      "ps-1",
		"version": "v1",
	})
	s.approvePolicyVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for second approval, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"PUBLISHED"`) {
		t.Fatalf("expected published status after quorum, body=%s", rr.Body.String())
	}
}

func TestGetDiffEvaluatePolicyVersion(t *testing.T) {
	queryRowStep := 0
	now := time.Now().UTC()
	s := &Server{
		AuthMode: "off",
		DB: fakePolicyDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "SELECT dsl, status, approvals_required FROM policy_versions") {
					return fakeRow{values: []any{"policyset finance v1:", "PUBLISHED", 2}}
				}
				if strings.Contains(sql, "COUNT(*) FROM policy_version_approvals") {
					return fakeRow{values: []any{2}}
				}
				if strings.Contains(sql, "SELECT dsl FROM policy_versions") {
					queryRowStep++
					if queryRowStep == 1 {
						return fakeRow{values: []any{"policyset finance v1:\naxiom A:\n  when action.name == \"pay\"\n  require source(\"bank\").age_sec <= 30"}}
					}
					return fakeRow{values: []any{"policyset finance v2:\naxiom B:\n  when action.name == \"refund\"\n  require source(\"bank\").age_sec <= 30"}}
				}
				return fakeRow{err: pgx.ErrNoRows}
			},
			queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
				if strings.Contains(sql, "FROM policy_versions pv") {
					return &fakeRows{rows: [][]any{
						{"ps-1", "v2", "PUBLISHED", 2, 2, "alice", "bob", now, now, now},
					}}, nil
				}
				if strings.Contains(sql, "FROM policy_version_approvals") {
					return &fakeRows{rows: [][]any{
						{"bob", now},
						{"carol", now.Add(time.Minute)},
					}}, nil
				}
				return &fakeRows{}, nil
			},
		},
	}

	rr := httptest.NewRecorder()
	req := withURLParams(httptest.NewRequest(http.MethodGet, "/v1/policysets/ps-1/versions/v1", nil), map[string]string{"id": "ps-1", "version": "v1"})
	s.getPolicyVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for getPolicyVersion, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodGet, "/v1/policysets/ps-1/versions", nil), map[string]string{"id": "ps-1"})
	s.listPolicyVersions(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"items"`) {
		t.Fatalf("expected versions list, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodGet, "/v1/policysets/ps-1/versions/v1/approvals", nil), map[string]string{"id": "ps-1", "version": "v1"})
	s.listVersionApprovals(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"approver"`) {
		t.Fatalf("expected approvals list, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodGet, "/v1/policysets/ps-1/versions:diff?from=v1&to=v2", nil), map[string]string{"id": "ps-1"})
	s.diffPolicyVersions(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"added"`) {
		t.Fatalf("expected diff output, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"},"time":{"event_time":"2026-02-03T11:00:00Z","request_time":"2026-02-03T11:00:02Z"}},"belief_state_snapshot":{"domain":"finance","sources":[{"source":"bank","age_sec":3}]}}`)), map[string]string{"id": "ps-1", "version": "v1"})
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected evaluatePolicyVersion 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestKeyHandlers(t *testing.T) {
	pub := base64.StdEncoding.EncodeToString([]byte("ed25519-public"))
	s := &Server{
		AuthMode: "off",
		DB: fakePolicyDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				if strings.Contains(sql, "FROM key_registry WHERE kid=$1") {
					return fakeRow{values: []any{"agent-a", []byte("ed25519-public"), "active"}}
				}
				return fakeRow{err: pgx.ErrNoRows}
			},
			queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
				return &fakeRows{rows: [][]any{
					{"kid-1", "agent-a", "active", time.Now().UTC()},
				}}, nil
			},
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				if strings.Contains(sql, "UPDATE key_registry") {
					return pgconn.NewCommandTag("UPDATE 1"), nil
				}
				return pgconn.NewCommandTag("INSERT 1"), nil
			},
		},
	}

	rr := httptest.NewRecorder()
	s.createKey(rr, httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(`{"kid":"kid-1","signer":"agent-a","public_key":"bad"}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid key to fail, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.createKey(rr, httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(`{"kid":"kid-1","signer":"agent-a","public_key":"`+pub+`"}`)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected create key success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req := withURLParams(httptest.NewRequest(http.MethodGet, "/v1/keys/kid-1", nil), map[string]string{"kid": "kid-1"})
	s.getKey(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"kid":"kid-1"`) {
		t.Fatalf("expected getKey success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.listKeys(rr, httptest.NewRequest(http.MethodGet, "/v1/keys?status=active&limit=10", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"items"`) {
		t.Fatalf("expected listKeys success, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(`{"status":"unknown"}`)), map[string]string{"kid": "kid-1"})
	s.patchKey(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid patch status, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(`{"status":"active","public_key":"`+pub+`"}`)), map[string]string{"kid": "kid-1"})
	s.patchKey(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected patchKey success, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPolicyAuthModeOnGuards(t *testing.T) {
	s := &Server{
		AuthMode: "oidc_hs256",
		DB:       fakePolicyDB{},
	}
	req := withURLParams(
		httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"policyset finance v1:","created_by":"alice"}`)),
		map[string]string{"id": "ps-1"},
	)
	rr := httptest.NewRecorder()
	s.createPolicyVersion(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated createPolicyVersion, got %d", rr.Code)
	}

	req = withURLParams(
		httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/submit", strings.NewReader(`{"submitter":"alice"}`)),
		map[string]string{"id": "ps-1", "version": "v1"},
	)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "bob"}))
	rr = httptest.NewRecorder()
	s.submitPolicyVersion(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected submitter mismatch 403, got %d", rr.Code)
	}
}

func TestSubmitPolicyVersionBranches(t *testing.T) {
	newReq := func(body string) *http.Request {
		return withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/submit", strings.NewReader(body)),
			map[string]string{"id": "ps-1", "version": "v1"},
		)
	}
	s := &Server{
		AuthMode: "off",
		DB: fakePolicyDB{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 0"), nil
			},
		},
	}

	rr := httptest.NewRecorder()
	s.submitPolicyVersion(rr, newReq(`{"submitter":""}`))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when submitter missing in auth off mode, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.submitPolicyVersion(rr, newReq(`{"submitter":"alice"}`))
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 when draft status transition does not happen, got %d", rr.Code)
	}

	s.DB = fakePolicyDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("db failed")
		},
	}
	rr = httptest.NewRecorder()
	s.submitPolicyVersion(rr, newReq(`{"submitter":"alice"}`))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on db error, got %d", rr.Code)
	}
}

func TestCreatePolicyVersionAdditionalBranches(t *testing.T) {
	t.Run("auth_off_requires_created_by", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB:       fakePolicyDB{},
		}
		rr := httptest.NewRecorder()
		req := withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"policyset finance v1:"}`)),
			map[string]string{"id": "ps-1"},
		)
		s.createPolicyVersion(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when created_by missing in auth-off mode, got %d", rr.Code)
		}
	})

	t.Run("dsl_parse_error", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB:       fakePolicyDB{},
		}
		rr := httptest.NewRecorder()
		req := withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"not a valid dsl","created_by":"alice"}`)),
			map[string]string{"id": "ps-1"},
		)
		s.createPolicyVersion(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid dsl parse, got %d", rr.Code)
		}
	})

	t.Run("db_exec_error", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					return pgconn.CommandTag{}, errors.New("insert failed")
				},
			},
		}
		rr := httptest.NewRecorder()
		req := withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"policyset finance v1:","created_by":"alice"}`)),
			map[string]string{"id": "ps-1"},
		)
		s.createPolicyVersion(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for policy version insert failure, got %d", rr.Code)
		}
	})

	t.Run("auth_on_created_by_mismatch", func(t *testing.T) {
		s := &Server{
			AuthMode: "oidc_hs256",
			DB:       fakePolicyDB{},
		}
		req := withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"policyset finance v1:","created_by":"alice"}`)),
			map[string]string{"id": "ps-1"},
		)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "bob"}))
		rr := httptest.NewRecorder()
		s.createPolicyVersion(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for created_by mismatch, got %d", rr.Code)
		}
	})

	t.Run("auth_on_sets_created_by_from_principal", func(t *testing.T) {
		var captured []any
		s := &Server{
			AuthMode: "oidc_hs256",
			DB: fakePolicyDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					captured = append([]any(nil), arguments...)
					return pgconn.NewCommandTag("INSERT 1"), nil
				},
			},
		}
		req := withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions", strings.NewReader(`{"version":"v1","dsl":"policyset finance v1:","approvals_required":1}`)),
			map[string]string{"id": "ps-1"},
		)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "alice"}))
		rr := httptest.NewRecorder()
		s.createPolicyVersion(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 for auth-on createPolicyVersion, got %d body=%s", rr.Code, rr.Body.String())
		}
		if len(captured) < 7 {
			t.Fatalf("expected exec args to include created_by, got %d args", len(captured))
		}
		createdBy, ok := captured[6].(string)
		if !ok || createdBy != "alice" {
			t.Fatalf("expected created_by=alice from principal, got %#v", captured[6])
		}
	})
}

func TestGetPolicyVersionAdditionalBranches(t *testing.T) {
	req := withURLParams(
		httptest.NewRequest(http.MethodGet, "/v1/policysets/ps-1/versions/v1", nil),
		map[string]string{"id": "ps-1", "version": "v1"},
	)

	t.Run("not_found", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeRow{err: pgx.ErrNoRows}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.getPolicyVersion(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for missing version, got %d", rr.Code)
		}
	})

	t.Run("not_published", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeRow{values: []any{"policyset finance v1:", "DRAFT", 2}}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.getPolicyVersion(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for non-published version, got %d", rr.Code)
		}
	})

	t.Run("count_approvals_error", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "SELECT dsl, status, approvals_required FROM policy_versions") {
						return fakeRow{values: []any{"policyset finance v1:", "PUBLISHED", 2}}
					}
					return fakeRow{err: errors.New("count failed")}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.getPolicyVersion(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 when approvals count query fails, got %d", rr.Code)
		}
	})
}

func TestDiffPolicyVersionsAdditionalBranches(t *testing.T) {
	makeReq := func(rawURL string) *http.Request {
		return withURLParams(httptest.NewRequest(http.MethodGet, rawURL, nil), map[string]string{"id": "ps-1"})
	}

	t.Run("missing_from_or_to", func(t *testing.T) {
		s := &Server{AuthMode: "off", DB: fakePolicyDB{}}
		rr := httptest.NewRecorder()
		s.diffPolicyVersions(rr, makeReq("/v1/policysets/ps-1/versions:diff"))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when from/to missing, got %d", rr.Code)
		}
	})

	t.Run("from_version_missing", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeRow{err: pgx.ErrNoRows}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.diffPolicyVersions(rr, makeReq("/v1/policysets/ps-1/versions:diff?from=v1&to=v2"))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 when from version missing, got %d", rr.Code)
		}
	})

	t.Run("to_version_missing", func(t *testing.T) {
		call := 0
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					call++
					if call == 1 {
						return fakeRow{values: []any{"policyset finance v1:"}}
					}
					return fakeRow{err: pgx.ErrNoRows}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.diffPolicyVersions(rr, makeReq("/v1/policysets/ps-1/versions:diff?from=v1&to=v2"))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("expected 404 when to version missing, got %d", rr.Code)
		}
	})
}

func TestCreateKeyAdditionalBranches(t *testing.T) {
	t.Run("invalid_json", func(t *testing.T) {
		s := &Server{AuthMode: "off", DB: fakePolicyDB{}}
		rr := httptest.NewRecorder()
		s.createKey(rr, httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(`{bad`)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d", rr.Code)
		}
	})

	t.Run("db_exec_error", func(t *testing.T) {
		pub := base64.StdEncoding.EncodeToString([]byte("ed25519-public"))
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					return pgconn.CommandTag{}, errors.New("insert failed")
				},
			},
		}
		rr := httptest.NewRecorder()
		s.createKey(rr, httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(`{"kid":"kid-1","signer":"agent-a","public_key":"`+pub+`"}`)))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 when key insert fails, got %d", rr.Code)
		}
	})

	t.Run("autogenerated_kid", func(t *testing.T) {
		pub := base64.StdEncoding.EncodeToString([]byte("ed25519-public"))
		s := &Server{AuthMode: "off", DB: fakePolicyDB{}}
		rr := httptest.NewRecorder()
		s.createKey(rr, httptest.NewRequest(http.MethodPost, "/v1/keys", strings.NewReader(`{"signer":"agent-a","public_key":"`+pub+`"}`)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 for autogenerated kid path, got %d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"kid":"`) {
			t.Fatalf("expected response to include autogenerated kid, body=%s", rr.Body.String())
		}
	})
}

func TestApprovePolicyVersionBranches(t *testing.T) {
	newReq := func(body string) *http.Request {
		return withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/approvals", strings.NewReader(body)),
			map[string]string{"id": "ps-1", "version": "v1"},
		)
	}

	t.Run("status_draft_requires_submit", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "FROM policy_versions") {
						return fakeRow{values: []any{"DRAFT", 2, "creator"}}
					}
					return fakeRow{values: []any{0}}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, newReq(`{"approver":"manager-1"}`))
		if rr.Code != http.StatusConflict {
			t.Fatalf("expected 409 for DRAFT status, got %d", rr.Code)
		}
	})

	t.Run("status_published_count_error", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "FROM policy_versions") {
						return fakeRow{values: []any{"PUBLISHED", 2, "creator"}}
					}
					return fakeRow{err: errors.New("count failed")}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, newReq(`{"approver":"manager-1"}`))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on count failure, got %d", rr.Code)
		}
	})

	t.Run("status_published_success", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "FROM policy_versions") {
						return fakeRow{values: []any{"PUBLISHED", 2, "creator"}}
					}
					return fakeRow{values: []any{2}}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, newReq(`{"approver":"manager-1"}`))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"PUBLISHED"`) {
			t.Fatalf("expected published summary response, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("approver_must_differ_from_creator", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeRow{values: []any{"PENDING_APPROVAL", 2, "manager-1"}}
				},
			},
		}
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, newReq(`{"approver":"manager-1"}`))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for creator/approver overlap, got %d", rr.Code)
		}
	})

	t.Run("insert_approval_error", func(t *testing.T) {
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return fakeRow{values: []any{"PENDING_APPROVAL", 2, "creator"}}
				},
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					if strings.Contains(sql, "INSERT INTO policy_version_approvals") {
						return pgconn.CommandTag{}, errors.New("insert failed")
					}
					return pgconn.NewCommandTag("UPDATE 1"), nil
				},
			},
		}
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, newReq(`{"approver":"manager-1"}`))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on insert approval failure, got %d", rr.Code)
		}
	})

	t.Run("publish_update_error", func(t *testing.T) {
		rowCalls := 0
		s := &Server{
			AuthMode: "off",
			DB: fakePolicyDB{
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					if strings.Contains(sql, "FROM policy_versions") {
						return fakeRow{values: []any{"PENDING_APPROVAL", 1, "creator"}}
					}
					rowCalls++
					if rowCalls == 1 {
						return fakeRow{values: []any{1}}
					}
					return fakeRow{values: []any{1}}
				},
				execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
					if strings.Contains(sql, "SET status='PUBLISHED'") {
						return pgconn.CommandTag{}, errors.New("publish failed")
					}
					return pgconn.NewCommandTag("INSERT 1"), nil
				},
			},
		}
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, newReq(`{"approver":"manager-1"}`))
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 on publish update failure, got %d", rr.Code)
		}
	})

	t.Run("auth_on_approver_mismatch", func(t *testing.T) {
		s := &Server{
			AuthMode: "oidc_hs256",
			DB:       fakePolicyDB{},
		}
		req := withURLParams(
			httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/approvals", strings.NewReader(`{"approver":"alice"}`)),
			map[string]string{"id": "ps-1", "version": "v1"},
		)
		req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "bob"}))
		rr := httptest.NewRecorder()
		s.approvePolicyVersion(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for approver mismatch in auth mode, got %d", rr.Code)
		}
	})
}

func TestEvaluatePolicyVersionBranches(t *testing.T) {
	s := &Server{
		AuthMode: "off",
		DB: fakePolicyDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeRow{values: []any{`policyset finance v1:
axiom Role_guard:
  when action.name == "pay"
  require actor.role contains "Operator"`}}
			},
		},
	}
	reqBase := map[string]string{"id": "ps-1", "version": "v1"}

	rr := httptest.NewRecorder()
	req := withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{bad`)), reqBase)
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{}`)), reqBase)
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing intent, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{"intent":{"operation":{"params":{"amount":1.25}}}}`)), reqBase)
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for numeric token intent, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{"intent":123}`)), reqBase)
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid intent object, got %d", rr.Code)
	}

	s.DB = fakePolicyDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeRow{err: pgx.ErrNoRows}
		},
	}
	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay","params":{"amount":"1.00"}}}}`)), reqBase)
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when policy version missing, got %d", rr.Code)
	}

	s.DB = fakePolicyDB{
		queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return fakeRow{values: []any{"not a valid dsl"}}
		},
	}
	rr = httptest.NewRecorder()
	req = withURLParams(httptest.NewRequest(http.MethodPost, "/v1/policysets/ps-1/versions/v1/evaluate", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay","params":{"amount":"1.00"}}}}`)), reqBase)
	s.evaluatePolicyVersion(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for policy parse failure, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestPatchKeyBranches(t *testing.T) {
	newReq := func(body string) *http.Request {
		return withURLParams(
			httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(body)),
			map[string]string{"kid": "kid-1"},
		)
	}
	s := &Server{
		AuthMode: "off",
		DB: fakePolicyDB{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				return pgconn.NewCommandTag("UPDATE 0"), nil
			},
		},
	}
	rr := httptest.NewRecorder()
	s.patchKey(rr, withURLParams(
		httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(`{bad`)),
		map[string]string{"kid": "kid-1"},
	))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid patch json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.patchKey(rr, withURLParams(
		httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(`{"status":"active","public_key":"bad"}`)),
		map[string]string{"kid": "kid-1"},
	))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid public_key, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.patchKey(rr, newReq(`{"status":"active"}`))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no rows affected in status-only patch, got %d", rr.Code)
	}

	pub := base64.StdEncoding.EncodeToString([]byte("ed25519-public"))
	rr = httptest.NewRecorder()
	s.patchKey(rr, withURLParams(
		httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(`{"status":"active","public_key":"`+pub+`"}`)),
		map[string]string{"kid": "kid-1"},
	))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no rows affected in public_key patch, got %d", rr.Code)
	}

	s.DB = fakePolicyDB{
		execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
			return pgconn.CommandTag{}, errors.New("db failed")
		},
	}
	rr = httptest.NewRecorder()
	s.patchKey(rr, newReq(`{"status":"active"}`))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on status-only patch db failure, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	s.patchKey(rr, withURLParams(
		httptest.NewRequest(http.MethodPatch, "/v1/keys/kid-1", strings.NewReader(`{"status":"active","public_key":"`+pub+`"}`)),
		map[string]string{"kid": "kid-1"},
	))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on public_key patch db failure, got %d", rr.Code)
	}
}
