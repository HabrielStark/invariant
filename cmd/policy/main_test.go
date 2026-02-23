package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/auth"
)

func TestDiffLines(t *testing.T) {
	from := `policyset finance v1:
axiom A:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`

	to := `policyset finance v2:
axiom A:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
axiom Fresh:
  when action.name == "pay_invoice"
  require source("bank").age_sec <= 30`

	added, removed := diffLines(from, to)
	if len(added) == 0 {
		t.Fatal("expected added lines")
	}
	if len(removed) == 0 {
		t.Fatal("expected removed lines")
	}
	if !contains(added, `policyset finance v2:`) {
		t.Fatalf("missing expected added policy header: %#v", added)
	}
	if !contains(removed, `policyset finance v1:`) {
		t.Fatalf("missing expected removed policy header: %#v", removed)
	}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func TestNullTimeAndEnvHelpers(t *testing.T) {
	if nullTime("") != nil {
		t.Fatal("expected nil for empty time")
	}
	if nullTime("invalid") != nil {
		t.Fatal("expected nil for invalid time")
	}
	ts := "2026-02-05T10:00:00Z"
	parsed := nullTime(ts)
	if parsed == nil || parsed.Format(time.RFC3339) != ts {
		t.Fatalf("unexpected parsed time: %v", parsed)
	}

	t.Setenv("POLICY_TEST_ENV", "x")
	if got := env("POLICY_TEST_ENV", "y"); got != "x" {
		t.Fatalf("unexpected env value: %s", got)
	}
	if got := env("POLICY_TEST_ENV_MISSING", "y"); got != "y" {
		t.Fatalf("unexpected env fallback: %s", got)
	}
	t.Setenv("POLICY_TEST_INT", "42")
	if got := envInt("POLICY_TEST_INT", 7); got != 42 {
		t.Fatalf("unexpected env int value: %d", got)
	}
	t.Setenv("POLICY_TEST_INT_BAD", "bad")
	if got := envInt("POLICY_TEST_INT_BAD", 7); got != 7 {
		t.Fatalf("unexpected env int fallback: %d", got)
	}
	t.Setenv("POLICY_TEST_DUR", "3")
	if got := envDurationSec("POLICY_TEST_DUR", 1); got != 3*time.Second {
		t.Fatalf("unexpected env duration: %s", got)
	}
}

func TestRequireSubject(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := s.requireSubject(req); err == nil {
		t.Fatal("expected unauthenticated error")
	}

	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{Subject: "user-1"}))
	subject, err := s.requireSubject(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "user-1" {
		t.Fatalf("unexpected subject: %s", subject)
	}
}

func TestWithRoles(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	s := &Server{AuthMode: "off"}
	rr := httptest.NewRecorder()
	s.withRoles(handler, "operator").ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected auth-off pass through, got %d", rr.Code)
	}

	s.AuthMode = "oidc_hs256"
	rr = httptest.NewRecorder()
	s.withRoles(handler, "operator").ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without principal, got %d", rr.Code)
	}

	reqForbidden := req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "u1",
		Roles:   []string{"viewer"},
	}))
	rr = httptest.NewRecorder()
	s.withRoles(handler, "operator").ServeHTTP(rr, reqForbidden)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for role mismatch, got %d", rr.Code)
	}

	reqAllowed := req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "u1",
		Roles:   []string{"operator"},
	}))
	rr = httptest.NewRecorder()
	s.withRoles(handler, "operator").ServeHTTP(rr, reqAllowed)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected allowed role to pass, got %d", rr.Code)
	}
}

func TestLimitRequestBodyMiddleware(t *testing.T) {
	s := &Server{MaxRequestBodyBytes: 8}
	handler := s.limitRequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := ioReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"x":"0123456789"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized request body, got %d", rr.Code)
	}
}

func TestInternalTokenOnly(t *testing.T) {
	s := &Server{}
	handler := s.internalTokenOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/internal/policysets/finance/versions/v1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when internal auth is not configured, got %d", rr.Code)
	}

	s.PolicyAuthHeader = "X-Policy-Token"
	s.PolicyAuthToken = "secret"
	handler = s.internalTokenOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/internal/policysets/finance/versions/v1", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}

	badReq := httptest.NewRequest(http.MethodGet, "/v1/internal/policysets/finance/versions/v1", nil)
	badReq.Header.Set("X-Policy-Token", "bad")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, badReq)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong token, got %d", rr.Code)
	}

	okReq := httptest.NewRequest(http.MethodGet, "/v1/internal/policysets/finance/versions/v1", nil)
	okReq.Header.Set("X-Policy-Token", "secret")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, okReq)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 with valid token, got %d", rr.Code)
	}
}

func ioReadAll(body io.ReadCloser) ([]byte, error) {
	defer body.Close()
	return io.ReadAll(body)
}

func TestRunPolicy(t *testing.T) {
	t.Run("telemetry_init_error", func(t *testing.T) {
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return nil, errors.New("otel failed")
			},
			func(ctx context.Context) (policyDB, func(), error) {
				return fakePolicyDB{}, func() {}, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err == nil || !strings.Contains(err.Error(), "otel failed") {
			t.Fatalf("expected telemetry error, got %v", err)
		}
	})

	t.Run("db_open_error", func(t *testing.T) {
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
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
		closed := false
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
				return fakePolicyDB{}, func() { closed = true }, nil
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
		closed := false
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
				return fakePolicyDB{}, func() { closed = true }, nil
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
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
				return fakePolicyDB{}, func() { closed = true }, nil
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
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("ADDR", ":19082")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "7")
		t.Setenv("HTTP_READ_TIMEOUT_SEC", "11")
		t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "13")
		t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "17")

		closed := false
		captured := &http.Server{}
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
				return fakePolicyDB{}, func() { closed = true }, nil
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
		if captured.Addr != ":19082" {
			t.Fatalf("expected addr :19082, got %q", captured.Addr)
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
		if healthRR.Code != http.StatusOK || !strings.Contains(healthRR.Body.String(), `"service":"policy"`) {
			t.Fatalf("expected healthz response, got %d body=%s", healthRR.Code, healthRR.Body.String())
		}

		policyReq := httptest.NewRequest(http.MethodPost, "/v1/policysets", strings.NewReader(`{bad`))
		policyRR := httptest.NewRecorder()
		captured.Handler.ServeHTTP(policyRR, policyReq)
		if policyRR.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid-json policyset response, got %d body=%s", policyRR.Code, policyRR.Body.String())
		}
	})
}
