package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/adapters/palantir"
	"axiom/pkg/ratelimit"
	"github.com/redis/go-redis/v9"
)

type fakeGatewayDBCloser struct {
	*fakeGatewayDB
	closed bool
}

func (f *fakeGatewayDBCloser) Close() {
	f.closed = true
}

func TestRunGateway(t *testing.T) {
	t.Run("telemetry_error", func(t *testing.T) {
		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return nil, errors.New("otel down")
			},
			func(context.Context) (gatewayDBCloser, error) {
				t.Fatal("openDB must not be called on telemetry error")
				return nil, nil
			},
			func(context.Context) (*redis.Client, error) {
				t.Fatal("openRedis must not be called on telemetry error")
				return nil, nil
			},
			func(*http.Server) error {
				t.Fatal("listen must not be called on telemetry error")
				return nil
			},
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "otel:") {
			t.Fatalf("expected wrapped telemetry error, got %v", err)
		}
	})

	t.Run("db_error", func(t *testing.T) {
		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return nil, errors.New("db down")
			},
			func(context.Context) (*redis.Client, error) {
				t.Fatal("openRedis must not be called on db error")
				return nil, nil
			},
			func(*http.Server) error {
				t.Fatal("listen must not be called on db error")
				return nil
			},
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "db:") {
			t.Fatalf("expected wrapped db error, got %v", err)
		}
	})

	t.Run("auth_off_guard", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "false")
		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}
		listenCalled := false

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				return nil, nil
			},
			func(*http.Server) error {
				listenCalled = true
				return nil
			},
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "ALLOW_INSECURE_AUTH_OFF=true") {
			t.Fatalf("expected auth-off guard error, got %v", err)
		}
		if listenCalled {
			t.Fatal("listen should not be called when auth off guard fails")
		}
		if !db.closed {
			t.Fatal("db must be closed on startup failure")
		}
	})

	t.Run("auth_off_forbidden_in_production_like_env", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("ENVIRONMENT", "production")
		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				return nil, nil
			},
			func(*http.Server) error {
				t.Fatal("listen should not run in production-like auth-off mode")
				return nil
			},
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "production-like") {
			t.Fatalf("expected production-like auth-off guard error, got %v", err)
		}
		if !db.closed {
			t.Fatal("db must be closed on startup failure")
		}
	})

	t.Run("strict_production_hardening_requires_db_tls", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "oidc_hs256")
		t.Setenv("ENVIRONMENT", "production")
		t.Setenv("STRICT_PROD_SECURITY", "true")
		t.Setenv("DATABASE_REQUIRE_TLS", "false")
		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				return nil, nil
			},
			func(*http.Server) error {
				t.Fatal("listen should not run when strict prod hardening fails")
				return nil
			},
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "DATABASE_REQUIRE_TLS=true") {
			t.Fatalf("expected strict prod DB TLS error, got %v", err)
		}
		if !db.closed {
			t.Fatal("db must be closed on startup failure")
		}
	})

	t.Run("listen_nil", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				return nil, nil
			},
			nil,
			nil,
		)
		if err == nil || !strings.Contains(err.Error(), "listen function required") {
			t.Fatalf("expected nil-listen error, got %v", err)
		}
		if !db.closed {
			t.Fatal("db must be closed")
		}
	})

	t.Run("success_mock_adapter_with_redis_fallback", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("RATE_LIMIT_ENABLED", "true")
		t.Setenv("RATE_LIMIT_WINDOW_SEC", "0")
		t.Setenv("POLICY_CACHE_TTL_SEC", "0")
		t.Setenv("ABAC_ATTR_CACHE_TTL_SEC", "0")
		t.Setenv("MAX_REQUEST_BODY_BYTES", "-1")
		t.Setenv("ADDR", ":18080")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "6")
		t.Setenv("HTTP_READ_TIMEOUT_SEC", "16")
		t.Setenv("HTTP_WRITE_TIMEOUT_SEC", "31")
		t.Setenv("HTTP_IDLE_TIMEOUT_SEC", "121")
		t.Setenv("ONTOLOGY_BACKEND", "mock")

		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}
		var captured *Server
		var listenCalled bool
		redisOpenCalls := 0

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				redisOpenCalls++
				return nil, errors.New("redis down")
			},
			func(server *http.Server) error {
				listenCalled = true
				if server.Addr != ":18080" {
					t.Fatalf("unexpected addr: %s", server.Addr)
				}
				if server.ReadHeaderTimeout != 6*time.Second || server.ReadTimeout != 16*time.Second || server.WriteTimeout != 31*time.Second || server.IdleTimeout != 121*time.Second {
					t.Fatalf("unexpected timeout config: %#v", server)
				}

				health := httptest.NewRecorder()
				server.Handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
				if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"service":"gateway"`) {
					t.Fatalf("unexpected health response: %d body=%s", health.Code, health.Body.String())
				}

				metricsReq := httptest.NewRecorder()
				server.Handler.ServeHTTP(metricsReq, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				if metricsReq.Code != http.StatusOK {
					t.Fatalf("expected metrics endpoint 200, got %d", metricsReq.Code)
				}

				invalidReq := httptest.NewRecorder()
				server.Handler.ServeHTTP(invalidReq, httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{`)))
				if invalidReq.Code != http.StatusBadRequest {
					t.Fatalf("expected invalid json from tool execute, got %d", invalidReq.Code)
				}

				return nil
			},
			func(s *Server) {
				captured = s
			},
		)
		if err != nil {
			t.Fatalf("expected startup success, got %v", err)
		}
		if !listenCalled {
			t.Fatal("listen was not called")
		}
		if redisOpenCalls != 1 {
			t.Fatalf("expected one redis open call, got %d", redisOpenCalls)
		}
		if captured == nil {
			t.Fatal("expected captured server")
		}
		if _, ok := captured.RateLimiter.(*ratelimit.InMemoryLimiter); !ok {
			t.Fatalf("expected in-memory limiter fallback, got %T", captured.RateLimiter)
		}
		if captured.RateLimitWindow != time.Minute {
			t.Fatalf("expected rate-limit window fallback 1m, got %s", captured.RateLimitWindow)
		}
		if captured.PolicyCacheTTL != 30*time.Second {
			t.Fatalf("expected policy cache ttl fallback 30s, got %s", captured.PolicyCacheTTL)
		}
		if captured.ABACAttrCacheTTL != 5*time.Minute {
			t.Fatalf("expected abac cache ttl fallback 5m, got %s", captured.ABACAttrCacheTTL)
		}
		if captured.MaxRequestBodyBytes != 1<<20 {
			t.Fatalf("expected body-size fallback 1MiB, got %d", captured.MaxRequestBodyBytes)
		}
		if _, ok := captured.OntologyExecutor.(palantir.HTTPExecutor); !ok {
			t.Fatalf("expected mock ontology executor (HTTP), got %T", captured.OntologyExecutor)
		}
		if !db.closed {
			t.Fatal("db must be closed on normal exit")
		}
	})

	t.Run("foundry_adapter_and_rate_limit_disabled", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("RATE_LIMIT_ENABLED", "false")
		t.Setenv("ONTOLOGY_BACKEND", "foundry")
		t.Setenv("FOUNDRY_BASE_URL", "https://foundry.example")
		t.Setenv("FOUNDRY_TOKEN", "token")
		t.Setenv("FOUNDRY_ONTOLOGY_ID", "ont-1")
		t.Setenv("FOUNDRY_ALLOW_BATCH", "false")
		t.Setenv("FOUNDRY_ALLOW_DRY_RUN", "false")
		t.Setenv("FOUNDRY_ALLOW_PREVIEW", "false")

		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}
		var captured *Server

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				return nil, nil
			},
			func(*http.Server) error { return nil },
			func(s *Server) {
				captured = s
			},
		)
		if err != nil {
			t.Fatalf("expected startup success, got %v", err)
		}
		if captured == nil {
			t.Fatal("expected captured server")
		}
		if captured.RateLimiter != nil {
			t.Fatalf("expected no limiter when disabled, got %T", captured.RateLimiter)
		}
		foundryExec, ok := captured.OntologyExecutor.(palantir.FoundryOntologyExecutor)
		if !ok {
			t.Fatalf("expected foundry executor, got %T", captured.OntologyExecutor)
		}
		if foundryExec.BaseURL != "https://foundry.example" || foundryExec.Token != "token" || foundryExec.OntologyID != "ont-1" {
			t.Fatalf("unexpected foundry config: %#v", foundryExec)
		}
		if foundryExec.AllowBatch || foundryExec.AllowDryRun || foundryExec.AllowPreview {
			t.Fatalf("expected foundry booleans false, got %#v", foundryExec)
		}
		if !db.closed {
			t.Fatal("db must be closed on normal exit")
		}
	})

	t.Run("listen_error_propagates", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		db := &fakeGatewayDBCloser{fakeGatewayDB: &fakeGatewayDB{}}
		expected := errors.New("listen failed")

		err := runGateway(
			func(context.Context, string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(context.Context) (gatewayDBCloser, error) {
				return db, nil
			},
			func(context.Context) (*redis.Client, error) {
				return nil, nil
			},
			func(*http.Server) error {
				return expected
			},
			nil,
		)
		if !errors.Is(err, expected) {
			t.Fatalf("expected listen error propagation, got %v", err)
		}
		if !db.closed {
			t.Fatal("db must be closed")
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
