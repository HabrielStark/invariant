package store

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidatePostgresTLS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "verify_full_allowed",
			url:     "postgres://u:p@db:5432/x?sslmode=verify-full",
			wantErr: false,
		},
		{
			name:    "require_allowed",
			url:     "postgres://u:p@db:5432/x?sslmode=require",
			wantErr: false,
		},
		{
			name:    "prefer_denied",
			url:     "postgres://u:p@db:5432/x?sslmode=prefer",
			wantErr: true,
		},
		{
			name:    "missing_sslmode_denied",
			url:     "postgres://u:p@db:5432/x",
			wantErr: true,
		},
		{
			name:    "invalid_url_denied",
			url:     "://bad",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePostgresTLS(tt.url)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.url)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.url, err)
			}
		})
	}
}

func TestNewPostgresPoolRejectsInvalidInputs(t *testing.T) {
	t.Setenv("DATABASE_REQUIRE_TLS", "")
	t.Setenv("DATABASE_URL", "://bad")
	if _, err := NewPostgresPool(context.Background()); err == nil {
		t.Fatal("expected parse error for invalid dsn")
	}

	t.Setenv("DATABASE_REQUIRE_TLS", "true")
	t.Setenv("DATABASE_URL", "postgres://u:p@db:5432/x?sslmode=disable")
	_, err := NewPostgresPool(context.Background())
	if err == nil {
		t.Fatal("expected tls enforcement error")
	}
	if !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("expected insecure transport error, got %v", err)
	}
}

func TestRequiresSecureTransportVariants(t *testing.T) {
	t.Setenv("TRANSPORT_REQ", "true")
	if !requiresSecureTransport("TRANSPORT_REQ") {
		t.Fatal("expected true for \"true\"")
	}

	t.Setenv("TRANSPORT_REQ", "1")
	if !requiresSecureTransport("TRANSPORT_REQ") {
		t.Fatal("expected true for \"1\"")
	}

	t.Setenv("TRANSPORT_REQ", "off")
	if requiresSecureTransport("TRANSPORT_REQ") {
		t.Fatal("expected false for \"off\"")
	}
}

func TestNewPostgresPoolRetryExhaustedPing(t *testing.T) {
	origRetries := postgresConnectRetries
	origDelay := postgresRetryDelay
	origPingTimeout := postgresPingTimeout
	origSleep := postgresSleep
	origNew := pgxPoolNewWithConfig
	defer func() {
		postgresConnectRetries = origRetries
		postgresRetryDelay = origDelay
		postgresPingTimeout = origPingTimeout
		postgresSleep = origSleep
		pgxPoolNewWithConfig = origNew
	}()

	postgresConnectRetries = 1
	postgresRetryDelay = 0
	postgresPingTimeout = 50 * time.Millisecond
	postgresSleep = func(time.Duration) {}
	pgxPoolNewWithConfig = pgxpool.NewWithConfig

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	t.Setenv("DATABASE_REQUIRE_TLS", "")
	t.Setenv("DATABASE_URL", "postgres://u:p@"+addr+"/x?sslmode=disable")
	_, err = NewPostgresPool(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db ping retries exhausted") {
		t.Fatalf("expected retry exhausted error, got %v", err)
	}
}

func TestNewPostgresPoolNewWithConfigError(t *testing.T) {
	origRetries := postgresConnectRetries
	origDelay := postgresRetryDelay
	origPingTimeout := postgresPingTimeout
	origSleep := postgresSleep
	origNew := pgxPoolNewWithConfig
	defer func() {
		postgresConnectRetries = origRetries
		postgresRetryDelay = origDelay
		postgresPingTimeout = origPingTimeout
		postgresSleep = origSleep
		pgxPoolNewWithConfig = origNew
	}()

	postgresConnectRetries = 1
	postgresRetryDelay = 0
	postgresPingTimeout = 5 * time.Millisecond
	postgresSleep = func(time.Duration) {}
	pgxPoolNewWithConfig = func(context.Context, *pgxpool.Config) (*pgxpool.Pool, error) {
		return nil, errors.New("boom")
	}

	t.Setenv("DATABASE_REQUIRE_TLS", "")
	t.Setenv("DATABASE_URL", "postgres://u:p@127.0.0.1:5432/x?sslmode=disable")
	_, err := NewPostgresPool(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db ping retries exhausted") {
		t.Fatalf("expected wrapped retry error, got %v", err)
	}
}

func TestNewPostgresPoolSetsTenantRuntimeParams(t *testing.T) {
	origRetries := postgresConnectRetries
	origDelay := postgresRetryDelay
	origPingTimeout := postgresPingTimeout
	origSleep := postgresSleep
	origNew := pgxPoolNewWithConfig
	defer func() {
		postgresConnectRetries = origRetries
		postgresRetryDelay = origDelay
		postgresPingTimeout = origPingTimeout
		postgresSleep = origSleep
		pgxPoolNewWithConfig = origNew
	}()

	postgresConnectRetries = 1
	postgresRetryDelay = 0
	postgresPingTimeout = 5 * time.Millisecond
	postgresSleep = func(time.Duration) {}

	var runtimeParams map[string]string
	pgxPoolNewWithConfig = func(ctx context.Context, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
		runtimeParams = map[string]string{}
		for k, v := range cfg.ConnConfig.RuntimeParams {
			runtimeParams[k] = v
		}
		return nil, errors.New("boom")
	}

	t.Setenv("DATABASE_REQUIRE_TLS", "")
	t.Setenv("DATABASE_URL", "postgres://u:p@127.0.0.1:5432/x?sslmode=disable")
	t.Setenv("DB_TENANT_SCOPE", "all")
	t.Setenv("DB_TENANT_STATIC", "tenant-a")
	_, err := NewPostgresPool(context.Background())
	if err == nil {
		t.Fatal("expected error due mocked pool creation failure")
	}
	if got := runtimeParams["app.current_tenant_scope"]; got != "all" {
		t.Fatalf("expected app.current_tenant_scope=all, got %q", got)
	}
	if got := runtimeParams["app.current_tenant"]; got != "tenant-a" {
		t.Fatalf("expected app.current_tenant=tenant-a, got %q", got)
	}
}
