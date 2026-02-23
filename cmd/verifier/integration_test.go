//go:build integration

package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestRunVerifierWithRealPostgres tests the nil-openDB fallback with real PostgreSQL
// Run with: go test -tags=integration -timeout 120s -run TestRunVerifierWithRealPostgres ./cmd/verifier/...
func TestRunVerifierWithRealPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}
	defer func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			log.Printf("failed to terminate postgres container: %v", err)
		}
	}()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	pool, err := createVerifierSchema(ctx, connStr)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	defer pool.Close()

	t.Setenv("DATABASE_URL", connStr)
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("ADDR", "127.0.0.1:0")
	t.Setenv("POLICY_URL", "http://localhost:8082")

	errCh := make(chan error, 1)
	go func() {
		errCh <- runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			nil, // nil triggers fallback to store.NewPostgresPool (covers lines 69-77)
			func(server *http.Server) error {
				return errors.New("test-stop")
			},
		)
	}()

	select {
	case err := <-errCh:
		if err != nil && err.Error() != "test-stop" {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func createVerifierSchema(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS key_registry (
		kid TEXT PRIMARY KEY,
		public_key BYTEA NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS belief_snapshots (
		snapshot_id TEXT PRIMARY KEY,
		payload JSONB NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS decisions (
		decision_id TEXT PRIMARY KEY,
		idempotency_key TEXT UNIQUE,
		intent_id TEXT NOT NULL,
		verdict TEXT NOT NULL,
		reason_code TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	`
	_, err = pool.Exec(ctx, schema)
	return pool, err
}
