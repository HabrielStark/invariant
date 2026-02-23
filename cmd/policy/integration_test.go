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

// TestRunPolicyWithRealPostgres tests the nil-openDB fallback with a real PostgreSQL container
// Run with: go test -tags=integration -timeout 60s -run TestRunPolicyWithRealPostgres ./cmd/policy/...
func TestRunPolicyWithRealPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Start PostgreSQL container
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

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %v", err)
	}

	// Create schema first
	pool, err := createSchema(ctx, connStr)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}
	defer pool.Close()

	// Set environment for the test
	t.Setenv("DATABASE_URL", connStr)
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("ADDR", "127.0.0.1:0")

	// Run the server with nil-openDB to trigger fallback
	errCh := make(chan error, 1)
	go func() {
		errCh <- runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			nil, // nil triggers fallback to store.NewPostgresPool (covers lines 79-87)
			func(server *http.Server) error {
				// Return immediately - we just want to test the openDB fallback was hit
				return errors.New("test-stop")
			},
		)
	}()

	select {
	case err := <-errCh:
		if err != nil && err.Error() != "test-stop" {
			t.Fatalf("unexpected error: %v", err)
		}
		// Success - nil-openDB fallback was executed and connected to real PostgreSQL
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server")
	}
}

func createSchema(ctx context.Context, connStr string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS key_registry (
		kid TEXT PRIMARY KEY,
		signer TEXT NOT NULL,
		public_key BYTEA NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS policy_sets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		domain TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS policy_versions (
		id SERIAL PRIMARY KEY,
		policy_set_id TEXT NOT NULL REFERENCES policy_sets(id),
		version TEXT NOT NULL,
		dsl TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'DRAFT',
		created_by TEXT,
		submitted_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE TABLE IF NOT EXISTS policy_version_approvals (
		id SERIAL PRIMARY KEY,
		policy_set_id TEXT NOT NULL,
		version TEXT NOT NULL,
		approver TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	`
	_, err = pool.Exec(ctx, schema)
	return pool, err
}
