//go:build integration

package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestRunMigrationsWithRealPostgres tests migrations with real PostgreSQL
// Run with: go test -tags=integration -timeout 120s -run TestRunMigrationsWithRealPostgres ./cmd/migrator/...
func TestRunMigrationsWithRealPostgres(t *testing.T) {
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

	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer pool.Close()

	// Create temp migrations directory with sample file
	dir := t.TempDir()
	migFile := filepath.Join(dir, "001_test.sql")
	if err := os.WriteFile(migFile, []byte("CREATE TABLE test_table (id SERIAL PRIMARY KEY);"), 0644); err != nil {
		t.Fatalf("failed to write migration: %v", err)
	}

	logs := []string{}
	err = runMigrations(ctx, pool, dir,
		nil, // use os.ReadFile
		nil, // use filepath.Glob
		func(format string, args ...any) { logs = append(logs, format) },
	)
	if err != nil {
		t.Fatalf("runMigrations failed: %v", err)
	}

	// Verify migration was applied
	var exists bool
	err = pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename='001_test.sql')").Scan(&exists)
	if err != nil || !exists {
		t.Fatalf("migration not recorded: exists=%v err=%v", exists, err)
	}

	// Verify table was created
	_, err = pool.Exec(ctx, "INSERT INTO test_table DEFAULT VALUES")
	if err != nil {
		t.Fatalf("test_table not created: %v", err)
	}

	// Run again - should skip
	logs = []string{}
	err = runMigrations(ctx, pool, dir, nil, nil, func(format string, args ...any) { logs = append(logs, format) })
	if err != nil {
		t.Fatalf("second runMigrations failed: %v", err)
	}
}
