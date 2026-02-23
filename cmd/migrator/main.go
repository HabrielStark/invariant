package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"axiom/pkg/store"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type migrationDB interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

type migratorDBCloser interface {
	migrationDB
	Close()
}

// Testable variables for main()
var (
	logFatalf = log.Fatalf
	openDBFn  = func(ctx context.Context) (migratorDBCloser, error) {
		return store.NewPostgresPool(ctx)
	}
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := openDBFn(ctx)
	if err != nil {
		logFatalf("db: %v", err)
		return
	}
	defer pool.Close()

	if err := runMigrations(ctx, pool, "migrations", nil, nil, log.Printf); err != nil {
		logFatalf("migration: %v", err)
	}
}

func validateMigrationPath(migrationsDir, file string) (string, error) {
	cleanDir := filepath.Clean(migrationsDir)
	cleanFile := filepath.Clean(file)
	prefix := cleanDir + string(os.PathSeparator)
	if !strings.HasPrefix(cleanFile, prefix) {
		return "", fmt.Errorf("path %q is outside migrations dir %q", file, migrationsDir)
	}
	return cleanFile, nil
}

func runMigrations(
	ctx context.Context,
	db migrationDB,
	migrationsDir string,
	readFile func(name string) ([]byte, error),
	glob func(pattern string) ([]string, error),
	logf func(format string, args ...any),
) error {
	if db == nil {
		return fmt.Errorf("db required")
	}
	if readFile == nil {
		// #nosec G304 -- migration file path is validated by validateMigrationPath before read.
		readFile = os.ReadFile
	}
	if glob == nil {
		glob = filepath.Glob
	}
	if logf == nil {
		logf = log.Printf
	}

	if _, err := db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	migrationsDir = filepath.Clean(migrationsDir)
	files, err := glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return fmt.Errorf("glob migrations: %w", err)
	}
	sort.Strings(files)

	for _, file := range files {
		cleanFile, err := validateMigrationPath(migrationsDir, file)
		if err != nil {
			return fmt.Errorf("invalid migration path: %s", file)
		}
		var exists bool
		if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename=$1)`, filepath.Base(cleanFile)).Scan(&exists); err != nil {
			return fmt.Errorf("migration lookup: %w", err)
		}
		if exists {
			continue
		}
		sqlBytes, err := readFile(cleanFile)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", cleanFile, err)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration tx: %w", err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", file, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(filename) VALUES($1)`, filepath.Base(cleanFile)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("mark migration %s: %w", cleanFile, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", cleanFile, err)
		}
		logf("applied migration %s", filepath.Base(cleanFile))
	}

	logf("migration applied: %s", fmt.Sprintf("%d files", len(files)))
	return nil
}
