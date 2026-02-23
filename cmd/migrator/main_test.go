package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeMigratorDB struct {
	execFn     func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	beginFn    func(ctx context.Context) (pgx.Tx, error)
}

func (f *fakeMigratorDB) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	if f.execFn != nil {
		return f.execFn(ctx, sql, arguments...)
	}
	return pgconn.NewCommandTag("EXEC 1"), nil
}

func (f *fakeMigratorDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.queryRowFn != nil {
		return f.queryRowFn(ctx, sql, args...)
	}
	return fakeMigratorRow{values: []any{false}}
}

func (f *fakeMigratorDB) Begin(ctx context.Context) (pgx.Tx, error) {
	if f.beginFn != nil {
		return f.beginFn(ctx)
	}
	return &fakeMigratorTx{}, nil
}

type fakeMigratorRow struct {
	values []any
	err    error
}

func (r fakeMigratorRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("scan arity mismatch")
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *bool:
			v, ok := r.values[i].(bool)
			if !ok {
				return errors.New("expected bool")
			}
			*d = v
		default:
			return errors.New("unsupported scan type")
		}
	}
	return nil
}

type fakeMigratorTx struct {
	execFn        func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	commitErr     error
	rollbackErr   error
	rollbackCalls int
}

func (t *fakeMigratorTx) Begin(ctx context.Context) (pgx.Tx, error) { return t, nil }
func (t *fakeMigratorTx) Commit(ctx context.Context) error          { return t.commitErr }
func (t *fakeMigratorTx) Rollback(ctx context.Context) error {
	t.rollbackCalls++
	return t.rollbackErr
}
func (t *fakeMigratorTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not implemented")
}
func (t *fakeMigratorTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults { return nil }
func (t *fakeMigratorTx) LargeObjects() pgx.LargeObjects                               { return pgx.LargeObjects{} }
func (t *fakeMigratorTx) Prepare(ctx context.Context, name string, sql string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not implemented")
}
func (t *fakeMigratorTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if t.execFn != nil {
		return t.execFn(ctx, sql, args...)
	}
	return pgconn.NewCommandTag("EXEC 1"), nil
}
func (t *fakeMigratorTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}
func (t *fakeMigratorTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return fakeMigratorRow{err: errors.New("not implemented")}
}
func (t *fakeMigratorTx) Conn() *pgx.Conn { return nil }

func TestValidateMigrationPath(t *testing.T) {
	t.Parallel()

	clean, err := validateMigrationPath("migrations", "migrations/001_init.sql")
	if err != nil {
		t.Fatalf("expected valid migration path, got error: %v", err)
	}
	if clean != filepath.Clean("migrations/001_init.sql") {
		t.Fatalf("unexpected clean path: %s", clean)
	}

	if _, err := validateMigrationPath("migrations", "../outside.sql"); err == nil {
		t.Fatal("expected rejection for outside migration path")
	}

	if _, err := validateMigrationPath("migrations", "other/001_init.sql"); err == nil {
		t.Fatal("expected rejection for different directory")
	}
}

func TestRunMigrationsSuccessAndSkip(t *testing.T) {
	db := &fakeMigratorDB{}
	tx := &fakeMigratorTx{}
	db.beginFn = func(ctx context.Context) (pgx.Tx, error) { return tx, nil }
	db.queryRowFn = func(ctx context.Context, sql string, args ...any) pgx.Row {
		base := args[0].(string)
		if base == "001_init.sql" {
			return fakeMigratorRow{values: []any{true}}
		}
		return fakeMigratorRow{values: []any{false}}
	}

	readCalls := 0
	readFile := func(name string) ([]byte, error) {
		readCalls++
		return []byte("SELECT 1;"), nil
	}
	glob := func(pattern string) ([]string, error) {
		return []string{"migrations/002_add.sql", "migrations/001_init.sql"}, nil
	}
	logs := make([]string, 0)
	logf := func(format string, args ...any) {
		logs = append(logs, format)
	}

	err := runMigrations(context.Background(), db, "migrations", readFile, glob, logf)
	if err != nil {
		t.Fatalf("runMigrations failed: %v", err)
	}
	if readCalls != 1 {
		t.Fatalf("expected one file read for unapplied migration, got %d", readCalls)
	}
	if tx.rollbackCalls != 0 {
		t.Fatalf("unexpected rollback calls: %d", tx.rollbackCalls)
	}
	if len(logs) < 2 {
		t.Fatalf("expected applied + summary logs, got %#v", logs)
	}
}

func TestRunMigrationsErrorBranches(t *testing.T) {
	t.Run("db required", func(t *testing.T) {
		err := runMigrations(context.Background(), nil, "migrations", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "db required") {
			t.Fatalf("expected db required error, got %v", err)
		}
	})

	t.Run("create table failure", func(t *testing.T) {
		db := &fakeMigratorDB{
			execFn: func(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, errors.New("create fail")
			},
		}
		err := runMigrations(context.Background(), db, "migrations", nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "create schema_migrations") {
			t.Fatalf("expected create schema error, got %v", err)
		}
	})

	t.Run("glob failure", func(t *testing.T) {
		db := &fakeMigratorDB{}
		glob := func(pattern string) ([]string, error) { return nil, errors.New("glob fail") }
		err := runMigrations(context.Background(), db, "migrations", nil, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "glob migrations") {
			t.Fatalf("expected glob error, got %v", err)
		}
	})

	t.Run("invalid migration path", func(t *testing.T) {
		db := &fakeMigratorDB{}
		glob := func(pattern string) ([]string, error) { return []string{"../evil.sql"}, nil }
		err := runMigrations(context.Background(), db, "migrations", nil, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "invalid migration path") {
			t.Fatalf("expected invalid path error, got %v", err)
		}
	})

	t.Run("lookup failure", func(t *testing.T) {
		db := &fakeMigratorDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeMigratorRow{err: errors.New("lookup fail")}
			},
		}
		glob := func(pattern string) ([]string, error) { return []string{"migrations/001.sql"}, nil }
		err := runMigrations(context.Background(), db, "migrations", nil, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "migration lookup") {
			t.Fatalf("expected lookup error, got %v", err)
		}
	})

	t.Run("read failure", func(t *testing.T) {
		db := &fakeMigratorDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeMigratorRow{values: []any{false}}
			},
		}
		glob := func(pattern string) ([]string, error) { return []string{"migrations/001.sql"}, nil }
		readFile := func(name string) ([]byte, error) { return nil, errors.New("read fail") }
		err := runMigrations(context.Background(), db, "migrations", readFile, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "read migration") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("begin failure", func(t *testing.T) {
		db := &fakeMigratorDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeMigratorRow{values: []any{false}}
			},
			beginFn: func(ctx context.Context) (pgx.Tx, error) {
				return nil, errors.New("begin fail")
			},
		}
		glob := func(pattern string) ([]string, error) { return []string{"migrations/001.sql"}, nil }
		readFile := func(name string) ([]byte, error) { return []byte("SELECT 1;"), nil }
		err := runMigrations(context.Background(), db, "migrations", readFile, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "begin migration tx") {
			t.Fatalf("expected begin error, got %v", err)
		}
	})

	t.Run("apply failure rollbacks", func(t *testing.T) {
		tx := &fakeMigratorTx{
			execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				return pgconn.CommandTag{}, errors.New("apply fail")
			},
		}
		db := &fakeMigratorDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeMigratorRow{values: []any{false}}
			},
			beginFn: func(ctx context.Context) (pgx.Tx, error) { return tx, nil },
		}
		glob := func(pattern string) ([]string, error) { return []string{"migrations/001.sql"}, nil }
		readFile := func(name string) ([]byte, error) { return []byte("SELECT 1;"), nil }
		err := runMigrations(context.Background(), db, "migrations", readFile, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "apply migration") {
			t.Fatalf("expected apply error, got %v", err)
		}
		if tx.rollbackCalls != 1 {
			t.Fatalf("expected rollback on apply failure, got %d", tx.rollbackCalls)
		}
	})

	t.Run("mark failure rollbacks", func(t *testing.T) {
		execCalls := 0
		tx := &fakeMigratorTx{
			execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
				execCalls++
				if execCalls == 2 {
					return pgconn.CommandTag{}, errors.New("mark fail")
				}
				return pgconn.NewCommandTag("EXEC 1"), nil
			},
		}
		db := &fakeMigratorDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeMigratorRow{values: []any{false}}
			},
			beginFn: func(ctx context.Context) (pgx.Tx, error) { return tx, nil },
		}
		glob := func(pattern string) ([]string, error) { return []string{"migrations/001.sql"}, nil }
		readFile := func(name string) ([]byte, error) { return []byte("SELECT 1;"), nil }
		err := runMigrations(context.Background(), db, "migrations", readFile, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "mark migration") {
			t.Fatalf("expected mark error, got %v", err)
		}
		if tx.rollbackCalls != 1 {
			t.Fatalf("expected rollback on mark failure, got %d", tx.rollbackCalls)
		}
	})

	t.Run("commit failure", func(t *testing.T) {
		tx := &fakeMigratorTx{
			commitErr: errors.New("commit fail"),
		}
		db := &fakeMigratorDB{
			queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
				return fakeMigratorRow{values: []any{false}}
			},
			beginFn: func(ctx context.Context) (pgx.Tx, error) { return tx, nil },
		}
		glob := func(pattern string) ([]string, error) { return []string{"migrations/001.sql"}, nil }
		readFile := func(name string) ([]byte, error) { return []byte("SELECT 1;"), nil }
		err := runMigrations(context.Background(), db, "migrations", readFile, glob, nil)
		if err == nil || !strings.Contains(err.Error(), "commit migration") {
			t.Fatalf("expected commit error, got %v", err)
		}
	})
}
