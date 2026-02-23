package main

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMainDirectMigrator tests the actual main() function by overriding global vars
func TestMainDirectMigrator(t *testing.T) {
	origLogFatalf := logFatalf
	origOpenDB := openDBFn
	defer func() {
		logFatalf = origLogFatalf
		openDBFn = origOpenDB
	}()

	t.Run("main success path", func(t *testing.T) {
		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		openDBFn = func(ctx context.Context) (migratorDBCloser, error) {
			return &fakeMigratorDBCloser{
				execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
					return pgconn.CommandTag{}, nil
				},
				queryRowFn: func(ctx context.Context, sql string, args ...any) pgx.Row {
					return &fakeRowMig{exists: true}
				},
			}, nil
		}

		main()

		if fatalCalled {
			t.Fatal("logFatalf should not be called on success")
		}
	})

	t.Run("main db error calls logFatalf", func(t *testing.T) {
		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		openDBFn = func(ctx context.Context) (migratorDBCloser, error) {
			return nil, errors.New("db connection failed")
		}

		main()

		if !fatalCalled {
			t.Fatal("logFatalf should be called on db error")
		}
	})

	t.Run("main migration error calls logFatalf", func(t *testing.T) {
		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		openDBFn = func(ctx context.Context) (migratorDBCloser, error) {
			return &fakeMigratorDBCloser{
				execFn: func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
					return pgconn.CommandTag{}, errors.New("exec failed")
				},
			}, nil
		}

		main()

		if !fatalCalled {
			t.Fatal("logFatalf should be called on migration error")
		}
	})
}

// fakeMigratorDBCloser implements migratorDBCloser for testing
type fakeMigratorDBCloser struct {
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
	beginFn    func(ctx context.Context) (pgx.Tx, error)
}

func (f *fakeMigratorDBCloser) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if f.execFn != nil {
		return f.execFn(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}

func (f *fakeMigratorDBCloser) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if f.queryRowFn != nil {
		return f.queryRowFn(ctx, sql, args...)
	}
	return &fakeRowMig{}
}

func (f *fakeMigratorDBCloser) Begin(ctx context.Context) (pgx.Tx, error) {
	if f.beginFn != nil {
		return f.beginFn(ctx)
	}
	return &fakeTxMig{}, nil
}

func (f *fakeMigratorDBCloser) Close() {}

// fakeRowMig implements pgx.Row
type fakeRowMig struct {
	exists bool
}

func (f *fakeRowMig) Scan(dest ...any) error {
	if len(dest) > 0 {
		if b, ok := dest[0].(*bool); ok {
			*b = f.exists
		}
	}
	return nil
}

// fakeTxMig implements pgx.Tx
type fakeTxMig struct {
	execFn     func(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	commitFn   func(ctx context.Context) error
	rollbackFn func(ctx context.Context) error
}

func (f *fakeTxMig) Begin(ctx context.Context) (pgx.Tx, error) { return nil, nil }
func (f *fakeTxMig) Commit(ctx context.Context) error {
	if f.commitFn != nil {
		return f.commitFn(ctx)
	}
	return nil
}
func (f *fakeTxMig) Rollback(ctx context.Context) error {
	if f.rollbackFn != nil {
		return f.rollbackFn(ctx)
	}
	return nil
}
func (f *fakeTxMig) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (f *fakeTxMig) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults { return nil }
func (f *fakeTxMig) LargeObjects() pgx.LargeObjects                               { return pgx.LargeObjects{} }
func (f *fakeTxMig) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, nil
}
func (f *fakeTxMig) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if f.execFn != nil {
		return f.execFn(ctx, sql, args...)
	}
	return pgconn.CommandTag{}, nil
}
func (f *fakeTxMig) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}
func (f *fakeTxMig) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &fakeRowMig{}
}
func (f *fakeTxMig) Conn() *pgx.Conn { return nil }
