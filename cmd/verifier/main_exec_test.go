package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestMainDirect tests the actual main() function by overriding global vars
func TestMainDirect(t *testing.T) {
	origLogFatalf := logFatalf
	origInitTelemetry := initTelemetryFn
	origOpenDB := openDBFnV
	origListen := listenFnV
	defer func() {
		logFatalf = origLogFatalf
		initTelemetryFn = origInitTelemetry
		openDBFnV = origOpenDB
		listenFnV = origListen
	}()

	t.Run("main success path", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")

		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryFn = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		}
		openDBFnV = func(ctx context.Context) (verifierDB, func(), error) {
			return &fakeVerifierDBExec{}, func() {}, nil
		}
		listenFnV = func(server *http.Server) error { return nil }

		main()

		if fatalCalled {
			t.Fatal("logFatalf should not be called on success")
		}
	})

	t.Run("main error path calls logFatalf", func(t *testing.T) {
		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryFn = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return nil, errors.New("telemetry init failed")
		}

		main()

		if !fatalCalled {
			t.Fatal("logFatalf should be called on error")
		}
	})
}

// fakeVerifierDBExec implements verifierDB for testing
type fakeVerifierDBExec struct{}

func (f *fakeVerifierDBExec) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (f *fakeVerifierDBExec) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &fakeRowExec{}
}

type fakeRowExec struct{}

func (f *fakeRowExec) Scan(dest ...any) error { return nil }

// TestRunVerifierEdges tests edge cases in runVerifier
func TestRunVerifierEdges(t *testing.T) {
	t.Run("telemetry error", func(t *testing.T) {
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return nil, errors.New("telemetry failed")
			},
			nil,
			nil,
		)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("db error", func(t *testing.T) {
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return nil, nil, errors.New("db failed")
			},
			nil,
		)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("full server lifecycle", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("PUBLIC_KEY_BASE64", "")

		var capturedServer *http.Server
		err := runVerifier(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (verifierDB, func(), error) {
				return &fakeVerifierDBExec{}, func() {}, nil
			},
			func(server *http.Server) error {
				capturedServer = server
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
				server.Handler.ServeHTTP(rr, req)
				if rr.Code != 200 {
					return errors.New("healthz failed")
				}
				return errors.New("test-stop")
			},
		)

		if err == nil || err.Error() != "test-stop" {
			t.Fatalf("expected test-stop, got %v", err)
		}
		if capturedServer == nil {
			t.Fatal("server not captured")
		}
	})
}
