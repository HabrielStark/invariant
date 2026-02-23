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
	origOpenDB := openDBFnP
	origListen := listenFnP
	defer func() {
		logFatalf = origLogFatalf
		initTelemetryFn = origInitTelemetry
		openDBFnP = origOpenDB
		listenFnP = origListen
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
		openDBFnP = func(ctx context.Context) (policyDB, func(), error) {
			return &fakePolicyDBExec{}, func() {}, nil
		}
		listenFnP = func(server *http.Server) error { return nil }

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

// fakePolicyDBExec implements policyDB for testing
type fakePolicyDBExec struct{}

func (f *fakePolicyDBExec) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (f *fakePolicyDBExec) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}

func (f *fakePolicyDBExec) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &fakeRowPolicy{}
}

type fakeRowPolicy struct{}

func (f *fakeRowPolicy) Scan(dest ...any) error { return nil }

// TestRunPolicyEdges tests edge cases in runPolicy
func TestRunPolicyEdges(t *testing.T) {
	t.Run("telemetry error", func(t *testing.T) {
		err := runPolicy(
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
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
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

		var capturedServer *http.Server
		err := runPolicy(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (policyDB, func(), error) {
				return &fakePolicyDBExec{}, func() {}, nil
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
