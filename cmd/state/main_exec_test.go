package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMainDirectState tests the actual main() function by overriding global vars
func TestMainDirectState(t *testing.T) {
	origLogFatalf := logFatalf
	origInitTelemetry := initTelemetryFn
	origOpenDB := openDBFnS
	origListen := listenFnS
	defer func() {
		logFatalf = origLogFatalf
		initTelemetryFn = origInitTelemetry
		openDBFnS = origOpenDB
		listenFnS = origListen
	}()

	t.Run("main success path", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("KAFKA_ENABLED", "false")

		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryFn = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		}
		openDBFnS = func(ctx context.Context) (stateDB, func(), error) {
			return &fakeStateDB{rows: &fakeStateRows{}}, func() {}, nil
		}
		listenFnS = func(server *http.Server) error { return nil }

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

// TestRunStateEdgesExec tests edge cases in runState
func TestRunStateEdgesExec(t *testing.T) {
	t.Run("telemetry error", func(t *testing.T) {
		err := runState(
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
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
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
		t.Setenv("KAFKA_ENABLED", "false")

		var capturedServer *http.Server
		err := runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{rows: &fakeStateRows{}}, func() {}, nil
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
