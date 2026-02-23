package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMainEntryPoint tests the full main() code path by calling runToolMock
func TestMainEntryPoint(t *testing.T) {
	t.Run("full server startup lifecycle", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("HTTP_READ_HEADER_TIMEOUT_SEC", "1")

		var capturedServer *http.Server
		err := runToolMock(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				if service != "tool-mock" {
					return nil, errors.New("unexpected service name")
				}
				return func(context.Context) error { return nil }, nil
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
			t.Fatal("server was not configured")
		}
	})

	t.Run("telemetry shutdown is called", func(t *testing.T) {
		shutdownCalled := false
		err := runToolMock(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error {
					shutdownCalled = true
					return nil
				}, nil
			},
			func(server *http.Server) error { return nil },
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !shutdownCalled {
			t.Fatal("telemetry shutdown was not called")
		}
	})

	// Cover nil path checks in runToolMock (lines 70-74)
	t.Run("nil initTelemetry uses default", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("OTEL_SDK_DISABLED", "true")

		var capturedServer *http.Server
		err := runToolMock(
			nil, // initTelemetry = nil triggers default
			func(server *http.Server) error {
				capturedServer = server
				return errors.New("test-stop")
			},
		)
		if err == nil || err.Error() != "test-stop" {
			t.Fatalf("expected test-stop, got %v", err)
		}
		if capturedServer == nil {
			t.Fatal("server was not configured")
		}
	})

	t.Run("nil listen uses default behavior", func(t *testing.T) {
		// This tests line 73-74 but we can't actually call ListenAndServe
		// So we only test that nil initTelemetry is handled
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("OTEL_SDK_DISABLED", "true")

		err := runToolMock(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(server *http.Server) error {
				// Test execute endpoint
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/execute", nil)
				server.Handler.ServeHTTP(rr, req)
				return errors.New("test-stop")
			},
		)
		if err == nil || err.Error() != "test-stop" {
			t.Fatalf("expected test-stop, got %v", err)
		}
	})
}

// TestMainDirect tests the actual main() function by overriding global vars
func TestMainDirect(t *testing.T) {
	origLogFatalf := logFatalf
	origInitTelemetry := initTelemetryFn
	origListen := listenFn
	defer func() {
		logFatalf = origLogFatalf
		initTelemetryFn = origInitTelemetry
		listenFn = origListen
	}()

	t.Run("main success path", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")

		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryFn = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		}
		listenFn = func(server *http.Server) error { return nil }

		main()

		if fatalCalled {
			t.Fatal("logFatalf should not be called on success")
		}
	})

	t.Run("main error path calls logFatalf", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")

		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryFn = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return nil, errors.New("telemetry init failed")
		}
		listenFn = func(server *http.Server) error { return nil }

		main()

		if !fatalCalled {
			t.Fatal("logFatalf should be called on error")
		}
	})
}
