package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

// TestMainDirectGateway tests the actual main() function by overriding global vars
func TestMainDirectGateway(t *testing.T) {
	origLogFatalf := logFatalf
	origInitTelemetry := initTelemetryG
	origOpenDB := openDBFnG
	origOpenRedis := openRedisFnG
	origListen := listenFnG
	origStartLoops := startLoopsFnG
	defer func() {
		logFatalf = origLogFatalf
		initTelemetryG = origInitTelemetry
		openDBFnG = origOpenDB
		openRedisFnG = origOpenRedis
		listenFnG = origListen
		startLoopsFnG = origStartLoops
	}()

	t.Run("main success path", func(t *testing.T) {
		t.Setenv("ADDR", "127.0.0.1:0")
		t.Setenv("AUTH_MODE", "off")
		t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
		t.Setenv("VERIFIER_URL", "http://localhost:8083")
		t.Setenv("STATE_URL", "http://localhost:8081")

		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryG = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		}
		openDBFnG = func(ctx context.Context) (gatewayDBCloser, error) {
			return &mockDBCloserGW{}, nil
		}
		openRedisFnG = func(ctx context.Context) (*redis.Client, error) {
			return nil, nil
		}
		listenFnG = func(server *http.Server) error { return nil }
		startLoopsFnG = func(s *Server) {}

		main()

		if fatalCalled {
			t.Fatal("logFatalf should not be called on success")
		}
	})

	t.Run("main error path calls logFatalf", func(t *testing.T) {
		fatalCalled := false
		logFatalf = func(format string, args ...any) { fatalCalled = true }
		initTelemetryG = func(ctx context.Context, service string) (func(context.Context) error, error) {
			return nil, errors.New("telemetry init failed")
		}

		main()

		if !fatalCalled {
			t.Fatal("logFatalf should be called on error")
		}
	})
}

// TestRunGatewayEdgesGW tests edge cases (unique function name to avoid conflicts)
func TestRunGatewayEdgesGW(t *testing.T) {
	t.Run("telemetry error", func(t *testing.T) {
		err := runGateway(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return nil, errors.New("telemetry failed")
			},
			nil,
			nil,
			nil,
			nil,
		)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("db error", func(t *testing.T) {
		err := runGateway(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (gatewayDBCloser, error) {
				return nil, errors.New("db failed")
			},
			nil,
			nil,
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
		t.Setenv("VERIFIER_URL", "http://localhost:8083")
		t.Setenv("STATE_URL", "http://localhost:8081")

		var capturedServer *http.Server
		err := runGateway(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (gatewayDBCloser, error) {
				return &mockDBCloserGW{}, nil
			},
			func(ctx context.Context) (*redis.Client, error) {
				return nil, nil
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
			func(s *Server) {},
		)

		if err == nil || err.Error() != "test-stop" {
			t.Fatalf("expected test-stop, got %v", err)
		}
		if capturedServer == nil {
			t.Fatal("server not captured")
		}
	})
}

// mockDBCloserGW implements gatewayDBCloser for testing
type mockDBCloserGW struct{}

func (m *mockDBCloserGW) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m *mockDBCloserGW) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockDBCloserGW) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &fakeRowGW2{}
}

func (m *mockDBCloserGW) Close() {}

type fakeRowGW2 struct{}

func (f *fakeRowGW2) Scan(dest ...any) error { return nil }
