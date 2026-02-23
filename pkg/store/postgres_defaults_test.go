package store

import (
	"strings"
	"testing"
)

func TestDefaultPostgresURLDefaults(t *testing.T) {
	t.Setenv("DATABASE_USER", "")
	t.Setenv("POSTGRES_PASSWORD", "")
	t.Setenv("DATABASE_HOST", "")
	t.Setenv("DATABASE_PORT", "")
	t.Setenv("DATABASE_NAME", "")
	t.Setenv("DATABASE_SSLMODE", "")

	dsn := defaultPostgresURL()
	if !strings.Contains(dsn, "postgres://axiom@localhost:5432/axiom") {
		t.Fatalf("unexpected default dsn: %s", dsn)
	}
	if !strings.Contains(dsn, "sslmode=disable") {
		t.Fatalf("expected default sslmode=disable in dsn, got %s", dsn)
	}
}

func TestDefaultPostgresURLFromEnv(t *testing.T) {
	t.Setenv("DATABASE_USER", "dbuser")
	t.Setenv("POSTGRES_PASSWORD", "secret")
	t.Setenv("DATABASE_HOST", "db.internal")
	t.Setenv("DATABASE_PORT", "6543")
	t.Setenv("DATABASE_NAME", "axiomdb")
	t.Setenv("DATABASE_SSLMODE", "require")

	dsn := defaultPostgresURL()
	if !strings.Contains(dsn, "postgres://dbuser:secret@db.internal:6543/axiomdb") {
		t.Fatalf("unexpected env dsn: %s", dsn)
	}
	if !strings.Contains(dsn, "sslmode=require") {
		t.Fatalf("expected sslmode=require in dsn, got %s", dsn)
	}
}

func TestDefaultPostgresURLInvalidPortFallback(t *testing.T) {
	t.Setenv("DATABASE_HOST", "db.internal")
	t.Setenv("DATABASE_PORT", "not-a-port")
	dsn := defaultPostgresURL()
	if !strings.Contains(dsn, "db.internal:5432") {
		t.Fatalf("expected fallback port 5432, got %s", dsn)
	}
}

func TestRequiresSecureTransport(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     true,
		"yes":   true,
		"on":    true,
		"false": false,
		"":      false,
	}
	for val, want := range cases {
		val := val
		want := want
		t.Run("value_"+val, func(t *testing.T) {
			t.Setenv("SECURE_TRANSPORT_TEST", val)
			if got := requiresSecureTransport("SECURE_TRANSPORT_TEST"); got != want {
				t.Fatalf("expected %v for %q, got %v", want, val, got)
			}
		})
	}
}
