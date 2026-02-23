package store

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func TestNewRedisSuccessWithInvalidDBFallback(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	defer mr.Close()

	t.Setenv("REDIS_ADDR", mr.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_DB", "not-a-number")
	t.Setenv("REDIS_TLS", "false")
	t.Setenv("REDIS_REQUIRE_TLS", "false")

	client, err := NewRedis(context.Background())
	if err != nil {
		t.Fatalf("expected redis client success, got %v", err)
	}
	defer client.Close()
}
