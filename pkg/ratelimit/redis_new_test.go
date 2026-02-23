package ratelimit

import (
	"testing"
	"time"
)

func TestNewRedisDefaults(t *testing.T) {
	lim := NewRedis(nil, 0)
	if lim.Window != time.Minute {
		t.Fatalf("expected default one-minute window, got %v", lim.Window)
	}
	if lim.Prefix != "rl:" {
		t.Fatalf("expected default redis prefix, got %q", lim.Prefix)
	}
	if lim.Fallback == nil {
		t.Fatal("expected in-memory fallback to be initialized")
	}
}
