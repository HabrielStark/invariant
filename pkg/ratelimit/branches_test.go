package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestNewInMemoryDefaultWindow(t *testing.T) {
	lim := NewInMemory(0)
	if lim.window != time.Minute {
		t.Fatalf("expected default 1 minute window, got %v", lim.window)
	}
}

func TestRedisLimiterFallbackNilBranches(t *testing.T) {
	t.Run("client_nil_and_no_fallback", func(t *testing.T) {
		lim := &RedisLimiter{
			Client:   nil,
			Window:   2 * time.Second,
			Prefix:   "rl:",
			Fallback: nil,
		}
		decision := lim.Allow("k1", 0)
		if !decision.Allowed || decision.Limit != 1 || decision.Count != 0 || decision.Remaining != 1 {
			t.Fatalf("expected permissive fallback decision, got %+v", decision)
		}
	})

	t.Run("redis_error_and_no_fallback", func(t *testing.T) {
		client := redis.NewClient(&redis.Options{
			Addr:         "127.0.0.1:1",
			DialTimeout:  5 * time.Millisecond,
			ReadTimeout:  5 * time.Millisecond,
			WriteTimeout: 5 * time.Millisecond,
			MaxRetries:   0,
		})
		defer client.Close()
		lim := &RedisLimiter{
			Client:   client,
			Window:   2 * time.Second,
			Prefix:   "rl:",
			Fallback: nil,
		}
		decision := lim.Allow("k2", 2)
		if !decision.Allowed || decision.Count != 0 || decision.Limit != 2 {
			t.Fatalf("expected permissive decision on redis error with no fallback, got %+v", decision)
		}
	})
}

func TestRedisLimiterUnexpectedScriptResult(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	lim := &RedisLimiter{
		Client:   client,
		Window:   100 * time.Millisecond,
		Prefix:   "rl:",
		Fallback: nil,
	}

	originalScript := rateLimitScript
	rateLimitScript = redis.NewScript(`return "bad-value"`)
	defer func() { rateLimitScript = originalScript }()

	decision := lim.Allow("actor:u1", 5)
	if !decision.Allowed || decision.Count != 0 || decision.Limit != 5 {
		t.Fatalf("expected permissive decision for invalid script result, got %+v", decision)
	}
}

func TestRedisLimiterShortScriptResultUsesFallback(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	lim := NewRedis(client, time.Second)
	lim.Fallback = NewInMemory(time.Second)

	originalScript := rateLimitScript
	rateLimitScript = redis.NewScript(`return {1}`)
	defer func() { rateLimitScript = originalScript }()

	first := lim.Allow("actor:u2", 1)
	if !first.Allowed || first.Count != 1 {
		t.Fatalf("expected fallback in-memory first decision, got %+v", first)
	}
	second := lim.Allow("actor:u2", 1)
	if second.Allowed {
		t.Fatalf("expected fallback limiter enforcement on second call, got %+v", second)
	}
}

func TestRedisLimiterNegativeTTLUsesWindow(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	lim := NewRedis(client, 500*time.Millisecond)
	lim.Prefix = "rl:"

	key := lim.Prefix + "actor:u3"
	if err := client.Set(context.Background(), key, "1", 0).Err(); err != nil {
		t.Fatalf("seed redis key: %v", err)
	}

	decision := lim.Allow("actor:u3", 10)
	if decision.ResetAt.Before(time.Now().UTC()) {
		t.Fatalf("expected resetAt in future, got %v", decision.ResetAt)
	}
}
