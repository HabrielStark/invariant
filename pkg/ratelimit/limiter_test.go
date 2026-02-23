package ratelimit

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestInMemoryLimiter(t *testing.T) {
	limiter := NewInMemory(50 * time.Millisecond)
	key := "tenant-a:tool:127.0.0.1"

	first := limiter.Allow(key, 2)
	if !first.Allowed || first.Count != 1 || first.Remaining != 1 {
		t.Fatalf("unexpected first decision: %+v", first)
	}
	second := limiter.Allow(key, 2)
	if !second.Allowed || second.Count != 2 || second.Remaining != 0 {
		t.Fatalf("unexpected second decision: %+v", second)
	}
	third := limiter.Allow(key, 2)
	if third.Allowed || third.Count != 3 || third.Remaining != 0 {
		t.Fatalf("unexpected third decision: %+v", third)
	}
	time.Sleep(70 * time.Millisecond)
	reset := limiter.Allow(key, 2)
	if !reset.Allowed || reset.Count != 1 {
		t.Fatalf("expected counter reset after window, got %+v", reset)
	}
}

func TestInMemoryLimiterLimitFloor(t *testing.T) {
	limiter := NewInMemory(time.Minute)
	decision := limiter.Allow("k", 0)
	if !decision.Allowed || decision.Limit != 1 {
		t.Fatalf("expected fallback limit=1 and allowed decision, got %+v", decision)
	}
}

func TestRedisLimiter(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	limiter := NewRedis(client, 25*time.Millisecond)
	key := "actor:u1"

	first := limiter.Allow(key, 2)
	if !first.Allowed || first.Count != 1 || first.Remaining != 1 {
		t.Fatalf("unexpected first decision: %+v", first)
	}
	second := limiter.Allow(key, 2)
	if !second.Allowed || second.Count != 2 || second.Remaining != 0 {
		t.Fatalf("unexpected second decision: %+v", second)
	}
	third := limiter.Allow(key, 2)
	if third.Allowed || third.Count != 3 || third.Remaining != 0 {
		t.Fatalf("unexpected third decision: %+v", third)
	}
	mr.FastForward(30 * time.Millisecond)
	reset := limiter.Allow(key, 2)
	if !reset.Allowed || reset.Count != 1 {
		t.Fatalf("expected counter reset after window, got %+v", reset)
	}
}

func TestRedisLimiterUnavailable(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  5 * time.Millisecond,
		ReadTimeout:  5 * time.Millisecond,
		WriteTimeout: 5 * time.Millisecond,
		MaxRetries:   0,
	})
	limiter := NewRedis(client, time.Second)
	decision := limiter.Allow("actor:u1", 1)
	if !decision.Allowed || decision.Count != 1 {
		t.Fatalf("expected in-memory fallback allow on redis outage, got %+v", decision)
	}
	second := limiter.Allow("actor:u1", 1)
	if second.Allowed {
		t.Fatalf("expected fallback limiter to enforce limits, got %+v", second)
	}
}
