package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMemoryCacheSetNXAndDel(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()

	ok, err := c.SetNX(ctx, "k1", "v1", time.Second)
	if err != nil {
		t.Fatalf("setnx error: %v", err)
	}
	if !ok {
		t.Fatal("expected first setnx to succeed")
	}

	ok, err = c.SetNX(ctx, "k1", "v2", time.Second)
	if err != nil {
		t.Fatalf("setnx error: %v", err)
	}
	if ok {
		t.Fatal("expected second setnx to fail")
	}

	if err := c.Del(ctx, "k1"); err != nil {
		t.Fatalf("del error: %v", err)
	}
	ok, err = c.SetNX(ctx, "k1", "v3", time.Second)
	if err != nil {
		t.Fatalf("setnx error: %v", err)
	}
	if !ok {
		t.Fatal("expected setnx after del to succeed")
	}
}

func TestMemoryCacheGetSetAndExpiry(t *testing.T) {
	c := NewMemoryCache()
	ctx := context.Background()

	if err := c.Set(ctx, "k2", "v2", 10*time.Millisecond); err != nil {
		t.Fatalf("set error: %v", err)
	}
	got, err := c.Get(ctx, "k2")
	if err != nil {
		t.Fatalf("get error: %v", err)
	}
	if got != "v2" {
		t.Fatalf("expected v2, got %q", got)
	}

	time.Sleep(15 * time.Millisecond)
	_, err = c.Get(ctx, "k2")
	if !errors.Is(err, redis.Nil) {
		t.Fatalf("expected redis.Nil after ttl, got %v", err)
	}
}

func TestNewCacheFallsBackToMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	cache := NewCache(ctx, nil)
	if _, ok := cache.(*MemoryCache); !ok {
		t.Fatalf("expected MemoryCache fallback for nil redis client, got %T", cache)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:         "127.0.0.1:1",
		DialTimeout:  5 * time.Millisecond,
		ReadTimeout:  5 * time.Millisecond,
		WriteTimeout: 5 * time.Millisecond,
	})
	defer redisClient.Close()

	cache = NewCache(ctx, redisClient)
	if _, ok := cache.(*MemoryCache); !ok {
		t.Fatalf("expected MemoryCache fallback on redis ping failure, got %T", cache)
	}
}

func TestNewCacheUsesRedisWhenAvailable(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	defer mr.Close()

	ctx := context.Background()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer redisClient.Close()

	cache := NewCache(ctx, redisClient)
	if _, ok := cache.(*RedisCache); !ok {
		t.Fatalf("expected RedisCache when redis ping succeeds, got %T", cache)
	}
}

func TestRedisCacheMethods(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	cache := &RedisCache{client: client}
	ctx := context.Background()

	ok, err := cache.SetNX(ctx, "k1", "v1", time.Minute)
	if err != nil {
		t.Fatalf("setnx failed: %v", err)
	}
	if !ok {
		t.Fatal("expected first setnx to succeed")
	}
	ok, err = cache.SetNX(ctx, "k1", "v2", time.Minute)
	if err != nil {
		t.Fatalf("setnx duplicate failed: %v", err)
	}
	if ok {
		t.Fatal("expected duplicate setnx to fail")
	}

	if err := cache.Set(ctx, "k2", "v2", time.Minute); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	got, err := cache.Get(ctx, "k2")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got != "v2" {
		t.Fatalf("expected v2, got %q", got)
	}

	if err := cache.Del(ctx, "k2"); err != nil {
		t.Fatalf("del failed: %v", err)
	}
	_, err = cache.Get(ctx, "k2")
	if !errors.Is(err, redis.Nil) {
		t.Fatalf("expected redis.Nil after delete, got %v", err)
	}
}
