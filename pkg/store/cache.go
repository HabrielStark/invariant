package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Cache interface {
	SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}

// RedisCache wraps go-redis.
type RedisCache struct{ client *redis.Client }

func (r *RedisCache) SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	return r.client.SetNX(ctx, key, value, ttl).Result()
}

func (r *RedisCache) Get(ctx context.Context, key string) (string, error) {
	res, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", err
	}
	return res, err
}

func (r *RedisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r *RedisCache) Del(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// MemoryCache is a simple in-memory TTL cache.
type MemoryCache struct {
	mu    sync.Mutex
	items map[string]memItem
}

type memItem struct {
	value     string
	expiresAt time.Time
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{items: map[string]memItem{}}
}

func (m *MemoryCache) SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
	if _, ok := m.items[key]; ok {
		return false, nil
	}
	m.items[key] = memItem{value: value, expiresAt: time.Now().Add(ttl)}
	return true, nil
}

func (m *MemoryCache) Get(ctx context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
	item, ok := m.items[key]
	if !ok {
		return "", redis.Nil
	}
	return item.value, nil
}

func (m *MemoryCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()
	m.items[key] = memItem{value: value, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (m *MemoryCache) Del(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.items, key)
	return nil
}

func (m *MemoryCache) cleanupLocked() {
	now := time.Now()
	for k, v := range m.items {
		if now.After(v.expiresAt) {
			delete(m.items, k)
		}
	}
}

// NewCache tries redis, falls back to memory.
func NewCache(ctx context.Context, client *redis.Client) Cache {
	if client != nil {
		if err := client.Ping(ctx).Err(); err == nil {
			return &RedisCache{client: client}
		}
	}
	return NewMemoryCache()
}
