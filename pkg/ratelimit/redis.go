package ratelimit

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var rateLimitScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {current, ttl}
`)

type RedisLimiter struct {
	Client   *redis.Client
	Window   time.Duration
	Prefix   string
	Fallback *InMemoryLimiter
}

func NewRedis(client *redis.Client, window time.Duration) *RedisLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &RedisLimiter{
		Client:   client,
		Window:   window,
		Prefix:   "rl:",
		Fallback: NewInMemory(window),
	}
}

func (l *RedisLimiter) Allow(key string, limit int) Decision {
	if limit <= 0 {
		limit = 1
	}
	if l.Client == nil {
		if l.Fallback != nil {
			return l.Fallback.Allow(key, limit)
		}
		return Decision{Allowed: true, Count: 0, Limit: limit, Remaining: limit, ResetAt: time.Now().UTC().Add(l.Window)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	redisKey := l.Prefix + key
	res, err := rateLimitScript.Run(ctx, l.Client, []string{redisKey}, int(l.Window.Milliseconds())).Result()
	if err != nil {
		if l.Fallback != nil {
			return l.Fallback.Allow(key, limit)
		}
		return Decision{Allowed: true, Count: 0, Limit: limit, Remaining: limit, ResetAt: time.Now().UTC().Add(l.Window)}
	}
	vals, ok := res.([]interface{})
	if !ok || len(vals) < 2 {
		if l.Fallback != nil {
			return l.Fallback.Allow(key, limit)
		}
		return Decision{Allowed: true, Count: 0, Limit: limit, Remaining: limit, ResetAt: time.Now().UTC().Add(l.Window)}
	}
	count, _ := vals[0].(int64)
	ttlMs, _ := vals[1].(int64)
	if ttlMs < 0 {
		ttlMs = int64(l.Window.Milliseconds())
	}
	allowed := int(count) <= limit
	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}
	return Decision{
		Allowed:   allowed,
		Count:     int(count),
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   time.Now().UTC().Add(time.Duration(ttlMs) * time.Millisecond),
	}
}
