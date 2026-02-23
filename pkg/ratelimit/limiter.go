package ratelimit

import (
	"sync"
	"time"
)

type Decision struct {
	Allowed   bool
	Count     int
	Limit     int
	Remaining int
	ResetAt   time.Time
}

type Limiter interface {
	Allow(key string, limit int) Decision
}

type InMemoryLimiter struct {
	mu     sync.Mutex
	window time.Duration
	items  map[string]entry
}

type entry struct {
	count   int
	resetAt time.Time
}

func NewInMemory(window time.Duration) *InMemoryLimiter {
	if window <= 0 {
		window = time.Minute
	}
	return &InMemoryLimiter{
		window: window,
		items:  make(map[string]entry),
	}
}

func (l *InMemoryLimiter) Allow(key string, limit int) Decision {
	if limit <= 0 {
		limit = 1
	}
	now := time.Now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	curr, ok := l.items[key]
	if !ok || now.After(curr.resetAt) {
		curr = entry{
			count:   0,
			resetAt: now.Add(l.window),
		}
	}
	curr.count++
	l.items[key] = curr
	allowed := curr.count <= limit
	remaining := limit - curr.count
	if remaining < 0 {
		remaining = 0
	}
	return Decision{
		Allowed:   allowed,
		Count:     curr.count,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   curr.resetAt,
	}
}

func (l *InMemoryLimiter) cleanup(now time.Time) {
	for k, v := range l.items {
		if now.After(v.resetAt) {
			delete(l.items, k)
		}
	}
}
