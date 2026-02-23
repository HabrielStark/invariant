package openclaw

import (
	"sync"
	"time"
)

type ttlEntry struct {
	value     InvokeResponse
	expiresAt time.Time
}

type TTLStore struct {
	mu    sync.Mutex
	items map[string]ttlEntry
}

func NewTTLStore() *TTLStore {
	return &TTLStore{items: map[string]ttlEntry{}}
}

func (s *TTLStore) SetNX(key string, value InvokeResponse, ttl time.Duration) bool {
	if key == "" {
		return false
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	if _, exists := s.items[key]; exists {
		return false
	}
	s.items[key] = ttlEntry{value: value, expiresAt: now.Add(ttl)}
	return true
}

func (s *TTLStore) Set(key string, value InvokeResponse, ttl time.Duration) {
	if key == "" {
		return
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.cleanupLocked(now)
	s.items[key] = ttlEntry{value: value, expiresAt: now.Add(ttl)}
	s.mu.Unlock()
}

func (s *TTLStore) Get(key string) (InvokeResponse, bool) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
	entry, ok := s.items[key]
	if !ok {
		return InvokeResponse{}, false
	}
	return entry.value, true
}

func (s *TTLStore) Delete(key string) {
	s.mu.Lock()
	delete(s.items, key)
	s.mu.Unlock()
}

func (s *TTLStore) cleanupLocked(now time.Time) {
	for k, entry := range s.items {
		if now.After(entry.expiresAt) {
			delete(s.items, k)
		}
	}
}

func stableVerdict(v string) bool {
	return v != "DEFER"
}
