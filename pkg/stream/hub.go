package stream

import (
	"encoding/json"
	"sync"
	"time"
)

type Event struct {
	Type string          `json:"type"`
	At   string          `json:"at"`
	Data json.RawMessage `json:"data,omitempty"`
}

func NewEvent(eventType string, data interface{}) Event {
	var raw json.RawMessage
	if data != nil {
		b, _ := json.Marshal(data)
		raw = b
	}
	return Event{Type: eventType, At: time.Now().UTC().Format(time.RFC3339Nano), Data: raw}
}

type Hub struct {
	mu   sync.RWMutex
	subs map[chan Event]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: map[chan Event]struct{}{}}
}

func (h *Hub) Subscribe(buffer int) chan Event {
	if buffer <= 0 {
		buffer = 32
	}
	ch := make(chan Event, buffer)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan Event) {
	h.mu.Lock()
	_, exists := h.subs[ch]
	if exists {
		delete(h.subs, ch)
	}
	h.mu.Unlock()
	if exists {
		close(ch)
	}
}

func (h *Hub) Publish(evt Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for ch := range h.subs {
		select {
		case ch <- evt:
		default:
		}
	}
}
