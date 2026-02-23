package stream

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	t.Parallel()

	evt := NewEvent("refresh", map[string]string{"id": "123"})
	if evt.Type != "refresh" {
		t.Fatalf("expected type refresh, got %q", evt.Type)
	}
	if evt.At == "" {
		t.Fatal("expected timestamp")
	}
	var payload map[string]string
	if err := json.Unmarshal(evt.Data, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload["id"] != "123" {
		t.Fatalf("expected id=123, got %q", payload["id"])
	}
}

func TestSubscribePublishAndUnsubscribeIdempotent(t *testing.T) {
	t.Parallel()

	h := NewHub()
	ch := h.Subscribe(1)
	h.Publish(NewEvent("ready", nil))

	select {
	case evt := <-ch:
		if evt.Type != "ready" {
			t.Fatalf("expected ready event, got %q", evt.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}

	h.Unsubscribe(ch)
	// Must not panic on repeated calls.
	h.Unsubscribe(ch)
}

func TestPublishDropsWhenBufferFull(t *testing.T) {
	t.Parallel()

	h := NewHub()
	ch := h.Subscribe(1)
	defer h.Unsubscribe(ch)

	first := NewEvent("first", nil)
	second := NewEvent("second", nil)
	h.Publish(first)
	h.Publish(second)

	select {
	case evt := <-ch:
		if evt.Type != "first" {
			t.Fatalf("expected first event to remain in buffer, got %q", evt.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for first event")
	}

	select {
	case evt := <-ch:
		t.Fatalf("did not expect second buffered event, got %q", evt.Type)
	default:
	}
}

func TestSubscribeUsesDefaultBuffer(t *testing.T) {
	t.Parallel()

	h := NewHub()
	ch := h.Subscribe(0)
	defer h.Unsubscribe(ch)
	if cap(ch) != 32 {
		t.Fatalf("expected default buffer 32, got %d", cap(ch))
	}
}
