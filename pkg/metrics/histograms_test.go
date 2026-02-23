package metrics

import (
	"testing"
	"time"
)

func TestHistogram_Observe(t *testing.T) {
	h := NewHistogram("test_endpoint")
	h.Observe(10 * time.Millisecond)
	h.Observe(50 * time.Millisecond)
	h.Observe(200 * time.Millisecond)
	h.Observe(500 * time.Millisecond)
	h.Observe(1 * time.Second)

	snap := h.Snapshot()
	if snap.Count != 5 {
		t.Errorf("count = %d, want 5", snap.Count)
	}
	if snap.Sum <= 0 {
		t.Error("sum should be positive")
	}
	if snap.Name != "test_endpoint" {
		t.Errorf("name = %q, want %q", snap.Name, "test_endpoint")
	}
}

func TestHistogram_Percentiles(t *testing.T) {
	h := NewHistogram("p_test")
	// Record 100 observations at 10ms each
	for i := 0; i < 100; i++ {
		h.Observe(10 * time.Millisecond)
	}
	p50 := h.Percentile(0.50)
	p95 := h.Percentile(0.95)
	p99 := h.Percentile(0.99)
	// All observations are 10ms = 0.01s — should fall in the 0.01 bucket
	if p50 > 0.025 {
		t.Errorf("p50 = %f, want <= 0.025", p50)
	}
	if p95 > 0.025 {
		t.Errorf("p95 = %f, want <= 0.025", p95)
	}
	if p99 > 0.025 {
		t.Errorf("p99 = %f, want <= 0.025", p99)
	}
}

func TestHistogram_Empty(t *testing.T) {
	h := NewHistogram("empty")
	if p := h.Percentile(0.50); p != 0 {
		t.Errorf("empty p50 = %f, want 0", p)
	}
	snap := h.Snapshot()
	if snap.Count != 0 {
		t.Errorf("count = %d, want 0", snap.Count)
	}
}

func TestHistogramRegistry(t *testing.T) {
	reg := NewHistogramRegistry()
	reg.ObserveDuration("GET /api/test", 100*time.Millisecond)
	reg.ObserveDuration("GET /api/test", 200*time.Millisecond)
	reg.ObserveDuration("POST /api/execute", 50*time.Millisecond)

	snaps := reg.Snapshots()
	if len(snaps) != 2 {
		t.Fatalf("len(snaps) = %d, want 2", len(snaps))
	}

	// Verify Get returns same histogram
	h1 := reg.Get("GET /api/test")
	h2 := reg.Get("GET /api/test")
	if h1 != h2 {
		t.Error("Get should return the same histogram instance")
	}
}

func TestHistogramSnapshot_Percentiles(t *testing.T) {
	h := NewHistogram("snap_test")
	// 90 fast + 10 slow
	for i := 0; i < 90; i++ {
		h.Observe(5 * time.Millisecond)
	}
	for i := 0; i < 10; i++ {
		h.Observe(2 * time.Second)
	}

	snap := h.Snapshot()
	if snap.Count != 100 {
		t.Fatalf("count = %d, want 100", snap.Count)
	}
	// P50 should be very low (5ms = 0.005s bucket)
	if snap.P50 > 0.01 {
		t.Errorf("p50 = %f, want <= 0.01", snap.P50)
	}
	// P99 should be high (2s = 2.5 bucket)
	if snap.P99 < 0.1 {
		t.Errorf("p99 = %f, want >= 0.1 (slow observations)", snap.P99)
	}
}

func TestRegistryObserveLatency(t *testing.T) {
	reg := NewRegistry()
	reg.ObserveLatency("GET /healthz", 10*time.Millisecond)
	reg.ObserveLatency("GET /healthz", 20*time.Millisecond)

	snap := reg.Snapshot()
	if len(snap.Histograms) != 1 {
		t.Fatalf("expected 1 histogram, got %d", len(snap.Histograms))
	}
	if snap.Histograms[0].Count != 2 {
		t.Errorf("histogram count = %d, want 2", snap.Histograms[0].Count)
	}
}
