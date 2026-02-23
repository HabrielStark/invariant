package metrics

import (
	"sync"
	"time"
)

// HistogramBucket stores counts for a specific latency bound.
type HistogramBucket struct {
	Le    float64 // upper bound in seconds
	Count int64
}

// Histogram tracks latency distributions with P50/P95/P99 percentiles.
type Histogram struct {
	mu      sync.Mutex
	name    string
	buckets []HistogramBucket
	sum     float64
	count   int64
}

// defaultBuckets provides P50/P95/P99-friendly latency bounds in seconds.
var defaultBuckets = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

// NewHistogram creates a histogram with default latency buckets.
func NewHistogram(name string) *Histogram {
	buckets := make([]HistogramBucket, len(defaultBuckets))
	for i, le := range defaultBuckets {
		buckets[i] = HistogramBucket{Le: le}
	}
	return &Histogram{name: name, buckets: buckets}
}

// Observe records a latency observation.
func (h *Histogram) Observe(d time.Duration) {
	sec := d.Seconds()
	h.mu.Lock()
	h.sum += sec
	h.count++
	for i := range h.buckets {
		if sec <= h.buckets[i].Le {
			h.buckets[i].Count++
		}
	}
	h.mu.Unlock()
}

// Percentile returns the estimated percentile (0.0-1.0) from histogram buckets.
func (h *Histogram) Percentile(p float64) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	target := int64(p * float64(h.count))
	for _, b := range h.buckets {
		if b.Count >= target {
			return b.Le
		}
	}
	if len(h.buckets) > 0 {
		return h.buckets[len(h.buckets)-1].Le
	}
	return 0
}

// Snapshot returns a copy of the histogram state for Prometheus exposition.
type HistogramSnapshot struct {
	Name    string
	Buckets []HistogramBucket
	Sum     float64
	Count   int64
	P50     float64
	P95     float64
	P99     float64
}

// Snapshot returns a thread-safe snapshot of current histogram state.
func (h *Histogram) Snapshot() HistogramSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	buckets := make([]HistogramBucket, len(h.buckets))
	copy(buckets, h.buckets)
	snap := HistogramSnapshot{
		Name:    h.name,
		Buckets: buckets,
		Sum:     h.sum,
		Count:   h.count,
	}
	// Calculate percentiles from snapshot
	if h.count > 0 {
		for _, b := range buckets {
			if snap.P50 == 0 && b.Count >= int64(0.50*float64(h.count)) {
				snap.P50 = b.Le
			}
			if snap.P95 == 0 && b.Count >= int64(0.95*float64(h.count)) {
				snap.P95 = b.Le
			}
			if snap.P99 == 0 && b.Count >= int64(0.99*float64(h.count)) {
				snap.P99 = b.Le
			}
		}
	}
	return snap
}

// HistogramRegistry manages named histograms for latency tracking.
type HistogramRegistry struct {
	mu         sync.RWMutex
	histograms map[string]*Histogram
}

// NewHistogramRegistry creates a new histogram registry.
func NewHistogramRegistry() *HistogramRegistry {
	return &HistogramRegistry{histograms: map[string]*Histogram{}}
}

// Get returns or creates a histogram by name.
func (r *HistogramRegistry) Get(name string) *Histogram {
	r.mu.RLock()
	h, ok := r.histograms[name]
	r.mu.RUnlock()
	if ok {
		return h
	}
	r.mu.Lock()
	if h, ok = r.histograms[name]; ok {
		r.mu.Unlock()
		return h
	}
	h = NewHistogram(name)
	r.histograms[name] = h
	r.mu.Unlock()
	return h
}

// ObserveDuration records a duration to the named histogram.
func (r *HistogramRegistry) ObserveDuration(name string, d time.Duration) {
	r.Get(name).Observe(d)
}

// Snapshots returns all histogram snapshots for exposition.
func (r *HistogramRegistry) Snapshots() []HistogramSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]HistogramSnapshot, 0, len(r.histograms))
	for _, h := range r.histograms {
		out = append(out, h.Snapshot())
	}
	return out
}
