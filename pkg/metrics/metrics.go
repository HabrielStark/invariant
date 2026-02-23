package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type Registry struct {
	mu                      sync.RWMutex
	endpoint                map[string]*EndpointStat
	verdict                 map[string]int64
	reason                  map[string]int64
	gauges                  map[string]float64
	invariantVerdictReason  map[string]int64
	shieldType              map[string]int64
	escrowState             map[string]int64
	openclawAdapterRequests int64
	verifyLatency           VerifyLatencyStat
	Histograms              *HistogramRegistry
}

type EndpointStat struct {
	Count          int64   `json:"count"`
	ErrorCount     int64   `json:"error_count"`
	TotalMillis    int64   `json:"total_millis"`
	MaxMillis      int64   `json:"max_millis"`
	AverageMillis  float64 `json:"average_millis"`
	LastStatusCode int     `json:"last_status_code"`
}

type VerifyLatencyStat struct {
	Count   int64   `json:"count"`
	TotalMS int64   `json:"total_ms"`
	MaxMS   int64   `json:"max_ms"`
	LastMS  int64   `json:"last_ms"`
	AvgMS   float64 `json:"avg_ms"`
}

type Snapshot struct {
	GeneratedAt              string                  `json:"generated_at"`
	Endpoints                map[string]EndpointStat `json:"endpoints"`
	Verdicts                 map[string]int64        `json:"verdicts"`
	Reasons                  map[string]int64        `json:"reasons"`
	Gauges                   map[string]float64      `json:"gauges"`
	InvariantVerdictReason   map[string]int64        `json:"invariant_verdict_reason"`
	ShieldTotals             map[string]int64        `json:"shield_totals"`
	EscrowTotals             map[string]int64        `json:"escrow_totals"`
	OpenClawAdapterRequests  int64                   `json:"openclaw_adapter_requests_total"`
	InvariantVerifyLatencyMS VerifyLatencyStat       `json:"invariant_verify_latency_ms"`
	Histograms               []HistogramSnapshot     `json:"histograms,omitempty"`
}

func NewRegistry() *Registry {
	return &Registry{
		endpoint:               map[string]*EndpointStat{},
		verdict:                map[string]int64{},
		reason:                 map[string]int64{},
		gauges:                 map[string]float64{},
		invariantVerdictReason: map[string]int64{},
		shieldType:             map[string]int64{},
		escrowState:            map[string]int64{},
		Histograms:             NewHistogramRegistry(),
	}
}

func (r *Registry) ObserveLatency(endpoint string, d time.Duration) {
	r.Histograms.ObserveDuration(endpoint, d)
}

func (r *Registry) Observe(path string, status int, d time.Duration) {
	millis := d.Milliseconds()
	r.mu.Lock()
	defer r.mu.Unlock()
	stat, ok := r.endpoint[path]
	if !ok {
		stat = &EndpointStat{}
		r.endpoint[path] = stat
	}
	stat.Count++
	if status >= 400 {
		stat.ErrorCount++
	}
	stat.TotalMillis += millis
	if millis > stat.MaxMillis {
		stat.MaxMillis = millis
	}
	stat.LastStatusCode = status
	stat.AverageMillis = float64(stat.TotalMillis) / float64(stat.Count)
}

func (r *Registry) IncVerdict(verdict string) {
	if verdict == "" {
		return
	}
	r.mu.Lock()
	r.verdict[verdict]++
	r.mu.Unlock()
}

func (r *Registry) IncReason(reason string) {
	if reason == "" {
		return
	}
	r.mu.Lock()
	r.reason[reason]++
	r.mu.Unlock()
}

func (r *Registry) IncVerdictReason(verdict, reason string) {
	verdict = strings.TrimSpace(verdict)
	reason = strings.TrimSpace(reason)
	if verdict == "" {
		return
	}
	if reason == "" {
		reason = "UNKNOWN"
	}
	key := verdict + "|" + reason
	r.mu.Lock()
	r.invariantVerdictReason[key]++
	r.mu.Unlock()
}

func (r *Registry) ObserveVerifyLatency(d time.Duration) {
	ms := d.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifyLatency.Count++
	r.verifyLatency.TotalMS += ms
	r.verifyLatency.LastMS = ms
	if ms > r.verifyLatency.MaxMS {
		r.verifyLatency.MaxMS = ms
	}
	r.verifyLatency.AvgMS = float64(r.verifyLatency.TotalMS) / float64(r.verifyLatency.Count)
}

func (r *Registry) IncShield(shieldType string) {
	shieldType = strings.TrimSpace(strings.ToUpper(shieldType))
	if shieldType == "" {
		return
	}
	r.mu.Lock()
	r.shieldType[shieldType]++
	r.mu.Unlock()
}

func (r *Registry) AddEscrowState(state string, delta int64) {
	state = strings.TrimSpace(strings.ToUpper(state))
	if state == "" || delta <= 0 {
		return
	}
	r.mu.Lock()
	r.escrowState[state] += delta
	r.mu.Unlock()
}

func (r *Registry) IncEscrowState(state string) {
	r.AddEscrowState(state, 1)
}

func (r *Registry) IncOpenClawAdapterRequests() {
	r.mu.Lock()
	r.openclawAdapterRequests++
	r.mu.Unlock()
}

func (r *Registry) SetGauge(name string, value float64) {
	if name == "" {
		return
	}
	r.mu.Lock()
	r.gauges[name] = value
	r.mu.Unlock()
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := Snapshot{
		GeneratedAt:             time.Now().UTC().Format(time.RFC3339),
		Endpoints:               make(map[string]EndpointStat, len(r.endpoint)),
		Verdicts:                make(map[string]int64, len(r.verdict)),
		Reasons:                 make(map[string]int64, len(r.reason)),
		Gauges:                  make(map[string]float64, len(r.gauges)),
		InvariantVerdictReason:  make(map[string]int64, len(r.invariantVerdictReason)),
		ShieldTotals:            make(map[string]int64, len(r.shieldType)),
		EscrowTotals:            make(map[string]int64, len(r.escrowState)),
		OpenClawAdapterRequests: r.openclawAdapterRequests,
		InvariantVerifyLatencyMS: VerifyLatencyStat{
			Count:   r.verifyLatency.Count,
			TotalMS: r.verifyLatency.TotalMS,
			MaxMS:   r.verifyLatency.MaxMS,
			LastMS:  r.verifyLatency.LastMS,
			AvgMS:   r.verifyLatency.AvgMS,
		},
	}
	for k, v := range r.endpoint {
		out.Endpoints[k] = *v
	}
	for k, v := range r.verdict {
		out.Verdicts[k] = v
	}
	for k, v := range r.reason {
		out.Reasons[k] = v
	}
	for k, v := range r.gauges {
		out.Gauges[k] = v
	}
	for k, v := range r.invariantVerdictReason {
		out.InvariantVerdictReason[k] = v
	}
	for k, v := range r.shieldType {
		out.ShieldTotals[k] = v
	}
	for k, v := range r.escrowState {
		out.EscrowTotals[k] = v
	}
	out.Histograms = r.Histograms.Snapshots()
	return out
}

func (r *Registry) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		snap := r.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(snap)
	}
}

func (r *Registry) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		snap := r.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		b := &strings.Builder{}
		b.WriteString("# HELP axiom_endpoint_count total requests by endpoint\n")
		b.WriteString("# TYPE axiom_endpoint_count counter\n")
		for _, ep := range SortedKeys(snap.Endpoints) {
			stat := snap.Endpoints[ep]
			fmt.Fprintf(b, "axiom_endpoint_count{endpoint=%q} %d\n", ep, stat.Count)
		}
		b.WriteString("# HELP axiom_endpoint_error_count total endpoint errors\n")
		b.WriteString("# TYPE axiom_endpoint_error_count counter\n")
		for _, ep := range SortedKeys(snap.Endpoints) {
			stat := snap.Endpoints[ep]
			fmt.Fprintf(b, "axiom_endpoint_error_count{endpoint=%q} %d\n", ep, stat.ErrorCount)
		}
		b.WriteString("# HELP axiom_endpoint_avg_millis endpoint average latency in milliseconds\n")
		b.WriteString("# TYPE axiom_endpoint_avg_millis gauge\n")
		for _, ep := range SortedKeys(snap.Endpoints) {
			stat := snap.Endpoints[ep]
			fmt.Fprintf(b, "axiom_endpoint_avg_millis{endpoint=%q} %.3f\n", ep, stat.AverageMillis)
		}
		b.WriteString("# HELP axiom_endpoint_total_millis endpoint total time in milliseconds\n")
		b.WriteString("# TYPE axiom_endpoint_total_millis counter\n")
		for _, ep := range SortedKeys(snap.Endpoints) {
			stat := snap.Endpoints[ep]
			fmt.Fprintf(b, "axiom_endpoint_total_millis{endpoint=%q} %d\n", ep, stat.TotalMillis)
		}
		b.WriteString("# HELP axiom_endpoint_max_millis endpoint max latency in milliseconds\n")
		b.WriteString("# TYPE axiom_endpoint_max_millis gauge\n")
		for _, ep := range SortedKeys(snap.Endpoints) {
			stat := snap.Endpoints[ep]
			fmt.Fprintf(b, "axiom_endpoint_max_millis{endpoint=%q} %d\n", ep, stat.MaxMillis)
		}
		b.WriteString("# HELP axiom_verdict_total total decisions by verdict\n")
		b.WriteString("# TYPE axiom_verdict_total counter\n")
		for _, verdict := range SortedKeys(snap.Verdicts) {
			fmt.Fprintf(b, "axiom_verdict_total{verdict=%q} %d\n", verdict, snap.Verdicts[verdict])
		}
		b.WriteString("# HELP axiom_reason_total total decisions by reason code\n")
		b.WriteString("# TYPE axiom_reason_total counter\n")
		for _, reason := range SortedKeys(snap.Reasons) {
			fmt.Fprintf(b, "axiom_reason_total{reason=%q} %d\n", reason, snap.Reasons[reason])
		}
		b.WriteString("# HELP axiom_gauge operational gauge metrics\n")
		b.WriteString("# TYPE axiom_gauge gauge\n")
		for _, name := range SortedKeys(snap.Gauges) {
			fmt.Fprintf(b, "axiom_gauge{name=%q} %.3f\n", name, snap.Gauges[name])
		}
		for _, h := range snap.Histograms {
			b.WriteString("# HELP axiom_latency_seconds latency histogram\n")
			b.WriteString("# TYPE axiom_latency_seconds histogram\n")
			for _, bucket := range h.Buckets {
				fmt.Fprintf(b, "axiom_latency_seconds_bucket{endpoint=%q,le=\"%.3f\"} %d\n", h.Name, bucket.Le, bucket.Count)
			}
			fmt.Fprintf(b, "axiom_latency_seconds_bucket{endpoint=%q,le=\"+Inf\"} %d\n", h.Name, h.Count)
			fmt.Fprintf(b, "axiom_latency_seconds_sum{endpoint=%q} %.6f\n", h.Name, h.Sum)
			fmt.Fprintf(b, "axiom_latency_seconds_count{endpoint=%q} %d\n", h.Name, h.Count)
			fmt.Fprintf(b, "axiom_latency_p50_seconds{endpoint=%q} %.6f\n", h.Name, h.P50)
			fmt.Fprintf(b, "axiom_latency_p95_seconds{endpoint=%q} %.6f\n", h.Name, h.P95)
			fmt.Fprintf(b, "axiom_latency_p99_seconds{endpoint=%q} %.6f\n", h.Name, h.P99)
		}

		b.WriteString("# HELP invariant_verdict_total Invariant verdict counter by verdict and reason\n")
		b.WriteString("# TYPE invariant_verdict_total counter\n")
		for _, key := range SortedKeys(snap.InvariantVerdictReason) {
			parts := strings.SplitN(key, "|", 2)
			verdict := parts[0]
			reason := "UNKNOWN"
			if len(parts) == 2 {
				reason = parts[1]
			}
			fmt.Fprintf(b, "invariant_verdict_total{verdict=%q,reason=%q} %d\n", verdict, reason, snap.InvariantVerdictReason[key])
		}

		b.WriteString("# HELP invariant_verify_latency_ms Invariant verifier latency in ms\n")
		b.WriteString("# TYPE invariant_verify_latency_ms gauge\n")
		fmt.Fprintf(b, "invariant_verify_latency_ms{stat=%q} %d\n", "last", snap.InvariantVerifyLatencyMS.LastMS)
		fmt.Fprintf(b, "invariant_verify_latency_ms{stat=%q} %.3f\n", "avg", snap.InvariantVerifyLatencyMS.AvgMS)
		fmt.Fprintf(b, "invariant_verify_latency_ms{stat=%q} %d\n", "max", snap.InvariantVerifyLatencyMS.MaxMS)

		b.WriteString("# HELP invariant_shield_total Invariant shield applications by type\n")
		b.WriteString("# TYPE invariant_shield_total counter\n")
		for _, shieldType := range SortedKeys(snap.ShieldTotals) {
			fmt.Fprintf(b, "invariant_shield_total{type=%q} %d\n", shieldType, snap.ShieldTotals[shieldType])
		}

		b.WriteString("# HELP invariant_escrow_total Invariant escrow transitions by state\n")
		b.WriteString("# TYPE invariant_escrow_total counter\n")
		for _, state := range SortedKeys(snap.EscrowTotals) {
			fmt.Fprintf(b, "invariant_escrow_total{state=%q} %d\n", state, snap.EscrowTotals[state])
		}

		b.WriteString("# HELP openclaw_adapter_requests_total OpenClaw adapter requests handled\n")
		b.WriteString("# TYPE openclaw_adapter_requests_total counter\n")
		fmt.Fprintf(b, "openclaw_adapter_requests_total %d\n", snap.OpenClawAdapterRequests)

		_, _ = w.Write([]byte(b.String()))
	}
}

func SortedKeys[M ~map[string]V, V any](m M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
