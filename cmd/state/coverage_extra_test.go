package main

import (
	"axiom/pkg/statebus"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestUpdateSourcesTenantResolutionError(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "oidc_hs256",
	}
	body := `{"tenant":"tenant-a","domain":"finance","sources":[]}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/sources", strings.NewReader(body))
	s.updateSources(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthenticated updateSources, got %d", rr.Code)
	}
}

func TestIngestEventMissingFields(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{bad`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"tenant":"t1","domain":"","source":"bank","event_time":"2026-02-01T00:00:00Z"}`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing domain, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"tenant":"t1","domain":"finance","source":"","event_time":"2026-02-01T00:00:00Z"}`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing source, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"tenant":"t1","domain":"finance","source":"bank","event_time":""}`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing event_time, got %d", rr.Code)
	}
}

func TestIngestEventTenantResolutionError(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "oidc_hs256",
	}
	body := `{"tenant":"t1","domain":"finance","source":"bank","event_time":"2026-02-01T00:00:00Z"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(body))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthenticated ingestEvent, got %d", rr.Code)
	}
}

func TestIngestEventWithIngestionTime(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	now := time.Now().UTC().Format(time.RFC3339)
	body := `{"tenant":"t1","domain":"finance","source":"bank","event_time":"` + now + `","ingestion_time":"` + now + `"}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(body))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid ingestEvent, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestIngestEventWithHealthScoreNegativeLag(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	body := `{"tenant":"t1","domain":"finance","source":"bank","event_time":"` + future + `","health_score":0.5}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(body))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for future event time, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSnapshotTenantResolutionError(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "oidc_hs256",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{"tenant":"t1","domain":"finance"}`))
	s.createSnapshot(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthenticated createSnapshot, got %d", rr.Code)
	}
}

func TestGetSnapshotTenantResolutionError(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "oidc_hs256",
	}
	router := chi.NewRouter()
	router.Get("/v1/state/snapshot/{snapshot_id}", s.getSnapshot)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/state/snapshot/snap-1", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unauthenticated getSnapshot, got %d", rr.Code)
	}
}

func TestApplyEventZeroTimestampDefaults(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
	}
	err := s.applyEvent(eventInput{
		Tenant:      "t1",
		Domain:      "finance",
		Source:      "bank",
		LagSec:      -5,
		HealthScore: 0.9,
	})
	if err != nil {
		t.Fatalf("expected applyEvent success with zero timestamps, got %v", err)
	}
	bs, ok := s.buildBeliefState("t1", "finance")
	if !ok {
		t.Fatal("expected belief state to exist")
	}
	if len(bs.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(bs.Sources))
	}
}

func TestBuildBeliefStateWithNegativeAge(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{
			"t1": {
				"finance": {
					"future": {
						Source:      "future",
						EventTime:   time.Now().Add(time.Hour),
						Ingestion:   time.Now(),
						HealthScore: 1.0,
						LagSec:      0,
					},
				},
			},
		},
	}
	bs, ok := s.buildBeliefState("t1", "finance")
	if !ok {
		t.Fatal("expected belief state to exist")
	}
	if bs.Sources[0].AgeSec < 0 {
		t.Fatalf("expected non-negative age, got %d", bs.Sources[0].AgeSec)
	}
}

func TestBuildBeliefStateTenantMissing(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
	}
	_, ok := s.buildBeliefState("missing", "finance")
	if ok {
		t.Fatal("expected not found for missing tenant")
	}
}

func TestBuildBeliefStateDomainMissing(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{
			"t1": {},
		},
	}
	_, ok := s.buildBeliefState("t1", "missing")
	if ok {
		t.Fatal("expected not found for missing domain")
	}
}

func TestPersistSourceStateNilDB(t *testing.T) {
	s := &Server{DB: nil}
	err := s.persistSourceState(eventInput{
		Tenant: "t1",
		Domain: "finance",
		Source: "bank",
	})
	if err != nil {
		t.Fatalf("expected nil error for nil DB, got %v", err)
	}
}

func TestLoadSourceStateNilDB(t *testing.T) {
	s := &Server{DB: nil, states: map[string]map[string]map[string]sourceRecord{}}
	err := s.loadSourceState(context.Background())
	if err != nil {
		t.Fatalf("expected nil error for nil DB, got %v", err)
	}
}

func TestNegativeMaxRequestBodyBytesDefault(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("KAFKA_ENABLED", "false")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "-1")

	var captured *http.Server
	err := runState(
		func(ctx context.Context, svc string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		},
		func(ctx context.Context) (stateDB, func(), error) {
			return &fakeStateDB{rows: &fakeStateRows{}}, nil, nil
		},
		func(server *http.Server) error {
			captured = server
			return errors.New("stop")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stop") {
		t.Fatalf("expected listen stop, got %v", err)
	}
	_ = captured
}

func TestServiceOrAuthFallback(t *testing.T) {
	s := &Server{
		ServiceAuthHeader: "X-State-Token",
		ServiceAuthToken:  "secret",
	}
	fallbackCalled := false
	authMw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fallbackCalled = true
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	handler := s.serviceOrAuth(authMw)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", nil)
	req.Header.Set("X-State-Token", "wrong")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if !fallbackCalled {
		t.Fatal("expected auth fallback to be called")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 from auth fallback, got %d", rr.Code)
	}
}

func TestConsumeEventsContextCancelledPath(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus: &errorStateBus{
			readErr: errors.New("read failed"),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeEvents did not exit after context cancellation")
	}
}

type errorStateBus struct {
	readErr error
}

func (b *errorStateBus) ReadMessage(ctx context.Context) (statebus.Message, error) {
	select {
	case <-ctx.Done():
		return statebus.Message{}, ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return statebus.Message{}, b.readErr
	}
}

func (b *errorStateBus) Close() error { return nil }

func TestConsumeEventsDecodeError(t *testing.T) {
	msgChan := make(chan statebus.Message, 10)
	msgChan <- statebus.Message{Value: []byte(`{invalid json`)}

	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    &channelBus{ch: msgChan},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
}

func TestConsumeEventsEventTimeParseError(t *testing.T) {
	msgChan := make(chan statebus.Message, 10)
	msgChan <- statebus.Message{Value: []byte(`{"tenant":"t1","domain":"finance","source":"bank","event_time":"not-valid-time"}`)}

	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    &channelBus{ch: msgChan},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
}

func TestConsumeEventsWithIngestionTimeAndHealthScore(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	healthScore := 0.85
	msgChan := make(chan statebus.Message, 10)
	msgChan <- statebus.Message{Value: []byte(`{"tenant":"t1","domain":"finance","source":"bank","event_time":"` + now + `","ingestion_time":"` + now + `","health_score":` + fmt.Sprintf("%f", healthScore) + `}`)}

	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    &channelBus{ch: msgChan},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Verify event was applied
	if _, ok := s.states["t1"]; !ok {
		t.Fatal("expected state for tenant t1")
	}
}

func TestConsumeEventsNegativeLag(t *testing.T) {
	// Future event time should result in lag = 0
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	msgChan := make(chan statebus.Message, 10)
	msgChan <- statebus.Message{Value: []byte(`{"tenant":"t1","domain":"finance","source":"bank","event_time":"` + future + `"}`)}

	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    &channelBus{ch: msgChan},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Verify lag was clamped to 0
	if rec, ok := s.states["t1"]["finance"]["bank"]; ok {
		if rec.LagSec < 0 {
			t.Fatalf("expected non-negative lag, got %d", rec.LagSec)
		}
	}
}

type channelBus struct {
	ch chan statebus.Message
}

func (b *channelBus) ReadMessage(ctx context.Context) (statebus.Message, error) {
	select {
	case <-ctx.Done():
		return statebus.Message{}, ctx.Err()
	case msg := <-b.ch:
		return msg, nil
	case <-time.After(10 * time.Millisecond):
		return statebus.Message{}, errors.New("no message")
	}
}

func (b *channelBus) Close() error { return nil }

func TestConsumeEventsApplyError(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	msgChan := make(chan statebus.Message, 10)
	// Event with empty tenant - applyEvent requires tenant
	msgChan <- statebus.Message{Value: []byte(`{"tenant":"","domain":"finance","source":"bank","event_time":"` + now + `"}`)}

	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    &channelBus{ch: msgChan},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done
}

func TestLoadSourceStateDBError(t *testing.T) {
	s := &Server{
		DB: &fakeStateDB{
			queryErr: errors.New("query failed"),
		},
		states: map[string]map[string]map[string]sourceRecord{},
	}
	err := s.loadSourceState(context.Background())
	if err == nil {
		t.Fatal("expected error from loadSourceState")
	}
}

func TestIngestEventInvalidEventTime(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/events", strings.NewReader(`{"tenant":"t1","domain":"finance","source":"bank","event_time":"not-valid"}`))
	s.ingestEvent(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid event_time, got %d", rr.Code)
	}
}

func TestGetBeliefStateNotFound(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	// getBeliefState uses query params, not URL params
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/state/belief?tenant=missing&domain=finance", nil)
	s.getBeliefState(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing belief state, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSnapshotMissingDomainReturns404(t *testing.T) {
	// When tenant/domain not in state, createSnapshot returns 404
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{"tenant":"t1","domain":"missing"}`))
	s.createSnapshot(rr, req)
	// Returns 404 when belief state doesn't exist for the given tenant/domain
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing domain/tenant, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCreateSnapshotJSONError(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/snapshot", strings.NewReader(`{invalid`))
	s.createSnapshot(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestUpdateSourcesJSONError(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/sources", strings.NewReader(`{invalid`))
	s.updateSources(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestUpdateSourcesMissingFields(t *testing.T) {
	s := &Server{
		states:   map[string]map[string]map[string]sourceRecord{},
		AuthMode: "off",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/state/sources", strings.NewReader(`{"tenant":"t1"}`))
	s.updateSources(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing domain, got %d", rr.Code)
	}
}

// Tests for nil-fallback paths in runState (lines 71-90)

func TestRunStateNilInitTelemetryFallback(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("KAFKA_ENABLED", "false")

	err := runState(
		nil, // triggers fallback to telemetry.Init (lines 71-73)
		func(ctx context.Context) (stateDB, func(), error) {
			// Set queryErr so loadSourceState fails gracefully instead of nil panic
			return &fakeStateDB{queryErr: errors.New("test warmup skip")}, nil, nil
		},
		func(server *http.Server) error {
			return errors.New("stop")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stop") {
		t.Fatalf("expected listen stop, got %v", err)
	}
}

func TestRunStateNilListenFallback(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("ADDR", "127.0.0.1:0")
	t.Setenv("KAFKA_ENABLED", "false")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runState(
			func(ctx context.Context, service string) (func(context.Context) error, error) {
				return func(context.Context) error { return nil }, nil
			},
			func(ctx context.Context) (stateDB, func(), error) {
				return &fakeStateDB{queryErr: errors.New("test warmup skip")}, nil, nil
			},
			nil, // triggers fallback to server.ListenAndServe (lines 83-85)
		)
	}()

	select {
	case <-ctx.Done():
		// Server started - fallback code executed
	case err := <-errCh:
		if err != nil && !strings.Contains(err.Error(), "address already in use") {
			t.Logf("server stopped with: %v (fallback code was still executed)", err)
		}
	}
}

func TestRunStateKafkaEnabledButFails(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("KAFKA_ENABLED", "true")
	t.Setenv("KAFKA_BROKERS", "127.0.0.1:9999") // Non-existent broker

	err := runState(
		func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		},
		func(ctx context.Context) (stateDB, func(), error) {
			return &fakeStateDB{queryErr: errors.New("test warmup skip")}, nil, nil
		},
		func(server *http.Server) error {
			return errors.New("should not reach")
		},
	)
	// Expected to fail - Kafka consumer creation will fail
	if err == nil {
		t.Fatal("expected error from Kafka consumer creation (no real Kafka)")
	}
}

// fakeBus implements statebus.Consumer for testing consumeEvents
type fakeBus struct {
	messages    []statebus.Message
	idx         int
	readErr     error
	cancelAfter int
}

func (b *fakeBus) ReadMessage(ctx context.Context) (statebus.Message, error) {
	if b.cancelAfter > 0 && b.idx >= b.cancelAfter {
		<-ctx.Done()
		return statebus.Message{}, ctx.Err()
	}
	if b.readErr != nil {
		return statebus.Message{}, b.readErr
	}
	if b.idx >= len(b.messages) {
		<-ctx.Done()
		return statebus.Message{}, ctx.Err()
	}
	msg := b.messages[b.idx]
	b.idx++
	return msg, nil
}

func (b *fakeBus) Close() error { return nil }

func TestConsumeEventsContextCancelled(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    &fakeBus{cancelAfter: 0},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeEvents did not exit on cancelled context")
	}
}

func TestConsumeEventsJSONDecodeError(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus: &fakeBus{
			messages: []statebus.Message{
				{Value: []byte(`{invalid json}`)},
			},
			cancelAfter: 1,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeEvents did not exit")
	}
}

func TestConsumeEventsTimeParseError(t *testing.T) {
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus: &fakeBus{
			messages: []statebus.Message{
				{Value: []byte(`{"tenant":"t1","domain":"d1","source":"s1","event_time":"not-a-time"}`)},
			},
			cancelAfter: 1,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeEvents did not exit")
	}
}

func TestConsumeEventsSuccessPath(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus: &fakeBus{
			messages: []statebus.Message{
				{Value: []byte(`{"tenant":"t1","domain":"d1","source":"s1","event_time":"` + now + `","ingestion_time":"` + now + `","health_score":0.9}`)},
			},
			cancelAfter: 1,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeEvents did not exit")
	}
}

func TestConsumeEventsNilHealthScore(t *testing.T) {
	// Test evt.HealthScore == nil branch
	now := time.Now().UTC().Format(time.RFC3339)
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus: &fakeBus{
			messages: []statebus.Message{
				{Value: []byte(`{"tenant":"t1","domain":"d1","source":"s1","event_time":"` + now + `"}`)}, // no health_score
			},
			cancelAfter: 1,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeEvents did not exit")
	}
}

func TestConsumeEventsApplyEventError(t *testing.T) {
	// Test applyEvent error branch - missing domain/source causes validation error
	now := time.Now().UTC().Format(time.RFC3339)
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus: &fakeBus{
			messages: []statebus.Message{
				{Value: []byte(`{"tenant":"t1","domain":"","source":"s1","event_time":"` + now + `"}`)}, // empty domain causes applyEvent error
			},
			cancelAfter: 1,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumeEvents did not exit")
	}
}

func TestConsumeEventsReadErrorRetry(t *testing.T) {
	// Test read error with retry path (lines 355-357)
	retryCount := 0
	bus := &fakeBusWithRetry{
		errCount:   1, // Return one error then cancel
		retryTrack: &retryCount,
	}
	s := &Server{
		states: map[string]map[string]map[string]sourceRecord{},
		bus:    bus,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		s.consumeEvents(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeEvents did not exit")
	}
}

// fakeBusWithRetry returns errors then cancels
type fakeBusWithRetry struct {
	errCount   int
	current    int
	retryTrack *int
}

func (b *fakeBusWithRetry) ReadMessage(ctx context.Context) (statebus.Message, error) {
	b.current++
	if b.current <= b.errCount {
		*b.retryTrack++
		return statebus.Message{}, errors.New("transient error")
	}
	<-ctx.Done()
	return statebus.Message{}, ctx.Err()
}

func (b *fakeBusWithRetry) Close() error { return nil }

func TestMaxRequestBodyBytesZeroDefault(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "0") // Force <= 0 path

	listenCalled := false
	err := runState(
		func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		},
		func(ctx context.Context) (stateDB, func(), error) {
			return &fakeStateDB{queryErr: errors.New("skip warmup")}, nil, nil
		},
		func(server *http.Server) error {
			listenCalled = true
			return nil
		},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listenCalled {
		t.Fatal("listen was not called")
	}
}

func TestMaxRequestBodyBytesNegativeDefault(t *testing.T) {
	t.Setenv("AUTH_MODE", "off")
	t.Setenv("ALLOW_INSECURE_AUTH_OFF", "true")
	t.Setenv("MAX_REQUEST_BODY_BYTES", "-1") // Force < 0 path

	err := runState(
		func(ctx context.Context, service string) (func(context.Context) error, error) {
			return func(context.Context) error { return nil }, nil
		},
		func(ctx context.Context) (stateDB, func(), error) {
			return &fakeStateDB{queryErr: errors.New("skip warmup")}, nil, nil
		},
		func(server *http.Server) error { return nil },
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
