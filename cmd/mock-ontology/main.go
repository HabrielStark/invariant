package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"axiom/pkg/httpx"
	"axiom/pkg/telemetry"

	"github.com/go-chi/chi/v5"
)

type Object struct {
	ID   string                 `json:"id"`
	Data map[string]interface{} `json:"data"`
}

type Store struct {
	mu    sync.Mutex
	items map[string]Object
}

// Testable variables for main()
var (
	logFatalf       = log.Fatalf
	initTelemetryFn = telemetry.Init
	listenFn        = func(server *http.Server) error { return server.ListenAndServe() }
)

func main() {
	if err := runMockOntology(initTelemetryFn, listenFn); err != nil {
		logFatalf("server error: %v", err)
	}
}

func (s *Store) execute(w http.ResponseWriter, r *http.Request) {
	var envelope map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&envelope)
	mode, _ := envelope["mode"].(string)
	payload := envelope
	if p, ok := envelope["payload"]; ok {
		if pm, ok := p.(map[string]interface{}); ok {
			payload = pm
		}
	}
	var req struct {
		Op     string   `json:"op"`
		Object Object   `json:"object"`
		IDs    []string `json:"ids"`
	}
	raw, _ := json.Marshal(payload)
	_ = json.Unmarshal(raw, &req)

	s.mu.Lock()
	defer s.mu.Unlock()
	if mode == "READ_ONLY" || mode == "DRY_RUN" {
		httpx.WriteJSON(w, 200, map[string]interface{}{"status": "ok", "mode": mode, "count": len(s.items)})
		return
	}
	switch req.Op {
	case "create":
		s.items[req.Object.ID] = req.Object
	case "update":
		if _, ok := s.items[req.Object.ID]; ok {
			s.items[req.Object.ID] = req.Object
		}
	case "delete":
		for _, id := range req.IDs {
			delete(s.items, id)
		}
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"status": "ok", "count": len(s.items)})
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDurationSec(k string, def int) time.Duration {
	return time.Second * time.Duration(envInt(k, def))
}

func runMockOntology(
	initTelemetry func(context.Context, string) (func(context.Context) error, error),
	listen func(*http.Server) error,
) error {
	if initTelemetry == nil {
		initTelemetry = telemetry.Init
	}
	if listen == nil {
		listen = func(server *http.Server) error { return server.ListenAndServe() }
	}

	shutdown, err := initTelemetry(context.Background(), "mock-ontology")
	if err != nil {
		return err
	}
	defer func() { _ = shutdown(context.Background()) }()

	store := &Store{items: map[string]Object{}}
	r := chi.NewRouter()
	r.Use(telemetry.HTTPMiddleware("mock-ontology"))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "mock-ontology"})
	})
	r.Post("/actions/execute", store.execute)

	addr := env("ADDR", ":8084")
	log.Printf("mock-ontology listening on %s", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: envDurationSec("HTTP_READ_HEADER_TIMEOUT_SEC", 5),
		ReadTimeout:       envDurationSec("HTTP_READ_TIMEOUT_SEC", 15),
		WriteTimeout:      envDurationSec("HTTP_WRITE_TIMEOUT_SEC", 30),
		IdleTimeout:       envDurationSec("HTTP_IDLE_TIMEOUT_SEC", 120),
	}
	return listen(server)
}
