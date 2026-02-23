package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"axiom/pkg/httpx"
	"axiom/pkg/telemetry"

	"github.com/go-chi/chi/v5"
)

// Testable variables for main()
var (
	logFatalf       = log.Fatalf
	initTelemetryFn = telemetry.Init
	listenFn        = func(server *http.Server) error { return server.ListenAndServe() }
)

func main() {
	if err := runToolMock(initTelemetryFn, listenFn); err != nil {
		logFatalf("server error: %v", err)
	}
}

func handleExecute(w http.ResponseWriter, r *http.Request) {
	var envelope map[string]interface{}
	_ = json.NewDecoder(r.Body).Decode(&envelope)
	mode, _ := envelope["mode"].(string)
	payload := envelope
	if p, ok := envelope["payload"]; ok {
		payload = map[string]interface{}{"payload": p}
	}
	resp := map[string]interface{}{"status": "ok", "echo": payload}
	if mode != "" {
		resp["mode"] = mode
	}
	httpx.WriteJSON(w, 200, resp)
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

func runToolMock(
	initTelemetry func(context.Context, string) (func(context.Context) error, error),
	listen func(*http.Server) error,
) error {
	if initTelemetry == nil {
		initTelemetry = telemetry.Init
	}
	if listen == nil {
		listen = func(server *http.Server) error { return server.ListenAndServe() }
	}

	shutdown, err := initTelemetry(context.Background(), "tool-mock")
	if err != nil {
		return err
	}
	defer func() { _ = shutdown(context.Background()) }()

	r := chi.NewRouter()
	r.Use(telemetry.HTTPMiddleware("tool-mock"))
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "tool-mock"})
	})
	r.Post("/execute", handleExecute)

	addr := env("ADDR", ":8085")
	log.Printf("tool-mock listening on %s", addr)
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
