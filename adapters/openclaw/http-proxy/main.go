package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"axiom/adapters/openclaw"
	"axiom/pkg/httpx"
)

func main() {
	cfg := openclaw.LoadConfigFromEnv()
	signer, err := openclaw.LoadSigner(cfg)
	if err != nil {
		log.Fatalf("openclaw-http-proxy signer: %v", err)
	}
	adapter := openclaw.NewAdapter(cfg, openclaw.NewHTTPGatewayClient(cfg), signer, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "openclaw-http-proxy"})
	})
	mux.HandleFunc("/metrics", adapter.Metrics().Handler())
	mux.HandleFunc("/metrics/prometheus", adapter.Metrics().PrometheusHandler())
	mux.HandleFunc("/tools/invoke", func(w http.ResponseWriter, r *http.Request) {
		handleInvoke(adapter, w, r)
	})
	mux.HandleFunc("/v1/openclaw/invoke", func(w http.ResponseWriter, r *http.Request) {
		handleInvoke(adapter, w, r)
	})
	mux.HandleFunc("/v1/escrow/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			httpx.Error(w, 405, "method not allowed")
			return
		}
		limit := 50
		if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		status := strings.TrimSpace(r.URL.Query().Get("status"))
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		body, err := openclaw.NewHTTPGatewayClient(cfg).ListEscrows(ctx, limit, status)
		if err != nil {
			httpx.Error(w, 502, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	addr := env("ADDR", ":8090")
	server := &http.Server{
		Addr:              addr,
		Handler:           httpx.SecurityHeadersMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("openclaw-http-proxy listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("openclaw-http-proxy listen: %v", err)
	}
}

func handleInvoke(adapter *openclaw.Adapter, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.Error(w, 405, "method not allowed")
		return
	}
	defer r.Body.Close()
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	req, err := decodeRequest(raw)
	if err != nil {
		httpx.Error(w, 400, "invalid request")
		return
	}
	if req.ActorID == "" {
		req.ActorID = strings.TrimSpace(r.Header.Get("X-OpenClaw-Actor-Id"))
	}
	if req.Tenant == "" {
		req.Tenant = strings.TrimSpace(r.Header.Get("X-OpenClaw-Tenant"))
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = strings.TrimSpace(r.Header.Get("X-OpenClaw-Idempotency-Key"))
	}
	if len(req.Roles) == 0 {
		roles := strings.TrimSpace(r.Header.Get("X-OpenClaw-Roles"))
		if roles != "" {
			req.Roles = strings.Split(roles, ",")
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	resp, err := adapter.HandleInvocation(ctx, req)
	if err != nil {
		httpx.Error(w, 500, err.Error())
		return
	}
	httpx.WriteJSON(w, 200, resp)
}

func decodeRequest(raw json.RawMessage) (openclaw.InvokeRequest, error) {
	return openclaw.ParseInvokeRequest(raw)
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
