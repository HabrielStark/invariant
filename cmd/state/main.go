package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/hardening"
	"axiom/pkg/httpx"
	"axiom/pkg/models"
	"axiom/pkg/statebus"
	"axiom/pkg/store"
	"axiom/pkg/telemetry"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type stateDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Server struct {
	DB                  stateDB
	mu                  sync.Mutex
	states              map[string]map[string]map[string]sourceRecord
	bus                 statebus.Consumer
	AuthMode            string
	AuthSecret          string
	ServiceAuthHeader   string
	ServiceAuthToken    string
	MaxRequestBodyBytes int64
}

type sourceRecord struct {
	Source      string
	EventTime   time.Time
	Ingestion   time.Time
	HealthScore float64
	LagSec      int
	JitterSec   int
}

// Testable variables for main()
var (
	logFatalf       = log.Fatalf
	initTelemetryFn = telemetry.Init
	openDBFnS       func(context.Context) (stateDB, func(), error)
	listenFnS       func(*http.Server) error
)

func main() {
	if err := runState(initTelemetryFn, openDBFnS, listenFnS); err != nil {
		logFatalf("state: %v", err)
	}
}

func runState(
	initTelemetry func(context.Context, string) (func(context.Context) error, error),
	openDB func(context.Context) (stateDB, func(), error),
	listen func(*http.Server) error,
) error {
	if initTelemetry == nil {
		initTelemetry = telemetry.Init
	}
	if openDB == nil {
		openDB = func(ctx context.Context) (stateDB, func(), error) {
			pool, err := store.NewPostgresPool(ctx)
			if err != nil {
				return nil, nil, err
			}
			return pool, pool.Close, nil
		}
	}
	if listen == nil {
		listen = func(server *http.Server) error { return server.ListenAndServe() }
	}

	ctx := context.Background()
	shutdown, err := initTelemetry(ctx, "state")
	if err != nil {
		return err
	}
	defer func() { _ = shutdown(context.Background()) }()

	db, closeDB, err := openDB(ctx)
	if err != nil {
		return err
	}
	if closeDB != nil {
		defer closeDB()
	}

	s := &Server{
		DB:                  db,
		states:              map[string]map[string]map[string]sourceRecord{},
		AuthMode:            env("AUTH_MODE", "oidc_hs256"),
		AuthSecret:          env("OIDC_HS256_SECRET", ""),
		ServiceAuthHeader:   env("STATE_AUTH_HEADER", ""),
		ServiceAuthToken:    env("STATE_AUTH_TOKEN", ""),
		MaxRequestBodyBytes: int64(envInt("MAX_REQUEST_BODY_BYTES", 1<<20)),
	}
	runtimeEnv := env("ENVIRONMENT", env("APP_ENV", ""))
	if strings.EqualFold(s.AuthMode, "off") {
		if env("ALLOW_INSECURE_AUTH_OFF", "false") != "true" {
			return errors.New("AUTH_MODE=off is disabled unless ALLOW_INSECURE_AUTH_OFF=true")
		}
		if isProductionLikeEnv(runtimeEnv) {
			return errors.New("AUTH_MODE=off is forbidden in production-like environments")
		}
		if !isExplicitNonProductionEnv(runtimeEnv) && !isTestBinaryProcess() {
			return errors.New("AUTH_MODE=off requires ENVIRONMENT=development|dev|local|test")
		}
	}
	if err := hardening.ValidateProduction(hardening.Options{
		Service:            "state",
		Environment:        runtimeEnv,
		StrictProdSecurity: env("STRICT_PROD_SECURITY", "true"),
		DatabaseRequireTLS: env("DATABASE_REQUIRE_TLS", ""),
		CORSAllowedOrigins: env("CORS_ALLOWED_ORIGINS", ""),
		RequiredServiceSecrets: []hardening.EnvRequirement{
			{Name: "STATE_AUTH_HEADER", Value: s.ServiceAuthHeader},
			{Name: "STATE_AUTH_TOKEN", Value: s.ServiceAuthToken},
		},
	}); err != nil {
		return err
	}
	if s.MaxRequestBodyBytes <= 0 {
		s.MaxRequestBodyBytes = 1 << 20
	}
	if err := s.loadSourceState(ctx); err != nil {
		log.Printf("state warmup failed: %v", err)
	}
	if env("KAFKA_ENABLED", "false") == "true" {
		consumer, err := statebus.NewKafkaConsumer(statebus.KafkaConfig{
			Brokers: strings.Split(env("KAFKA_BROKERS", "localhost:9092"), ","),
			Topic:   env("KAFKA_TOPIC", "axiom.state.events"),
			GroupID: env("KAFKA_GROUP_ID", "axiom-state"),
		})
		if err != nil {
			return err
		}
		s.bus = consumer
		go s.consumeEvents(context.Background())
	}
	defer func() {
		if s.bus != nil {
			_ = s.bus.Close()
		}
	}()

	r := chi.NewRouter()
	r.Use(httpx.CORSMiddleware(env("CORS_ALLOWED_ORIGINS", "")))
	r.Use(httpx.SecurityHeadersMiddleware)
	r.Use(telemetry.HTTPMiddleware("state"))
	r.Use(s.limitRequestBodyMiddleware)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "state"})
	})
	authTimeout := time.Millisecond * time.Duration(envInt("AUTH_TIMEOUT_MS", 5000))
	authMw := auth.Middleware(
		s.AuthMode,
		s.AuthSecret,
		auth.WithJWKS(env("OIDC_JWKS_URL", "")),
		auth.WithIssuer(env("OIDC_ISSUER", "")),
		auth.WithAudience(env("OIDC_AUDIENCE", "")),
		auth.WithTimeout(authTimeout),
	)
	api := chi.NewRouter()
	api.Use(s.serviceOrAuth(authMw))
	api.Post("/v1/state/sources", s.updateSources)
	api.Post("/v1/state/events", s.ingestEvent)
	api.Post("/v1/state/snapshot", s.createSnapshot)
	api.Get("/v1/state/snapshot/{snapshot_id}", s.getSnapshot)
	api.Get("/v1/beliefstate", s.getBeliefState)
	r.Mount("/", api)

	addr := env("ADDR", ":8083")
	log.Printf("state service listening on %s", addr)
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

func (s *Server) updateSources(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant  string               `json:"tenant"`
		Domain  string               `json:"domain"`
		Sources []models.SourceState `json:"sources"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	tenant, err := s.resolveTenant(r, req.Tenant)
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	if req.Domain == "" {
		httpx.Error(w, 400, "domain required")
		return
	}
	now := time.Now().UTC()
	for _, src := range req.Sources {
		eventTime := now.Add(-time.Duration(src.AgeSec) * time.Second)
		_ = s.applyEvent(eventInput{
			Tenant:      tenant,
			Domain:      req.Domain,
			Source:      src.Source,
			EventTime:   eventTime,
			Ingestion:   now,
			HealthScore: src.HealthScore,
			LagSec:      src.LagSec,
			JitterSec:   src.JitterSec,
		})
	}
	httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
}

func (s *Server) getBeliefState(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		httpx.Error(w, 400, "domain required")
		return
	}
	tenant, err := s.resolveTenant(r, r.URL.Query().Get("tenant"))
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	state, ok := s.buildBeliefState(tenant, domain)
	if !ok {
		httpx.Error(w, 404, "not found")
		return
	}
	httpx.WriteJSON(w, 200, state)
}

func (s *Server) ingestEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant        string   `json:"tenant"`
		Domain        string   `json:"domain"`
		Source        string   `json:"source"`
		EventTime     string   `json:"event_time"`
		IngestionTime string   `json:"ingestion_time"`
		HealthScore   *float64 `json:"health_score,omitempty"`
		JitterSec     int      `json:"jitter_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	tenant, err := s.resolveTenant(r, req.Tenant)
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	if req.Domain == "" || req.Source == "" || req.EventTime == "" {
		httpx.Error(w, 400, "domain, source, event_time required")
		return
	}
	eventTime, err := time.Parse(time.RFC3339, req.EventTime)
	if err != nil {
		httpx.Error(w, 400, "event_time must be RFC3339")
		return
	}
	ingestion := time.Now().UTC()
	if req.IngestionTime != "" {
		parsed, err := time.Parse(time.RFC3339, req.IngestionTime)
		if err != nil {
			httpx.Error(w, 400, "ingestion_time must be RFC3339")
			return
		}
		ingestion = parsed
	}
	health := 1.0
	if req.HealthScore != nil {
		health = *req.HealthScore
	}
	lag := int(ingestion.Sub(eventTime).Seconds())
	if lag < 0 {
		lag = 0
	}

	_ = s.applyEvent(eventInput{
		Tenant:      tenant,
		Domain:      req.Domain,
		Source:      req.Source,
		EventTime:   eventTime.UTC(),
		Ingestion:   ingestion.UTC(),
		HealthScore: health,
		LagSec:      lag,
		JitterSec:   req.JitterSec,
	})

	state, _ := s.buildBeliefState(tenant, req.Domain)
	httpx.WriteJSON(w, 200, state)
}

type eventInput struct {
	Tenant      string
	Domain      string
	Source      string
	EventTime   time.Time
	Ingestion   time.Time
	HealthScore float64
	LagSec      int
	JitterSec   int
}

type busEvent struct {
	Tenant        string   `json:"tenant,omitempty"`
	Domain        string   `json:"domain"`
	Source        string   `json:"source"`
	EventTime     string   `json:"event_time"`
	IngestionTime string   `json:"ingestion_time,omitempty"`
	HealthScore   *float64 `json:"health_score,omitempty"`
	JitterSec     int      `json:"jitter_sec,omitempty"`
}

func (s *Server) applyEvent(evt eventInput) error {
	if evt.Domain == "" || evt.Source == "" {
		return errors.New("domain and source required")
	}
	if evt.LagSec < 0 {
		evt.LagSec = 0
	}
	if evt.Ingestion.IsZero() {
		evt.Ingestion = time.Now().UTC()
	}
	if evt.EventTime.IsZero() {
		evt.EventTime = evt.Ingestion
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.states[evt.Tenant]; !ok {
		s.states[evt.Tenant] = map[string]map[string]sourceRecord{}
	}
	if _, ok := s.states[evt.Tenant][evt.Domain]; !ok {
		s.states[evt.Tenant][evt.Domain] = map[string]sourceRecord{}
	}
	s.states[evt.Tenant][evt.Domain][evt.Source] = sourceRecord{
		Source:      evt.Source,
		EventTime:   evt.EventTime,
		Ingestion:   evt.Ingestion,
		HealthScore: evt.HealthScore,
		LagSec:      evt.LagSec,
		JitterSec:   evt.JitterSec,
	}
	return s.persistSourceState(evt)
}

func (s *Server) consumeEvents(ctx context.Context) {
	for {
		msg, err := s.bus.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("state bus read error: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		var evt busEvent
		if err := json.Unmarshal(msg.Value, &evt); err != nil {
			log.Printf("state bus decode error: %v", err)
			continue
		}
		eventTime, err := time.Parse(time.RFC3339, evt.EventTime)
		if err != nil {
			log.Printf("state bus event_time parse error: %v", err)
			continue
		}
		ingestion := time.Now().UTC()
		if evt.IngestionTime != "" {
			if parsed, err := time.Parse(time.RFC3339, evt.IngestionTime); err == nil {
				ingestion = parsed
			}
		}
		health := 1.0
		if evt.HealthScore != nil {
			health = *evt.HealthScore
		}
		lag := int(ingestion.Sub(eventTime).Seconds())
		if lag < 0 {
			lag = 0
		}
		if err := s.applyEvent(eventInput{
			Tenant:      evt.Tenant,
			Domain:      evt.Domain,
			Source:      evt.Source,
			EventTime:   eventTime.UTC(),
			Ingestion:   ingestion.UTC(),
			HealthScore: health,
			LagSec:      lag,
			JitterSec:   evt.JitterSec,
		}); err != nil {
			log.Printf("state bus apply event error: %v", err)
		}
	}
}

func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tenant string `json:"tenant"`
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	tenant, err := s.resolveTenant(r, req.Tenant)
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	state, ok := s.buildBeliefState(tenant, req.Domain)
	if !ok {
		httpx.Error(w, 404, "not found")
		return
	}
	snapshotID := uuid.New().String()
	state.SnapshotID = snapshotID
	state.Tenant = tenant
	state.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	payload, _ := json.Marshal(state)
	_, err = s.DB.Exec(r.Context(), `INSERT INTO belief_snapshots(snapshot_id, tenant, domain, payload) VALUES ($1,$2,$3,$4)`, snapshotID, tenant, req.Domain, payload)
	if err != nil {
		internalServerError(w, "create snapshot", err)
		return
	}
	httpx.WriteJSON(w, 201, state)
}

func (s *Server) buildBeliefState(tenant, domain string) (models.BeliefState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tenantMap, ok := s.states[tenant]
	if !ok {
		return models.BeliefState{}, false
	}
	sourceMap, ok := tenantMap[domain]
	if !ok {
		return models.BeliefState{}, false
	}
	now := time.Now().UTC()
	sources := make([]models.SourceState, 0, len(sourceMap))
	for _, rec := range sourceMap {
		age := int(now.Sub(rec.EventTime).Seconds())
		if age < 0 {
			age = 0
		}
		lag := rec.LagSec
		if rec.Ingestion.After(rec.EventTime) {
			lag = int(rec.Ingestion.Sub(rec.EventTime).Seconds())
		}
		sources = append(sources, models.SourceState{
			Source:      rec.Source,
			AgeSec:      age,
			HealthScore: rec.HealthScore,
			LagSec:      lag,
			JitterSec:   rec.JitterSec,
		})
	}
	return models.BeliefState{
		Tenant:    tenant,
		Domain:    domain,
		Sources:   sources,
		CreatedAt: now.Format(time.RFC3339),
	}, true
}

func (s *Server) getSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshotID := chi.URLParam(r, "snapshot_id")
	tenant, err := s.resolveTenant(r, r.URL.Query().Get("tenant"))
	if err != nil {
		httpx.Error(w, 403, err.Error())
		return
	}
	row := s.DB.QueryRow(r.Context(), `SELECT payload FROM belief_snapshots WHERE tenant=$1 AND snapshot_id=$2`, tenant, snapshotID)
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		httpx.Error(w, 404, "not found")
		return
	}
	var state models.BeliefState
	if err := json.Unmarshal(payload, &state); err != nil {
		httpx.Error(w, 500, "corrupt snapshot")
		return
	}
	httpx.WriteJSON(w, 200, state)
}

func (s *Server) persistSourceState(evt eventInput) error {
	if s.DB == nil {
		return nil
	}
	_, err := s.DB.Exec(context.Background(), `
		INSERT INTO source_states(tenant, domain, source, event_time, ingestion_time, health_score, lag_sec, jitter_sec)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (tenant, domain, source) DO UPDATE SET
			event_time=EXCLUDED.event_time,
			ingestion_time=EXCLUDED.ingestion_time,
			health_score=EXCLUDED.health_score,
			lag_sec=EXCLUDED.lag_sec,
			jitter_sec=EXCLUDED.jitter_sec,
			updated_at=now()
	`, evt.Tenant, evt.Domain, evt.Source, evt.EventTime, evt.Ingestion, evt.HealthScore, evt.LagSec, evt.JitterSec)
	return err
}

func (s *Server) loadSourceState(ctx context.Context) error {
	if s.DB == nil {
		return nil
	}
	rows, err := s.DB.Query(ctx, `
		SELECT tenant, domain, source, event_time, ingestion_time, health_score, lag_sec, jitter_sec
		FROM source_states
	`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var tenant string
		var domain string
		var rec sourceRecord
		if err := rows.Scan(&tenant, &domain, &rec.Source, &rec.EventTime, &rec.Ingestion, &rec.HealthScore, &rec.LagSec, &rec.JitterSec); err != nil {
			return err
		}
		if _, ok := s.states[tenant]; !ok {
			s.states[tenant] = map[string]map[string]sourceRecord{}
		}
		if _, ok := s.states[tenant][domain]; !ok {
			s.states[tenant][domain] = map[string]sourceRecord{}
		}
		s.states[tenant][domain][rec.Source] = rec
	}
	return rows.Err()
}

func (s *Server) serviceOrAuth(authMw func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.serviceTokenValid(r) {
				p := auth.Principal{Subject: "service", Roles: []string{"service"}}
				next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
				return
			}
			authMw(next).ServeHTTP(w, r)
		})
	}
}

func (s *Server) serviceTokenValid(r *http.Request) bool {
	if s.ServiceAuthHeader == "" || s.ServiceAuthToken == "" {
		return false
	}
	token := r.Header.Get(s.ServiceAuthHeader)
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.ServiceAuthToken)) == 1
}

func (s *Server) resolveTenant(r *http.Request, reqTenant string) (string, error) {
	reqTenant = strings.TrimSpace(reqTenant)
	principal, ok := auth.PrincipalFromContext(r.Context())
	if ok && auth.HasAnyRole(principal, "service") {
		if reqTenant == "" {
			return "", errors.New("tenant required")
		}
		return reqTenant, nil
	}
	if strings.EqualFold(s.AuthMode, "off") {
		if reqTenant != "" {
			return reqTenant, nil
		}
		if ok && principal.Tenant != "" {
			return principal.Tenant, nil
		}
		return "", nil
	}
	if !ok {
		return "", errors.New("unauthenticated")
	}
	if principal.Tenant == "" {
		return "", errors.New("tenant required")
	}
	if reqTenant != "" && !strings.EqualFold(reqTenant, principal.Tenant) {
		return "", errors.New("tenant mismatch")
	}
	return principal.Tenant, nil
}

func internalServerError(w http.ResponseWriter, op string, err error) {
	if err != nil {
		log.Printf("state %s: %v", op, err)
	}
	httpx.Error(w, 500, "internal error")
}

func isProductionLikeEnv(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "prod", "production", "staging", "stage":
		return true
	default:
		return false
	}
}

func isExplicitNonProductionEnv(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "dev", "development", "local", "test", "testing":
		return true
	default:
		return false
	}
}

func isTestBinaryProcess() bool {
	return strings.HasSuffix(strings.TrimSpace(os.Args[0]), ".test")
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

func (s *Server) limitRequestBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.MaxRequestBodyBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.MaxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func envDurationSec(k string, def int) time.Duration {
	return time.Second * time.Duration(envInt(k, def))
}
