package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"axiom/pkg/abac"
	"axiom/pkg/adapters/palantir"
	"axiom/pkg/audit"
	"axiom/pkg/auth"
	"axiom/pkg/axiomdsl"
	"axiom/pkg/escrowfsm"
	"axiom/pkg/hardening"
	"axiom/pkg/httpx"
	"axiom/pkg/metrics"
	"axiom/pkg/models"
	"axiom/pkg/policyeval"
	"axiom/pkg/policyir"
	"axiom/pkg/ratelimit"
	"axiom/pkg/rta"
	"axiom/pkg/shield"
	"axiom/pkg/smt"
	"axiom/pkg/store"
	"axiom/pkg/stream"
	"axiom/pkg/telemetry"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	DB                     gatewayDB
	Cache                  store.Cache
	HTTPClient             *http.Client
	VerifierURL            string
	StateURL               string
	ToolURL                string
	OntologyURL            string
	PolicyURL              string
	Audit                  auditStore
	Config                 rta.Config
	Redis                  *redis.Client
	Metrics                *metrics.Registry
	UpstreamRetries        int
	UpstreamRetryDelay     time.Duration
	VerifierAuthHeader     string
	VerifierAuthToken      string
	StateAuthHeader        string
	StateAuthToken         string
	ToolAuthHeader         string
	ToolAuthToken          string
	OntologyAuthHeader     string
	OntologyAuthToken      string
	RateLimiter            ratelimit.Limiter
	RateLimitEnabled       bool
	RateLimitPerMinute     int
	RateLimitWindow        time.Duration
	PolicyCache            *policyCache
	PolicyCacheTTL         time.Duration
	PolicyRequirePublished bool
	ABACEnabled            bool
	ABACAttrURL            string
	ABACAttrHeader         string
	ABACAttrToken          string
	ABACAttrCacheTTL       time.Duration
	Events                 *stream.Hub
	AuthMode               string
	AuthSecret             string
	DomainRoleAllow        map[string]map[string]struct{}
	StrictActorBinding     bool
	RetentionEnabled       bool
	RetentionDays          int
	RetentionInterval      time.Duration
	ToolExecutor           palantir.Executor
	OntologyExecutor       palantir.Executor
	TrustedProxyCIDRs      []*net.IPNet
	MaxRequestBodyBytes    int64
	StrictShieldNoCommit   bool
	ExternalKeyStore       auth.KeyStore
}

type auditStore interface {
	Append(ctx context.Context, rec audit.Record) error
	Get(ctx context.Context, decisionID, tenant string) (audit.Record, error)
}

type gatewayDB interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var approvalsFromClaimRe = regexp.MustCompile(`(?i)approvals_required\s*([<>=!]+)?\s*(\d+)`)

var criticalReasonCodes = map[string]struct{}{
	"SOD_FAIL":             {},
	"ACCESS_FAIL":          {},
	"BAD_SIGNATURE":        {},
	"KEY_INVALID":          {},
	"REPLAY_DETECTED":      {},
	"SEQUENCE_REPLAY":      {},
	"INTENT_HASH_MISMATCH": {},
	"SUBJECT_RESTRICTED":   {},
}

const (
	incidentStatusOpen         = "OPEN"
	incidentStatusAcknowledged = "ACKNOWLEDGED"
	incidentStatusResolved     = "RESOLVED"
)

type cachedPolicy struct {
	policy    *policyir.PolicySetIR
	expiresAt time.Time
}

type policyCache struct {
	mu    sync.RWMutex
	items map[string]cachedPolicy
	ttl   time.Duration
}

func newPolicyCache(ttl time.Duration) *policyCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &policyCache{items: map[string]cachedPolicy{}, ttl: ttl}
}

func (c *policyCache) Get(key string) (*policyir.PolicySetIR, bool) {
	c.mu.RLock()
	item, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || time.Now().UTC().After(item.expiresAt) {
		return nil, false
	}
	return item.policy, true
}

func (c *policyCache) Set(key string, policy *policyir.PolicySetIR) {
	if policy == nil {
		return
	}
	c.mu.Lock()
	c.items[key] = cachedPolicy{policy: policy, expiresAt: time.Now().UTC().Add(c.ttl)}
	c.mu.Unlock()
}

type gatewayDBCloser interface {
	gatewayDB
	Close()
}

type gatewayInitTelemetryFunc func(ctx context.Context, service string) (func(context.Context) error, error)
type gatewayOpenDBFunc func(ctx context.Context) (gatewayDBCloser, error)
type gatewayOpenRedisFunc func(ctx context.Context) (*redis.Client, error)
type gatewayListenFunc func(server *http.Server) error
type gatewayStartLoopsFunc func(s *Server)

// Testable variables for main()
var (
	logFatalf      = log.Fatalf
	initTelemetryG = telemetry.Init
	openDBFnG      = func(ctx context.Context) (gatewayDBCloser, error) { return store.NewPostgresPool(ctx) }
	openRedisFnG   = store.NewRedis
	listenFnG      = func(server *http.Server) error { return server.ListenAndServe() }
	startLoopsFnG  = func(s *Server) {
		go s.expireEscrowsLoop(context.Background())
		if s.RetentionEnabled {
			go s.retentionLoop(context.Background())
		}
		go s.metricsLoop(context.Background())
	}
)

func main() {
	if err := runGateway(initTelemetryG, openDBFnG, openRedisFnG, listenFnG, startLoopsFnG); err != nil {
		logFatalf("gateway: %v", err)
	}
}

func runGateway(
	initTelemetry gatewayInitTelemetryFunc,
	openDB gatewayOpenDBFunc,
	openRedis gatewayOpenRedisFunc,
	listen gatewayListenFunc,
	startLoops gatewayStartLoopsFunc,
) error {
	ctx := context.Background()
	shutdown, err := initTelemetry(ctx, "gateway")
	if err != nil {
		return fmt.Errorf("otel: %w", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	pool, err := openDB(ctx)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	defer pool.Close()

	rateLimitEnabled := env("RATE_LIMIT_ENABLED", "true") == "true"
	redisClient, err := openRedis(ctx)
	if err != nil {
		log.Printf("redis unavailable, falling back to in-memory cache/limits: %v", err)
		redisClient = nil
	}
	if redisClient != nil {
		defer redisClient.Close()
	}
	cache := store.NewCache(ctx, redisClient)
	rateLimitWindow := time.Second * time.Duration(envInt("RATE_LIMIT_WINDOW_SEC", 60))
	if rateLimitWindow <= 0 {
		rateLimitWindow = time.Minute
	}
	policyCacheTTL := time.Second * time.Duration(envInt("POLICY_CACHE_TTL_SEC", 30))
	if policyCacheTTL <= 0 {
		policyCacheTTL = 30 * time.Second
	}
	abacAttrTTL := time.Second * time.Duration(envInt("ABAC_ATTR_CACHE_TTL_SEC", 300))
	if abacAttrTTL <= 0 {
		abacAttrTTL = 5 * time.Minute
	}
	trustedProxyCIDRs := parseCIDRs(env("TRUSTED_PROXY_CIDRS", ""))
	auditSalt := env("AUDIT_HASH_SALT", "")
	auditRedact := strings.EqualFold(strings.TrimSpace(env("AUDIT_REDACT", "false")), "true")
	maxRequestBodyBytes := int64(envInt("MAX_REQUEST_BODY_BYTES", 1<<20))
	if maxRequestBodyBytes <= 0 {
		maxRequestBodyBytes = 1 << 20
	}

	s := &Server{
		DB:          pool,
		Cache:       cache,
		HTTPClient:  telemetry.InstrumentClient(&http.Client{Timeout: time.Millisecond * time.Duration(envInt("UPSTREAM_TIMEOUT_MS", 3000))}),
		VerifierURL: env("VERIFIER_URL", "http://localhost:8081"),
		StateURL:    env("STATE_URL", "http://localhost:8083"),
		ToolURL:     env("TOOL_URL", "http://localhost:8085"),
		OntologyURL: env("ONTOLOGY_URL", "http://localhost:8084"),
		PolicyURL:   env("POLICY_URL", "http://localhost:8082"),
		Audit:       &audit.Writer{DB: pool, HashSalt: []byte(auditSalt), Redact: auditRedact},
		Config: rta.Config{
			MaxVerifyTime:   time.Millisecond * time.Duration(envInt("MAX_VERIFY_TIME_MS", 200)),
			MaxDeferTotal:   time.Millisecond * time.Duration(envInt("MAX_DEFER_TOTAL_MS", 30000)),
			MaxEscrowTTL:    time.Hour * time.Duration(envInt("MAX_ESCROW_TTL_HOURS", 24)),
			DegradedNoAllow: env("DEGRADED_NO_ALLOW", "true") == "true",
		},
		Redis:                  redisClient,
		Metrics:                metrics.NewRegistry(),
		UpstreamRetries:        envInt("UPSTREAM_RETRIES", 1),
		UpstreamRetryDelay:     time.Millisecond * time.Duration(envInt("UPSTREAM_RETRY_DELAY_MS", 50)),
		VerifierAuthHeader:     env("VERIFIER_AUTH_HEADER", ""),
		VerifierAuthToken:      env("VERIFIER_AUTH_TOKEN", ""),
		StateAuthHeader:        env("STATE_AUTH_HEADER", ""),
		StateAuthToken:         env("STATE_AUTH_TOKEN", ""),
		ToolAuthHeader:         env("TOOL_AUTH_HEADER", ""),
		ToolAuthToken:          env("TOOL_AUTH_TOKEN", ""),
		OntologyAuthHeader:     env("ONTOLOGY_AUTH_HEADER", ""),
		OntologyAuthToken:      env("ONTOLOGY_AUTH_TOKEN", ""),
		RateLimitEnabled:       rateLimitEnabled,
		RateLimitPerMinute:     envInt("RATE_LIMIT_PER_MINUTE", 240),
		RateLimitWindow:        rateLimitWindow,
		PolicyCache:            newPolicyCache(policyCacheTTL),
		PolicyCacheTTL:         policyCacheTTL,
		PolicyRequirePublished: env("POLICY_REQUIRE_PUBLISHED", "true") == "true",
		ABACEnabled:            env("ABAC_POLICY_ENABLED", "true") == "true",
		ABACAttrURL:            env("ABAC_ATTR_URL", ""),
		ABACAttrHeader:         env("ABAC_ATTR_HEADER", ""),
		ABACAttrToken:          env("ABAC_ATTR_TOKEN", ""),
		ABACAttrCacheTTL:       abacAttrTTL,
		Events:                 stream.NewHub(),
		AuthMode:               env("AUTH_MODE", "oidc_hs256"),
		AuthSecret:             env("OIDC_HS256_SECRET", ""),
		DomainRoleAllow:        parseDomainRoleAllow(env("ABAC_DOMAIN_ROLES", "")),
		StrictActorBinding:     env("ABAC_STRICT_ACTOR_BINDING", "true") == "true",
		RetentionEnabled:       env("RETENTION_ENABLED", "false") == "true",
		RetentionDays:          envInt("RETENTION_DAYS", 90),
		RetentionInterval:      time.Second * time.Duration(envInt("RETENTION_INTERVAL_SEC", 3600)),
		TrustedProxyCIDRs:      trustedProxyCIDRs,
		MaxRequestBodyBytes:    maxRequestBodyBytes,
		StrictShieldNoCommit:   env("SHIELD_STRICT_NO_COMMIT", "true") == "true",
	}
	externalKeyStore, err := buildExternalKeyStore(
		s.HTTPClient,
		env("KEYSTORE_PROVIDER", "db"),
		env("VAULT_ADDR", ""),
		env("VAULT_TOKEN", ""),
		env("VAULT_NAMESPACE", ""),
		env("VAULT_TRANSIT_MOUNT", "transit"),
		env("VAULT_KEY_PREFIX", ""),
		time.Millisecond*time.Duration(envInt("VAULT_KEY_LOOKUP_TIMEOUT_MS", 1500)),
		envInt("VAULT_KEY_LOOKUP_RETRIES", 1),
		time.Millisecond*time.Duration(envInt("VAULT_KEY_LOOKUP_RETRY_DELAY_MS", 100)),
	)
	if err != nil {
		return err
	}
	s.ExternalKeyStore = externalKeyStore
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
		Service:               "gateway",
		Environment:           runtimeEnv,
		StrictProdSecurity:    env("STRICT_PROD_SECURITY", "true"),
		DatabaseRequireTLS:    env("DATABASE_REQUIRE_TLS", ""),
		RedisAddr:             env("REDIS_ADDR", ""),
		RedisRequireTLS:       env("REDIS_REQUIRE_TLS", ""),
		RedisTLSInsecure:      env("REDIS_TLS_INSECURE", ""),
		RedisAllowInsecureTLS: env("REDIS_ALLOW_INSECURE_TLS", ""),
		CORSAllowedOrigins:    env("CORS_ALLOWED_ORIGINS", ""),
		RequiredServiceSecrets: []hardening.EnvRequirement{
			{Name: "VERIFIER_AUTH_HEADER", Value: s.VerifierAuthHeader},
			{Name: "VERIFIER_AUTH_TOKEN", Value: s.VerifierAuthToken},
			{Name: "STATE_AUTH_HEADER", Value: s.StateAuthHeader},
			{Name: "STATE_AUTH_TOKEN", Value: s.StateAuthToken},
		},
	}); err != nil {
		return err
	}
	if s.RateLimitEnabled {
		if redisClient != nil {
			s.RateLimiter = ratelimit.NewRedis(redisClient, rateLimitWindow)
		} else {
			s.RateLimiter = ratelimit.NewInMemory(rateLimitWindow)
		}
	}
	s.ToolExecutor = palantir.HTTPExecutor{
		Client:     s.HTTPClient,
		Endpoint:   s.ToolURL + "/execute",
		Headers:    authHeaderMap(s.ToolAuthHeader, s.ToolAuthToken),
		Retries:    s.UpstreamRetries,
		RetryDelay: s.UpstreamRetryDelay,
	}
	ontologyAdapter := strings.ToLower(strings.TrimSpace(env("ONTOLOGY_BACKEND", "")))
	if ontologyAdapter == "" {
		ontologyAdapter = strings.ToLower(strings.TrimSpace(env("ONTOLOGY_ADAPTER", "")))
	}
	if ontologyAdapter == "" {
		if strings.TrimSpace(env("FOUNDRY_BASE_URL", "")) != "" {
			ontologyAdapter = "foundry"
		} else {
			ontologyAdapter = "mock"
		}
	}
	switch ontologyAdapter {
	case "foundry":
		s.OntologyExecutor = palantir.FoundryOntologyExecutor{
			Client:       s.HTTPClient,
			BaseURL:      env("FOUNDRY_BASE_URL", ""),
			Token:        env("FOUNDRY_TOKEN", ""),
			OntologyID:   env("FOUNDRY_ONTOLOGY_ID", ""),
			Headers:      authHeaderMap(s.OntologyAuthHeader, s.OntologyAuthToken),
			Retries:      s.UpstreamRetries,
			RetryDelay:   s.UpstreamRetryDelay,
			AllowBatch:   env("FOUNDRY_ALLOW_BATCH", "true") == "true",
			AllowDryRun:  env("FOUNDRY_ALLOW_DRY_RUN", "true") == "true",
			AllowPreview: env("FOUNDRY_ALLOW_PREVIEW", "true") == "true",
		}
	default:
		s.OntologyExecutor = palantir.HTTPExecutor{
			Client:     s.HTTPClient,
			Endpoint:   s.OntologyURL + "/actions/execute",
			Headers:    authHeaderMap(s.OntologyAuthHeader, s.OntologyAuthToken),
			Retries:    s.UpstreamRetries,
			RetryDelay: s.UpstreamRetryDelay,
		}
	}

	r := chi.NewRouter()
	r.Use(httpx.CORSMiddleware(env("CORS_ALLOWED_ORIGINS", "")))
	r.Use(httpx.SecurityHeadersMiddleware)
	r.Use(s.metricsMiddleware)
	r.Use(telemetry.HTTPMiddleware("gateway"))
	r.Use(s.limitRequestBodyMiddleware)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "gateway"})
	})

	authRouter := chi.NewRouter()
	authTimeout := time.Millisecond * time.Duration(envInt("AUTH_TIMEOUT_MS", 5000))
	authRouter.Use(auth.Middleware(
		s.AuthMode,
		s.AuthSecret,
		auth.WithJWKS(env("OIDC_JWKS_URL", "")),
		auth.WithIssuer(env("OIDC_ISSUER", "")),
		auth.WithAudience(env("OIDC_AUDIENCE", "")),
		auth.WithTimeout(authTimeout),
	))
	authRouter.Get("/metrics", s.Metrics.Handler())
	authRouter.Get("/metrics/prometheus", s.Metrics.PrometheusHandler())
	authRouter.Post("/v1/tool/execute", s.withRoles(s.handleToolExecute, "operator", "financeoperator", "platformengineer"))
	authRouter.Post("/v1/ontology/actions/execute", s.withRoles(s.handleOntologyExecute, "operator", "financeoperator", "platformengineer"))
	authRouter.Post("/v1/verify", s.withRoles(s.proxyVerify, "operator", "complianceofficer", "platformengineer"))
	authRouter.Post("/v1/escrow/approve", s.withRoles(s.approveEscrow, "approver", "financemanager", "complianceofficer"))
	authRouter.Post("/v1/escrow/execute", s.withRoles(s.executeEscrow, "approver", "financemanager", "complianceofficer", "operator"))
	authRouter.Post("/v1/escrow/cancel", s.withRoles(s.cancelEscrow, "operator", "complianceofficer"))
	authRouter.Post("/v1/escrow/rollback", s.withRoles(s.rollbackEscrow, "operator", "complianceofficer"))
	authRouter.Get("/v1/escrow/{escrow_id}", s.withRoles(s.getEscrow, "operator", "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/escrows", s.withRoles(s.listEscrows, "operator", "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/beliefstate", s.withRoles(s.proxyBeliefState, "operator", "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/stream", s.withRoles(s.streamEvents, "operator", "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/verdicts", s.withRoles(s.listVerdicts, "operator", "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/incidents", s.withRoles(s.listIncidents, "operator", "complianceofficer", "securityadmin"))
	authRouter.Patch("/v1/incidents/{incident_id}", s.withRoles(s.patchIncident, "operator", "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/compliance/export", s.withRoles(s.exportComplianceData, "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/compliance/subjects/restrictions", s.withRoles(s.listSubjectRestrictions, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/compliance/subjects/restrict", s.withRoles(s.restrictSubject, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/compliance/subjects/unrestrict", s.withRoles(s.unrestrictSubject, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/compliance/retention/run", s.withRoles(s.runRetentionNow, "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/audit/{decision_id}", s.withRoles(s.getAudit, "operator", "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/audit/{decision_id}/replay", s.withRoles(s.replayAudit, "operator", "complianceofficer", "securityadmin"))
	// GDPR / data subject endpoints
	authRouter.Get("/v1/gdpr/export", s.withRoles(s.handleGDPRExport, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/gdpr/erasure", s.withRoles(s.handleGDPRErasure, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/gdpr/access-request", s.withRoles(s.handleGDPRAccessRequest, "complianceofficer", "securityadmin"))
	r.Mount("/", authRouter)

	if startLoops != nil {
		startLoops(s)
	}

	addr := env("ADDR", ":8080")
	log.Printf("gateway listening on %s", addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadHeaderTimeout: envDurationSec("HTTP_READ_HEADER_TIMEOUT_SEC", 5),
		ReadTimeout:       envDurationSec("HTTP_READ_TIMEOUT_SEC", 15),
		WriteTimeout:      envDurationSec("HTTP_WRITE_TIMEOUT_SEC", 30),
		IdleTimeout:       envDurationSec("HTTP_IDLE_TIMEOUT_SEC", 120),
	}
	if listen == nil {
		return errors.New("listen function required")
	}
	return listen(server)
}

type executeRequest struct {
	Intent        json.RawMessage `json:"intent"`
	Cert          json.RawMessage `json:"cert"`
	ToolPayload   json.RawMessage `json:"tool_payload,omitempty"`
	ActionPayload json.RawMessage `json:"action_payload,omitempty"`
}

func (s *Server) handleToolExecute(w http.ResponseWriter, r *http.Request) {
	s.handleExecute(w, r, "TOOL_CALL")
}

func (s *Server) handleOntologyExecute(w http.ResponseWriter, r *http.Request) {
	s.handleExecute(w, r, "ONTOLOGY_ACTION")
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request, expectedType string) {
	body, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	var req executeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if len(req.Intent) == 0 || len(req.Cert) == 0 {
		httpx.Error(w, 400, "intent and cert required")
		return
	}
	if err := models.ValidateNoJSONNumbers(req.Intent); err != nil {
		httpx.Error(w, 400, err.Error())
		return
	}
	var intent models.ActionIntent
	if err := json.Unmarshal(req.Intent, &intent); err != nil {
		httpx.Error(w, 400, "invalid intent")
		return
	}
	if intent.ActionType != expectedType {
		httpx.Error(w, 400, "action_type mismatch")
		return
	}
	var cert models.ActionCert
	if err := json.Unmarshal(req.Cert, &cert); err != nil {
		httpx.Error(w, 400, "invalid cert")
		return
	}
	if cert.PolicyVersion == "" || cert.PolicySetID == "" {
		httpx.Error(w, 400, "policy_set_id and policy_version required")
		return
	}
	if cert.ExpiresAt == "" {
		httpx.Error(w, 400, "expires_at required")
		return
	}
	if cert.Signature.Kid == "" {
		httpx.Error(w, 400, "signature.kid required")
		return
	}
	policy, policyErr := s.loadPolicy(r.Context(), cert.PolicySetID, cert.PolicyVersion)
	if s.ABACEnabled && policyErr != nil {
		s.writeDeferred(w, "ABAC_POLICY_UNAVAILABLE", cert, 5000)
		return
	}
	if ok, reason := s.authorizeIntent(r, intent, cert, policy); !ok {
		s.writeDeny(w, r.Context(), reason, intent, cert, nil)
		return
	}
	if reason, counterexample := validateBatchPayloadIntegrity(intent, req.ActionPayload); reason != "" {
		s.writeDeny(w, r.Context(), reason, intent, cert, counterexample)
		return
	}
	// idempotency
	if intent.IdempotencyKey == "" {
		httpx.Error(w, 400, "idempotency_key required")
		return
	}
	principal, _ := auth.PrincipalFromContext(r.Context())
	tenant := resolveTenant(intent, principal)
	idempotencyKey := scopedIdempotencyKey(tenant, intent.Actor.ID, intent.IdempotencyKey)
	if resp, ok := s.checkIdempotency(r.Context(), tenant, idempotencyKey); ok {
		httpx.WriteJSON(w, 200, resp)
		return
	}
	restricted, restrictionReason, err := s.isSubjectRestricted(r.Context(), tenant, intent.Actor.ID)
	if err != nil {
		s.writeDeferred(w, "SUBJECT_CONTROL_UNAVAILABLE", cert, 5000)
		return
	}
	if restricted {
		counterexample := &models.Counterexample{
			MinimalFacts: []string{
				"actor_id_hash=" + hashIdentity(intent.Actor.ID),
				"restriction_reason=" + restrictionReason,
			},
			FailedAxioms: []string{"Data_subject_restriction"},
		}
		s.writeDeny(w, r.Context(), "SUBJECT_RESTRICTED", intent, cert, counterexample)
		return
	}
	if blocked, retryAfter := s.checkRateLimit(r, intent, policy); blocked {
		decisionID := uuid.New().String()
		resp := models.GatewayResponse{
			Verdict:      rta.VerdictDeny,
			ReasonCode:   "RATE_LIMITED",
			RetryAfterMS: retryAfter,
			Counterexample: &models.Counterexample{
				MinimalFacts: []string{fmt.Sprintf("limit_per_window=%d", s.RateLimitPerMinute)},
				FailedAxioms: []string{"Rate_limit"},
			},
		}
		_ = s.Audit.Append(r.Context(), audit.Record{
			DecisionID:     decisionID,
			IntentRaw:      req.Intent,
			CertRaw:        req.Cert,
			PolicyVersion:  cert.PolicyVersion,
			Tenant:         tenant,
			ActorIDHash:    hashIdentity(intent.Actor.ID),
			Verdict:        resp.Verdict,
			ReasonCode:     resp.ReasonCode,
			Counterexample: marshalCounterexample(resp.Counterexample),
			CreatedAt:      time.Now().UTC(),
		})
		s.Metrics.IncVerdict(resp.Verdict)
		s.Metrics.IncReason(resp.ReasonCode)
		s.Metrics.IncVerdictReason(resp.Verdict, resp.ReasonCode)
		s.raiseRateLimitIncident(r.Context(), decisionID, intent)
		httpx.WriteJSON(w, 200, resp)
		return
	}
	// expiry
	var expiry time.Time
	if cert.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, cert.ExpiresAt)
		if err != nil {
			httpx.Error(w, 400, "expires_at must be RFC3339")
			return
		}
		expiry = exp
		if time.Now().UTC().After(expiry) {
			s.writeDeny(w, r.Context(), "CERT_EXPIRED", intent, cert, nil)
			return
		}
	}
	// canonical hash
	canonical, err := models.CanonicalizeJSON(req.Intent)
	if err != nil {
		httpx.Error(w, 400, "canonicalization failed")
		return
	}
	calcHash := models.IntentHash(canonical, cert.PolicyVersion, cert.Nonce)
	if cert.IntentHash != calcHash {
		s.writeDeny(w, r.Context(), "INTENT_HASH_MISMATCH", intent, cert, nil)
		return
	}
	// replay protection
	if cert.Nonce == "" {
		httpx.Error(w, 400, "nonce required")
		return
	}
	ttl := time.Minute * 5
	if !expiry.IsZero() {
		ttl = time.Until(expiry)
		if ttl <= 0 {
			s.writeDeny(w, r.Context(), "CERT_EXPIRED", intent, cert, nil)
			return
		}
	}
	nonceKey := scopedNonceKey(tenant, intent.Actor.ID, cert.Nonce)
	okNonce, err := s.Cache.SetNX(r.Context(), nonceKey, "1", ttl)
	if err != nil {
		s.writeDeferred(w, "REPLAY_UNAVAILABLE", cert, 2000)
		return
	}
	if !okNonce {
		s.writeDeny(w, r.Context(), "REPLAY_DETECTED", intent, cert, nil)
		return
	}
	// signature check
	pubKey, status, err := s.lookupKey(r.Context(), cert.Signature.Kid)
	if err != nil || status != "active" {
		s.writeDeny(w, r.Context(), "KEY_INVALID", intent, cert, nil)
		return
	}
	if err := auth.VerifyEd25519(pubKey, cert); err != nil {
		s.writeDeny(w, r.Context(), "BAD_SIGNATURE", intent, cert, nil)
		return
	}
	// optional monotonic sequence guard for series/batch certs
	if cert.Sequence != nil {
		accepted, err := s.acceptSequence(r.Context(), cert.Signature.Kid, tenant, intent.Actor.ID, cert.PolicySetID, *cert.Sequence, ttl)
		if err != nil {
			s.writeDeferred(w, "SEQUENCE_GUARD_UNAVAILABLE", cert, 2000)
			return
		}
		if !accepted {
			s.writeDeny(w, r.Context(), "SEQUENCE_REPLAY", intent, cert, nil)
			return
		}
	}

	// fetch belief snapshot
	belief, stateUnknown := s.fetchSnapshot(r.Context(), tenant, intent.Target.Domain)
	stateFresh := isStateFresh(belief, intent.DataRequirements.MaxStalenessSec, intent.DataRequirements.RequiredSources)
	reqTime := parseIntentTime(intent.Time.RequestTime, time.Now().UTC())
	deferExpired := shouldExpireDefer(s.Config.MaxDeferTotal, reqTime, time.Now().UTC())
	hasRollback := hasRollbackPlan(cert)
	batchPolicyPartition := s.evaluateBatchPolicyPartition(policy, intent, belief, req.ActionPayload)
	effectiveActionPayload := req.ActionPayload
	escrowActionPayload := req.ActionPayload
	if batchPolicyPartition != nil {
		if payload, ok := filterBatchActionPayloadByIDs(req.ActionPayload, batchPolicyPartition.AllowIDs); ok {
			effectiveActionPayload = payload
		}
		if payload, ok := filterBatchActionPayloadByIDs(req.ActionPayload, batchPolicyPartition.EscrowIDs); ok {
			escrowActionPayload = payload
		}
	}

	// call verifier
	verifyStart := time.Now()
	verifierResp, degraded := s.callVerifier(r.Context(), req.Intent, req.Cert, belief, false)
	s.Metrics.ObserveVerifyLatency(time.Since(verifyStart))
	criticalFail := false
	if verifierResp != nil {
		criticalFail = isCriticalReason(verifierResp.ReasonCode)
	}

	verdict, sh, reason := rta.Decide(s.Config, rta.Inputs{
		VerifierResp: verifierResp,
		StateFresh:   stateFresh,
		StateUnknown: stateUnknown,
		HasRollback:  hasRollback,
		CriticalFail: criticalFail,
		Degraded:     degraded,
		DeferExpired: deferExpired,
	})
	verdict, sh, reason = tightenBatchVerdict(verdict, sh, reason, batchPolicyPartition)

	decisionID := uuid.New().String()
	var counterexample *models.Counterexample
	if verifierResp != nil {
		counterexample = verifierResp.Counterexample
	}
	gwResp := models.GatewayResponse{
		Verdict:        verdict,
		ReasonCode:     reason,
		PolicySetID:    cert.PolicySetID,
		PolicyVersion:  cert.PolicyVersion,
		Counterexample: counterexample,
	}

	switch verdict {
	case rta.VerdictAllow:
		result, err := s.executeUpstream(r.Context(), intent.ActionType, req.ToolPayload, effectiveActionPayload)
		if err != nil {
			gwResp = models.GatewayResponse{Verdict: rta.VerdictShield, ReasonCode: "UPSTREAM_FAIL", Shield: shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly))}
		} else {
			gwResp.Result = result
		}
	case rta.VerdictShield:
		if sh != nil && sh.Type == shield.ShieldRequireApproval {
			escrowReq := req
			escrowReq.ActionPayload = escrowActionPayload
			escrowID, err := s.createEscrow(r.Context(), tenant, intent, escrowReq, cert, policy)
			if err != nil {
				gwResp = models.GatewayResponse{Verdict: rta.VerdictDeny, ReasonCode: "ESCROW_FAIL"}
			} else {
				gwResp = models.GatewayResponse{Verdict: rta.VerdictEscrow, ReasonCode: reason, Escrow: &models.EscrowRef{EscrowID: escrowID, Status: escrowfsm.Pending, TTL: s.Config.MaxEscrowTTL.String()}}
			}
			break
		}
		if sh == nil {
			sh = shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly))
		}
		if sh.Type == shield.ShieldReadOnly || sh.Type == shield.ShieldDryRun {
			result, err := s.executeShieldMode(r.Context(), intent.ActionType, sh.Type, req.ToolPayload, req.ActionPayload)
			if err == nil {
				gwResp.Result = result
			}
		} else if sh.Type == shield.ShieldSmallBatch {
			max := 100
			if sh.Params != nil {
				if v, ok := asInt64(sh.Params["max"]); ok && v > 0 {
					max = int(v)
				}
			}
			result, err := s.executeSmallBatch(r.Context(), intent.ActionType, effectiveActionPayload, max)
			if err == nil {
				gwResp.Result = result
				if batchPolicyPartition != nil && len(batchPolicyPartition.EscrowIDs) > 0 {
					escrowReq := req
					escrowReq.ActionPayload = escrowActionPayload
					escrowID, escrowErr := s.createEscrow(r.Context(), tenant, intent, escrowReq, cert, policy)
					if escrowErr == nil {
						gwResp.Escrow = &models.EscrowRef{EscrowID: escrowID, Status: escrowfsm.Pending, TTL: s.Config.MaxEscrowTTL.String()}
					}
				}
			}
		}
		gwResp.Shield = sh
	case rta.VerdictEscrow:
		escrowReq := req
		escrowReq.ActionPayload = escrowActionPayload
		escrowID, err := s.createEscrow(r.Context(), tenant, intent, escrowReq, cert, policy)
		if err != nil {
			gwResp = models.GatewayResponse{Verdict: rta.VerdictDeny, ReasonCode: "ESCROW_FAIL"}
		} else {
			gwResp.Escrow = &models.EscrowRef{EscrowID: escrowID, Status: escrowfsm.Pending, TTL: s.Config.MaxEscrowTTL.String()}
		}
	case rta.VerdictDefer:
		retryAfter := 5000
		if verifierResp != nil && verifierResp.RetryAfterMS > 0 {
			retryAfter = verifierResp.RetryAfterMS
		}
		gwResp.RetryAfterMS = retryAfter
		_ = s.Cache.Del(r.Context(), nonceKey)
	case rta.VerdictDeny:
		// no-op
	}
	gwResp.PolicySetID = cert.PolicySetID
	gwResp.PolicyVersion = cert.PolicyVersion
	if batchPolicyPartition != nil {
		mergeBatchExecutionPartition(batchPolicyPartition, gwResp.Result, sh)
		gwResp.Batch = batchPolicyPartition
	} else {
		s.attachBatchPartition(&gwResp, intent, req.ActionPayload, sh)
	}
	if gwResp.Counterexample == nil && (gwResp.Verdict == rta.VerdictDeny || gwResp.Verdict == rta.VerdictShield) {
		gwResp.Counterexample = &models.Counterexample{
			MinimalFacts: []string{"reason_code=" + gwResp.ReasonCode},
		}
	}

	// store idempotency decision only for terminal / stable verdicts
	if shouldPersistDecision(gwResp.Verdict) {
		s.storeDecision(r.Context(), tenant, decisionID, idempotencyKey, gwResp)
	}
	// audit append
	_ = s.Audit.Append(r.Context(), audit.Record{DecisionID: decisionID, IntentRaw: req.Intent, CertRaw: req.Cert, PolicyVersion: cert.PolicyVersion, Tenant: tenant, ActorIDHash: hashIdentity(intent.Actor.ID), Verdict: gwResp.Verdict, ReasonCode: gwResp.ReasonCode, Counterexample: marshalCounterexample(gwResp.Counterexample), CreatedAt: time.Now().UTC()})
	if isCriticalIncident(gwResp.Verdict, gwResp.ReasonCode) {
		s.raiseIncident(r.Context(), decisionID, "SECURITY_POLICY", gwResp.ReasonCode, gwResp.Verdict, intent, cert, gwResp.Counterexample)
	}
	s.Metrics.IncVerdict(gwResp.Verdict)
	s.Metrics.IncReason(gwResp.ReasonCode)
	s.Metrics.IncVerdictReason(gwResp.Verdict, gwResp.ReasonCode)
	if gwResp.Shield != nil {
		s.Metrics.IncShield(gwResp.Shield.Type)
	}

	httpx.WriteJSON(w, 200, gwResp)
}

func (s *Server) proxyVerify(w http.ResponseWriter, r *http.Request) {
	// proxy only
	url := s.VerifierURL + "/v1/verify"
	body, ok := readRequestBody(w, r)
	if !ok {
		return
	}
	headers := authHeaderMap(s.VerifierAuthHeader, s.VerifierAuthToken)
	status, respBody, err := httpx.RequestJSON(r.Context(), s.HTTPClient, http.MethodPost, url, body, headers, s.UpstreamRetries, s.UpstreamRetryDelay)
	if err != nil {
		httpx.Error(w, 502, "verifier unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

func (s *Server) listVerdicts(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	tenant, scoped := s.tenantScope(r.Context())
	var rows pgx.Rows
	var err error
	if scoped {
		rows, err = s.DB.Query(r.Context(), `SELECT decision_id, idempotency_key, verdict, reason_code, created_at FROM decisions WHERE tenant=$1 ORDER BY created_at DESC LIMIT $2`, tenant, limit)
	} else {
		rows, err = s.DB.Query(r.Context(), `SELECT decision_id, idempotency_key, verdict, reason_code, created_at FROM decisions ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "failed to list verdicts")
		return
	}
	defer rows.Close()
	items := make([]models.DecisionSummary, 0, limit)
	for rows.Next() {
		var item models.DecisionSummary
		if err := rows.Scan(&item.DecisionID, &item.IdempotencyKey, &item.Verdict, &item.ReasonCode, &item.CreatedAt); err == nil {
			items = append(items, item)
		}
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) exportComplianceData(w http.ResponseWriter, r *http.Request) {
	actorID := strings.TrimSpace(r.URL.Query().Get("actor_id"))
	if actorID == "" {
		httpx.Error(w, 400, "actor_id required")
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	type auditItem struct {
		DecisionID    string    `json:"decision_id"`
		PolicyVersion string    `json:"policy_version"`
		Verdict       string    `json:"verdict"`
		ReasonCode    string    `json:"reason_code"`
		CreatedAt     time.Time `json:"created_at"`
	}
	actorHash := hashIdentity(actorID)
	tenant, scoped := s.tenantScope(r.Context())
	var auditRows pgx.Rows
	var err error
	if scoped {
		auditRows, err = s.DB.Query(r.Context(), `
			SELECT decision_id, policy_version, verdict, reason_code, created_at
			FROM audit_records
			WHERE tenant=$1 AND (actor_id_hash=$2 OR intent_raw->'actor'->>'id' = $3)
			ORDER BY created_at DESC
			LIMIT $4
		`, tenant, actorHash, actorID, limit)
	} else {
		auditRows, err = s.DB.Query(r.Context(), `
			SELECT decision_id, policy_version, verdict, reason_code, created_at
			FROM audit_records
			WHERE actor_id_hash=$1 OR intent_raw->'actor'->>'id' = $2
			ORDER BY created_at DESC
			LIMIT $3
		`, actorHash, actorID, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "failed to query audit records")
		return
	}
	defer auditRows.Close()
	audits := make([]auditItem, 0, limit)
	for auditRows.Next() {
		var item auditItem
		if err := auditRows.Scan(&item.DecisionID, &item.PolicyVersion, &item.Verdict, &item.ReasonCode, &item.CreatedAt); err == nil {
			audits = append(audits, item)
		}
	}

	type escrowItem struct {
		EscrowID          string    `json:"escrow_id"`
		Status            string    `json:"status"`
		ApprovalsRequired int       `json:"approvals_required"`
		ApprovalsReceived int       `json:"approvals_received"`
		CreatedAt         time.Time `json:"created_at"`
	}
	var escrowRows pgx.Rows
	if scoped {
		escrowRows, err = s.DB.Query(r.Context(), `
			SELECT escrow_id, status, approvals_required, approvals_received, created_at
			FROM escrows
			WHERE tenant=$1 AND intent_raw->'actor'->>'id' = $2
			ORDER BY created_at DESC
			LIMIT $3
		`, tenant, actorID, limit)
	} else {
		escrowRows, err = s.DB.Query(r.Context(), `
			SELECT escrow_id, status, approvals_required, approvals_received, created_at
			FROM escrows
			WHERE intent_raw->'actor'->>'id' = $1
			ORDER BY created_at DESC
			LIMIT $2
		`, actorID, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "failed to query escrows")
		return
	}
	defer escrowRows.Close()
	escrows := make([]escrowItem, 0, limit)
	for escrowRows.Next() {
		var item escrowItem
		if err := escrowRows.Scan(&item.EscrowID, &item.Status, &item.ApprovalsRequired, &item.ApprovalsReceived, &item.CreatedAt); err == nil {
			escrows = append(escrows, item)
		}
	}

	type incidentItem struct {
		IncidentID string    `json:"incident_id"`
		Severity   string    `json:"severity"`
		Category   string    `json:"category"`
		ReasonCode string    `json:"reason_code"`
		Status     string    `json:"status"`
		CreatedAt  time.Time `json:"created_at"`
	}
	var incidentRows pgx.Rows
	if scoped {
		incidentRows, err = s.DB.Query(r.Context(), `
			SELECT incident_id, severity, category, reason_code, status, created_at
			FROM incidents
			WHERE tenant=$1 AND (
				details->>'actor_id_hash' = $2 OR
				details->>'actor_id' = $3
			)
			ORDER BY created_at DESC
			LIMIT $4
		`, tenant, actorHash, actorID, limit)
	} else {
		incidentRows, err = s.DB.Query(r.Context(), `
			SELECT incident_id, severity, category, reason_code, status, created_at
			FROM incidents
			WHERE details->>'actor_id_hash' = $1 OR details->>'actor_id' = $2
			ORDER BY created_at DESC
			LIMIT $3
		`, actorHash, actorID, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "failed to query incidents")
		return
	}
	defer incidentRows.Close()
	incidents := make([]incidentItem, 0, limit)
	for incidentRows.Next() {
		var item incidentItem
		if err := incidentRows.Scan(&item.IncidentID, &item.Severity, &item.Category, &item.ReasonCode, &item.Status, &item.CreatedAt); err == nil {
			incidents = append(incidents, item)
		}
	}

	type subjectRestrictionItem struct {
		Tenant      string     `json:"tenant"`
		ActorIDHash string     `json:"actor_id_hash"`
		Reason      string     `json:"reason"`
		CreatedBy   string     `json:"created_by"`
		CreatedAt   time.Time  `json:"created_at"`
		LiftedBy    string     `json:"lifted_by,omitempty"`
		LiftedAt    *time.Time `json:"lifted_at,omitempty"`
	}
	var restrictionRows pgx.Rows
	if scoped {
		restrictionRows, err = s.DB.Query(r.Context(), `
			SELECT tenant, actor_id_hash, reason, created_by, created_at, COALESCE(lifted_by, ''), lifted_at
			FROM subject_restrictions
			WHERE tenant=$1 AND actor_id_hash=$2
			ORDER BY created_at DESC
			LIMIT $3
		`, tenant, actorHash, limit)
	} else {
		restrictionRows, err = s.DB.Query(r.Context(), `
			SELECT tenant, actor_id_hash, reason, created_by, created_at, COALESCE(lifted_by, ''), lifted_at
			FROM subject_restrictions
			WHERE actor_id_hash=$1
			ORDER BY created_at DESC
			LIMIT $2
		`, actorHash, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "failed to query subject restrictions")
		return
	}
	defer restrictionRows.Close()
	restrictions := make([]subjectRestrictionItem, 0, limit)
	for restrictionRows.Next() {
		var item subjectRestrictionItem
		if err := restrictionRows.Scan(&item.Tenant, &item.ActorIDHash, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.LiftedBy, &item.LiftedAt); err == nil {
			restrictions = append(restrictions, item)
		}
	}
	activeRestrictions := 0
	for _, item := range restrictions {
		if item.LiftedAt == nil {
			activeRestrictions++
		}
	}

	httpx.WriteJSON(w, 200, map[string]interface{}{
		"actor_id":             actorID,
		"actor_hash":           hashIdentity(actorID),
		"generated_at":         time.Now().UTC().Format(time.RFC3339),
		"audit_records":        audits,
		"escrows":              escrows,
		"incidents":            incidents,
		"subject_restrictions": restrictions,
		"record_counts": map[string]int{
			"audit_records":               len(audits),
			"escrows":                     len(escrows),
			"incidents":                   len(incidents),
			"subject_restrictions":        len(restrictions),
			"active_subject_restrictions": activeRestrictions,
		},
		"retention_days": s.RetentionDays,
	})
}

func (s *Server) proxyBeliefState(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		httpx.Error(w, 400, "domain required")
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	params := url.Values{}
	params.Set("domain", domain)
	if scoped {
		params.Set("tenant", tenant)
	} else if requestedTenant := strings.TrimSpace(r.URL.Query().Get("tenant")); requestedTenant != "" {
		params.Set("tenant", requestedTenant)
	}
	status, body, err := httpx.RequestJSON(
		r.Context(),
		s.HTTPClient,
		http.MethodGet,
		s.StateURL+"/v1/beliefstate?"+params.Encode(),
		nil,
		authHeaderMap(s.StateAuthHeader, s.StateAuthToken),
		s.UpstreamRetries,
		s.UpstreamRetryDelay,
	)
	if err != nil {
		httpx.Error(w, 502, "state unavailable")
		return
	}
	if status == http.StatusNotFound {
		httpx.WriteJSON(w, 200, models.BeliefState{
			Tenant:    params.Get("tenant"),
			Domain:    domain,
			Sources:   []models.SourceState{},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}
	if status != http.StatusOK {
		httpx.Error(w, 502, "state unavailable")
		return
	}
	var state models.BeliefState
	if err := json.Unmarshal(body, &state); err != nil {
		httpx.Error(w, 502, "invalid state response")
		return
	}
	httpx.WriteJSON(w, 200, state)
}

func (s *Server) listSubjectRestrictions(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	actorID := strings.TrimSpace(r.URL.Query().Get("actor_id"))
	actorHash := ""
	if actorID != "" {
		actorHash = hashIdentity(actorID)
	}
	tenant, scoped := s.tenantScope(r.Context())
	query := `
		SELECT tenant, actor_id_hash, reason, created_by, created_at, COALESCE(lifted_by, ''), lifted_at
		FROM subject_restrictions
		WHERE lifted_at IS NULL
	`
	var (
		rows pgx.Rows
		err  error
	)
	switch {
	case scoped && actorHash != "":
		rows, err = s.DB.Query(r.Context(), query+` AND tenant=$1 AND actor_id_hash=$2 ORDER BY created_at DESC LIMIT $3`, tenant, actorHash, limit)
	case scoped:
		rows, err = s.DB.Query(r.Context(), query+` AND tenant=$1 ORDER BY created_at DESC LIMIT $2`, tenant, limit)
	case actorHash != "":
		rows, err = s.DB.Query(r.Context(), query+` AND actor_id_hash=$1 ORDER BY created_at DESC LIMIT $2`, actorHash, limit)
	default:
		rows, err = s.DB.Query(r.Context(), query+` ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "failed to list subject restrictions")
		return
	}
	defer rows.Close()
	items := make([]models.SubjectRestriction, 0, limit)
	for rows.Next() {
		var item models.SubjectRestriction
		if err := rows.Scan(&item.Tenant, &item.ActorIDHash, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.LiftedBy, &item.LiftedAt); err == nil {
			items = append(items, item)
		}
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) restrictSubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ActorID     string `json:"actor_id"`
		Reason      string `json:"reason"`
		RequestedBy string `json:"requested_by"`
		Tenant      string `json:"tenant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	req.ActorID = strings.TrimSpace(req.ActorID)
	if req.ActorID == "" {
		httpx.Error(w, 400, "actor_id required")
		return
	}
	requestedBy, ok := s.resolveComplianceActor(w, r, req.RequestedBy)
	if !ok {
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	targetTenant := tenant
	if !scoped {
		targetTenant = strings.TrimSpace(req.Tenant)
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "manual restriction"
	}
	actorHash := hashIdentity(req.ActorID)
	cmd, err := s.DB.Exec(r.Context(), `
		INSERT INTO subject_restrictions(tenant, actor_id_hash, reason, created_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant, actor_id_hash) DO UPDATE
		SET reason=EXCLUDED.reason, created_by=EXCLUDED.created_by, created_at=now(), lifted_by=NULL, lifted_at=NULL
	`, targetTenant, actorHash, reason, requestedBy)
	if err != nil || cmd.RowsAffected() == 0 {
		httpx.Error(w, 500, "failed to restrict subject")
		return
	}
	row := s.DB.QueryRow(r.Context(), `
		SELECT tenant, actor_id_hash, reason, created_by, created_at, COALESCE(lifted_by, ''), lifted_at
		FROM subject_restrictions
		WHERE tenant=$1 AND actor_id_hash=$2
	`, targetTenant, actorHash)
	var item models.SubjectRestriction
	if err := row.Scan(&item.Tenant, &item.ActorIDHash, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.LiftedBy, &item.LiftedAt); err != nil {
		httpx.Error(w, 500, "failed to load subject restriction")
		return
	}
	s.publishRefresh()
	httpx.WriteJSON(w, 200, item)
}

func (s *Server) unrestrictSubject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ActorID     string `json:"actor_id"`
		RequestedBy string `json:"requested_by"`
		Tenant      string `json:"tenant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	req.ActorID = strings.TrimSpace(req.ActorID)
	if req.ActorID == "" {
		httpx.Error(w, 400, "actor_id required")
		return
	}
	requestedBy, ok := s.resolveComplianceActor(w, r, req.RequestedBy)
	if !ok {
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	targetTenant := tenant
	if !scoped {
		targetTenant = strings.TrimSpace(req.Tenant)
	}
	actorHash := hashIdentity(req.ActorID)
	cmd, err := s.DB.Exec(r.Context(), `
		UPDATE subject_restrictions
		SET lifted_by=$3, lifted_at=now()
		WHERE tenant=$1 AND actor_id_hash=$2 AND lifted_at IS NULL
	`, targetTenant, actorHash, requestedBy)
	if err != nil {
		httpx.Error(w, 500, "failed to unrestrict subject")
		return
	}
	if cmd.RowsAffected() == 0 {
		httpx.Error(w, 404, "active restriction not found")
		return
	}
	row := s.DB.QueryRow(r.Context(), `
		SELECT tenant, actor_id_hash, reason, created_by, created_at, COALESCE(lifted_by, ''), lifted_at
		FROM subject_restrictions
		WHERE tenant=$1 AND actor_id_hash=$2
	`, targetTenant, actorHash)
	var item models.SubjectRestriction
	if err := row.Scan(&item.Tenant, &item.ActorIDHash, &item.Reason, &item.CreatedBy, &item.CreatedAt, &item.LiftedBy, &item.LiftedAt); err != nil {
		httpx.Error(w, 500, "failed to load subject restriction")
		return
	}
	s.publishRefresh()
	httpx.WriteJSON(w, 200, item)
}

func (s *Server) runRetentionNow(w http.ResponseWriter, r *http.Request) {
	report, err := s.applyRetention(r.Context())
	if err != nil {
		httpx.Error(w, 500, "retention failed")
		return
	}
	httpx.WriteJSON(w, 200, report)
}

func (s *Server) getAudit(w http.ResponseWriter, r *http.Request) {
	decisionID := chi.URLParam(r, "decision_id")
	tenant, _ := s.tenantScope(r.Context())
	rec, err := s.Audit.Get(r.Context(), decisionID, tenant)
	if err != nil {
		httpx.Error(w, 404, "not found")
		return
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{
		"intent":         json.RawMessage(rec.IntentRaw),
		"cert":           json.RawMessage(rec.CertRaw),
		"policy_version": rec.PolicyVersion,
		"decision":       map[string]string{"verdict": rec.Verdict, "reason_code": rec.ReasonCode},
		"counterexample": json.RawMessage(rec.Counterexample),
	})
}

func (s *Server) replayAudit(w http.ResponseWriter, r *http.Request) {
	decisionID := chi.URLParam(r, "decision_id")
	tenant, _ := s.tenantScope(r.Context())
	rec, err := s.Audit.Get(r.Context(), decisionID, tenant)
	if err != nil {
		httpx.Error(w, 404, "not found")
		return
	}
	var cert models.ActionCert
	if err := json.Unmarshal(rec.CertRaw, &cert); err != nil {
		httpx.Error(w, 500, "invalid stored cert")
		return
	}
	replayBelief := models.BeliefState{}
	if len(cert.Evidence.StateSnapshotRefs) > 0 && cert.Evidence.StateSnapshotRefs[0].SnapshotID != "" {
		replayBelief.SnapshotID = cert.Evidence.StateSnapshotRefs[0].SnapshotID
	}
	vr, degraded := s.callVerifier(r.Context(), rec.IntentRaw, rec.CertRaw, replayBelief, true)
	if degraded || vr == nil {
		httpx.WriteJSON(w, 200, map[string]interface{}{
			"original": map[string]string{"verdict": rec.Verdict, "reason_code": rec.ReasonCode},
			"replay":   map[string]string{"verdict": rta.VerdictDefer, "reason_code": "REPLAY_UNAVAILABLE"},
			"drift":    true,
		})
		return
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{
		"original": map[string]string{"verdict": rec.Verdict, "reason_code": rec.ReasonCode},
		"replay":   map[string]interface{}{"verdict": vr.Verdict, "reason_code": vr.ReasonCode, "counterexample": vr.Counterexample},
		"drift":    rec.Verdict != vr.Verdict || rec.ReasonCode != vr.ReasonCode,
	})
}

func (s *Server) retentionLoop(ctx context.Context) {
	interval := s.RetentionInterval
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, err := s.applyRetention(ctx)
			if err != nil {
				log.Printf("retention run failed: %v", err)
				continue
			}
			log.Printf("retention run completed: %+v", report)
		}
	}
}

func (s *Server) metricsLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	s.updateOperationalMetrics(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.updateOperationalMetrics(ctx)
		}
	}
}

func (s *Server) updateOperationalMetrics(ctx context.Context) {
	if s.DB == nil || s.Metrics == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var escrowPending int
	_ = s.DB.QueryRow(ctx, `SELECT COUNT(*) FROM escrows WHERE status=$1 OR status=$2`, escrowfsm.Pending, escrowfsm.Approved).Scan(&escrowPending)
	s.Metrics.SetGauge("escrow_pending", float64(escrowPending))
	var escrowOldest float64
	_ = s.DB.QueryRow(ctx, `
		SELECT COALESCE(MAX(EXTRACT(EPOCH FROM (now() - created_at))), 0)
		FROM escrows WHERE status=$1 OR status=$2
	`, escrowfsm.Pending, escrowfsm.Approved).Scan(&escrowOldest)
	s.Metrics.SetGauge("escrow_pending_oldest_seconds", escrowOldest)
	var policyPending int
	var policyOldest float64
	_ = s.DB.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(MAX(EXTRACT(EPOCH FROM (now() - created_at))), 0)
		FROM policy_versions WHERE status='PENDING_APPROVAL'
	`).Scan(&policyPending, &policyOldest)
	s.Metrics.SetGauge("policy_pending_count", float64(policyPending))
	s.Metrics.SetGauge("policy_pending_oldest_seconds", policyOldest)
	var incidentsUnack int
	_ = s.DB.QueryRow(ctx, `
		SELECT COUNT(*) FROM incidents
		WHERE status='OPEN' AND acknowledged_by IS NULL AND severity IN ('CRITICAL','HIGH')
	`).Scan(&incidentsUnack)
	s.Metrics.SetGauge("incidents_unack_critical", float64(incidentsUnack))
}

func (s *Server) applyRetention(ctx context.Context) (map[string]interface{}, error) {
	days := s.RetentionDays
	if days <= 0 {
		days = 90
	}
	cutoff := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	report := map[string]interface{}{
		"cutoff":           cutoff.Format(time.RFC3339),
		"days":             days,
		"tables":           map[string]int64{},
		"immutable_tables": []string{"audit_records"},
	}
	tables := report["tables"].(map[string]int64)

	cmd, err := s.DB.Exec(ctx, `DELETE FROM decisions WHERE created_at < $1`, cutoff)
	if err != nil {
		return nil, err
	}
	tables["decisions"] = cmd.RowsAffected()

	cmd, err = s.DB.Exec(ctx, `DELETE FROM escrows WHERE created_at < $1`, cutoff)
	if err != nil {
		return nil, err
	}
	tables["escrows"] = cmd.RowsAffected()

	cmd, err = s.DB.Exec(ctx, `DELETE FROM incidents WHERE created_at < $1`, cutoff)
	if err != nil {
		return nil, err
	}
	tables["incidents"] = cmd.RowsAffected()

	// audit_records is immutable by migration trigger and intentionally excluded from retention deletes.
	tables["audit_records"] = 0

	cmd, err = s.DB.Exec(ctx, `DELETE FROM belief_snapshots WHERE created_at < $1`, cutoff)
	if err != nil {
		return nil, err
	}
	tables["belief_snapshots"] = cmd.RowsAffected()
	return report, nil
}

func (s *Server) fetchSnapshot(ctx context.Context, tenant, domain string) (models.BeliefState, bool) {
	url := s.StateURL + "/v1/state/snapshot"
	payload, _ := json.Marshal(map[string]string{"domain": domain, "tenant": tenant})
	status, body, err := httpx.RequestJSON(ctx, s.HTTPClient, http.MethodPost, url, payload, authHeaderMap(s.StateAuthHeader, s.StateAuthToken), s.UpstreamRetries, s.UpstreamRetryDelay)
	if err != nil {
		return models.BeliefState{}, true
	}
	if status != 201 {
		return models.BeliefState{}, true
	}
	var bs models.BeliefState
	if err := json.Unmarshal(body, &bs); err != nil {
		return models.BeliefState{}, true
	}
	return bs, false
}

func isStateFresh(bs models.BeliefState, maxStaleness int, required []string) bool {
	if len(required) > 0 {
		have := map[string]bool{}
		for _, s := range bs.Sources {
			have[s.Source] = true
		}
		for _, r := range required {
			if !have[r] {
				return false
			}
		}
	}
	if maxStaleness <= 0 {
		if len(bs.Sources) == 0 {
			return false
		}
		for _, s := range bs.Sources {
			if s.AgeSec > 0 {
				return false
			}
		}
		return true
	}
	for _, s := range bs.Sources {
		if s.AgeSec > maxStaleness {
			return false
		}
	}
	return true
}

func parseIntentTime(raw string, fallback time.Time) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fallback
	}
	return parsed.UTC()
}

func shouldExpireDefer(maxDefer time.Duration, requestTime, now time.Time) bool {
	if maxDefer <= 0 {
		return false
	}
	if requestTime.IsZero() {
		return false
	}
	if now.Before(requestTime) {
		return false
	}
	return now.Sub(requestTime) >= maxDefer
}

func hasRollbackPlan(cert models.ActionCert) bool {
	planType := strings.ToUpper(strings.TrimSpace(cert.RollbackPlan.Type))
	if planType == "" {
		return false
	}
	if planType == "NONE" || planType == "NOOP" {
		return false
	}
	return len(cert.RollbackPlan.Steps) > 0
}

func (s *Server) callVerifier(ctx context.Context, intentRaw, certRaw json.RawMessage, belief models.BeliefState, replay bool) (*models.VerifierResponse, bool) {
	payload := map[string]interface{}{"intent": json.RawMessage(intentRaw), "cert": json.RawMessage(certRaw)}
	if belief.SnapshotID != "" {
		payload["snapshot_id"] = belief.SnapshotID
	} else {
		payload["belief_state_snapshot"] = belief
	}
	if replay {
		payload["replay"] = true
	}
	body, _ := json.Marshal(payload)
	ctxTimeout, cancel := context.WithTimeout(ctx, s.Config.MaxVerifyTime)
	defer cancel()
	status, respBody, err := httpx.RequestJSON(ctxTimeout, s.HTTPClient, http.MethodPost, s.VerifierURL+"/v1/verify", body, authHeaderMap(s.VerifierAuthHeader, s.VerifierAuthToken), s.UpstreamRetries, s.UpstreamRetryDelay)
	if err != nil {
		return nil, true
	}
	if status != 200 {
		return nil, true
	}
	var vr models.VerifierResponse
	if err := json.Unmarshal(respBody, &vr); err != nil {
		return nil, true
	}
	return &vr, false
}

func (s *Server) executeUpstream(ctx context.Context, actionType string, toolPayload, actionPayload json.RawMessage) (json.RawMessage, error) {
	var payload json.RawMessage
	var exec palantir.Executor
	switch actionType {
	case "TOOL_CALL":
		payload = toolPayload
		exec = s.ToolExecutor
	case "ONTOLOGY_ACTION":
		payload = actionPayload
		exec = s.OntologyExecutor
	default:
		return nil, errors.New("unknown action type")
	}
	if exec == nil {
		return nil, errors.New("missing upstream adapter")
	}
	return exec.Execute(ctx, payload)
}

func (s *Server) executeShieldMode(ctx context.Context, actionType string, mode string, toolPayload, actionPayload json.RawMessage) (json.RawMessage, error) {
	wrapper := map[string]interface{}{
		"mode": mode,
	}
	switch actionType {
	case "TOOL_CALL":
		var raw interface{}
		_ = json.Unmarshal(toolPayload, &raw)
		wrapper["payload"] = raw
	case "ONTOLOGY_ACTION":
		var raw interface{}
		_ = json.Unmarshal(actionPayload, &raw)
		wrapper["payload"] = raw
	}
	if s.StrictShieldNoCommit && (mode == shield.ShieldReadOnly || mode == shield.ShieldDryRun) {
		report := map[string]interface{}{
			"mode":            mode,
			"action_type":     actionType,
			"upstream_called": false,
			"commit_blocked":  true,
			"payload":         wrapper["payload"],
			"report":          "shield enforced locally to prevent side effects",
		}
		body, _ := json.Marshal(report)
		return body, nil
	}
	body, _ := json.Marshal(wrapper)
	return s.executeUpstream(ctx, actionType, body, body)
}

func (s *Server) executeSmallBatch(ctx context.Context, actionType string, actionPayload json.RawMessage, max int) (json.RawMessage, error) {
	if actionType != "ONTOLOGY_ACTION" {
		return nil, errors.New("small batch only supported for ontology actions")
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(actionPayload, &payload); err != nil {
		return nil, err
	}
	idsRaw, ok := payload["ids"].([]interface{})
	if !ok || len(idsRaw) == 0 {
		return nil, errors.New("no ids for small batch")
	}
	chunkSize := 100
	if max > 0 {
		chunkSize = max
	}
	var (
		results  []interface{}
		allowIDs []string
		denyIDs  []string
	)
	for i := 0; i < len(idsRaw); i += chunkSize {
		end := i + chunkSize
		if end > len(idsRaw) {
			end = len(idsRaw)
		}
		chunk := idsRaw[i:end]
		payload["ids"] = chunk
		body, _ := json.Marshal(payload)
		res, err := s.executeUpstream(ctx, actionType, body, body)
		if err != nil {
			chunkIDs := asStringSlice(chunk)
			denyIDs = append(denyIDs, chunkIDs...)
			results = append(results, map[string]interface{}{
				"ids":    chunkIDs,
				"status": "error",
				"error":  err.Error(),
			})
			continue
		}
		var parsed interface{}
		_ = json.Unmarshal(res, &parsed)
		chunkIDs := asStringSlice(chunk)
		allowIDs = append(allowIDs, chunkIDs...)
		results = append(results, map[string]interface{}{
			"ids":      chunkIDs,
			"status":   "ok",
			"response": parsed,
		})
	}
	out, _ := json.Marshal(map[string]interface{}{
		"chunks":    results,
		"allow_ids": allowIDs,
		"deny_ids":  denyIDs,
	})
	return out, nil
}

func tightenBatchVerdict(verdict string, sh *models.SuggestedShield, reason string, partition *models.BatchPartition) (string, *models.SuggestedShield, string) {
	if partition == nil || partition.Total == 0 {
		return verdict, sh, reason
	}
	if verdict == rta.VerdictDeny || verdict == rta.VerdictDefer {
		return verdict, sh, reason
	}
	if len(partition.EscrowIDs) == 0 && len(partition.DenyIDs) == 0 && len(partition.DeferIDs) == 0 {
		return verdict, sh, reason
	}
	if len(partition.AllowIDs) > 0 {
		return rta.VerdictShield, shield.Suggested(shield.ShieldSmallBatch, shield.DefaultParams(shield.ShieldSmallBatch)), "BATCH_POLICY_PARTIAL"
	}
	if len(partition.EscrowIDs) > 0 {
		return rta.VerdictEscrow, shield.Suggested(shield.ShieldRequireApproval, shield.DefaultParams(shield.ShieldRequireApproval)), "BATCH_POLICY_ESCROW"
	}
	if len(partition.DeferIDs) > 0 {
		return rta.VerdictDefer, sh, "BATCH_POLICY_DEFER"
	}
	return rta.VerdictDeny, nil, "BATCH_POLICY_DENY"
}

func (s *Server) evaluateBatchPolicyPartition(policy *policyir.PolicySetIR, intent models.ActionIntent, belief models.BeliefState, actionPayload json.RawMessage) *models.BatchPartition {
	if policy == nil || !strings.EqualFold(strings.TrimSpace(intent.Target.Scope), "batch") {
		return nil
	}
	ids := collectBatchIDs(intent, actionPayload)
	if len(ids) == 0 {
		return nil
	}
	evalPolicy := clonePolicyWithInvariants(policy)
	partition := &models.BatchPartition{
		Scope: "batch",
		Total: len(ids),
		Items: make([]models.BatchItemVerdict, 0, len(ids)),
	}
	for _, id := range ids {
		itemIntent := intent
		itemIntent.Target.Scope = "single"
		itemIntent.Target.ObjectIDs = []string{id}
		failure := smt.EvalPolicy(evalPolicy, smt.BuildContext(itemIntent, belief))
		if failure == nil {
			partition.AllowIDs = append(partition.AllowIDs, id)
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictAllow, ReasonCode: "OK"})
			continue
		}
		reason := strings.TrimSpace(failure.Axiom.ID)
		if reason == "" {
			reason = "AXIOM_FAIL"
		}
		sh := policyeval.ShieldFromAxiom(failure.Axiom)
		if sh != nil && sh.Type == shield.ShieldRequireApproval {
			partition.EscrowIDs = append(partition.EscrowIDs, id)
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictEscrow, ReasonCode: reason})
			continue
		}
		partition.DenyIDs = append(partition.DenyIDs, id)
		partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictDeny, ReasonCode: reason})
	}
	return partition
}

func clonePolicyWithInvariants(policy *policyir.PolicySetIR) *policyir.PolicySetIR {
	if policy == nil {
		return nil
	}
	clone := *policy
	clone.Axioms = append([]policyir.Axiom{}, policy.Axioms...)
	for i, inv := range policy.Invariants {
		id := fmt.Sprintf("Invariant#%d", i+1)
		clone.Axioms = append(clone.Axioms, policyir.Axiom{ID: id, Requires: []string{inv}})
	}
	return &clone
}

func filterBatchActionPayloadByIDs(actionPayload json.RawMessage, ids []string) (json.RawMessage, bool) {
	if len(actionPayload) == 0 || len(ids) == 0 {
		return nil, false
	}
	allowSet := toStringSet(ids)
	var payload map[string]interface{}
	if err := json.Unmarshal(actionPayload, &payload); err != nil {
		return nil, false
	}
	rawIDs, ok := payload["ids"].([]interface{})
	if !ok {
		return nil, false
	}
	filtered := make([]string, 0, len(rawIDs))
	for _, item := range rawIDs {
		id, ok := item.(string)
		if !ok {
			continue
		}
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, allowed := allowSet[id]; allowed {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		return nil, false
	}
	payload["ids"] = filtered
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}
	return out, true
}

func mergeBatchExecutionPartition(partition *models.BatchPartition, result json.RawMessage, sh *models.SuggestedShield) {
	if partition == nil || sh == nil || sh.Type != shield.ShieldSmallBatch {
		return
	}
	allow, deny := extractSmallBatchIDs(result)
	if len(allow) == 0 && len(deny) == 0 {
		return
	}
	allowSet := toStringSet(partition.AllowIDs)
	denySet := toStringSet(partition.DenyIDs)
	escrowSet := toStringSet(partition.EscrowIDs)
	deferSet := toStringSet(partition.DeferIDs)
	for _, id := range deny {
		if _, escrow := escrowSet[id]; escrow {
			continue
		}
		if _, deferred := deferSet[id]; deferred {
			continue
		}
		delete(allowSet, id)
		denySet[id] = struct{}{}
	}
	for _, id := range allow {
		if _, denied := denySet[id]; denied {
			continue
		}
		if _, escrow := escrowSet[id]; escrow {
			continue
		}
		if _, deferred := deferSet[id]; deferred {
			continue
		}
		allowSet[id] = struct{}{}
	}
	partition.AllowIDs = make([]string, 0, len(allowSet))
	for id := range allowSet {
		partition.AllowIDs = append(partition.AllowIDs, id)
	}
	partition.DenyIDs = make([]string, 0, len(denySet))
	for id := range denySet {
		partition.DenyIDs = append(partition.DenyIDs, id)
	}
	order := make([]string, 0, len(partition.Items))
	for _, item := range partition.Items {
		if strings.TrimSpace(item.ObjectID) != "" {
			order = append(order, item.ObjectID)
		}
	}
	if len(order) == 0 {
		order = append(order, partition.AllowIDs...)
		order = append(order, partition.EscrowIDs...)
		order = append(order, partition.DenyIDs...)
		order = append(order, partition.DeferIDs...)
	}
	partition.Items = make([]models.BatchItemVerdict, 0, len(order))
	for _, id := range order {
		switch {
		case containsString(partition.EscrowIDs, id):
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictEscrow, ReasonCode: "REQUIRE_APPROVAL"})
		case containsString(partition.DeferIDs, id):
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictDefer, ReasonCode: "STATE_UNKNOWN"})
		case containsString(partition.DenyIDs, id):
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictDeny, ReasonCode: "SMALL_BATCH_CHUNK_FAIL"})
		case containsString(partition.AllowIDs, id):
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictAllow, ReasonCode: "SMALL_BATCH_CHUNK_OK"})
		default:
			partition.Items = append(partition.Items, models.BatchItemVerdict{ObjectID: id, Verdict: rta.VerdictDeny, ReasonCode: "BATCH_POLICY_DENY"})
		}
	}
}

func asStringSlice(items []interface{}) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func toStringSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	return out
}

func containsString(items []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item) == target {
			return true
		}
	}
	return false
}

func collectBatchIDs(intent models.ActionIntent, actionPayload json.RawMessage) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(intent.Target.ObjectIDs))
	for _, id := range intent.Target.ObjectIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(actionPayload) == 0 {
		return out
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(actionPayload, &payload); err != nil {
		return out
	}
	rawIDs, ok := payload["ids"].([]interface{})
	if !ok {
		return out
	}
	for _, item := range rawIDs {
		id, ok := item.(string)
		if !ok {
			continue
		}
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func validateBatchPayloadIntegrity(intent models.ActionIntent, actionPayload json.RawMessage) (string, *models.Counterexample) {
	if !strings.EqualFold(strings.TrimSpace(intent.Target.Scope), "batch") {
		return "", nil
	}
	intentIDs := normalizeIDs(intent.Target.ObjectIDs)
	payloadIDs, hasPayloadIDs, err := parseBatchPayloadIDs(actionPayload)
	if err != nil {
		return "BATCH_IDS_INVALID", &models.Counterexample{
			MinimalFacts: []string{
				"scope=batch",
				"payload.ids.invalid",
			},
			FailedAxioms: []string{"Batch_payload_integrity"},
		}
	}
	if len(intentIDs) == 0 && !hasPayloadIDs {
		return "BATCH_IDS_MISSING", &models.Counterexample{
			MinimalFacts: []string{
				"scope=batch",
				"intent.object_ids=0",
				"payload.ids=absent",
			},
			FailedAxioms: []string{"Batch_payload_integrity"},
		}
	}
	if !hasPayloadIDs {
		return "", nil
	}
	if len(intentIDs) == 0 {
		return "BATCH_IDS_MISMATCH", &models.Counterexample{
			MinimalFacts: []string{
				"intent.object_ids=0",
				fmt.Sprintf("payload.ids=%d", len(payloadIDs)),
			},
			FailedAxioms: []string{"Batch_payload_integrity"},
		}
	}
	if !equalIDSets(intentIDs, payloadIDs) {
		return "BATCH_IDS_MISMATCH", &models.Counterexample{
			MinimalFacts: []string{
				fmt.Sprintf("intent.object_ids=%d", len(intentIDs)),
				fmt.Sprintf("payload.ids=%d", len(payloadIDs)),
			},
			FailedAxioms: []string{"Batch_payload_integrity"},
		}
	}
	return "", nil
}

func parseBatchPayloadIDs(actionPayload json.RawMessage) ([]string, bool, error) {
	if len(actionPayload) == 0 {
		return nil, false, nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(actionPayload, &payload); err != nil {
		return nil, false, err
	}
	raw, exists := payload["ids"]
	if !exists {
		return nil, false, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, true, errors.New("ids must be array")
	}
	ids := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		id, ok := item.(string)
		if !ok {
			return nil, true, errors.New("ids must contain strings")
		}
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, found := seen[id]; found {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, true, errors.New("ids must not be empty")
	}
	return ids, true, nil
}

func normalizeIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func equalIDSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, item := range a {
		set[item] = struct{}{}
	}
	for _, item := range b {
		if _, ok := set[item]; !ok {
			return false
		}
	}
	return true
}

func (s *Server) attachBatchPartition(resp *models.GatewayResponse, intent models.ActionIntent, actionPayload json.RawMessage, sh *models.SuggestedShield) {
	if resp == nil || !strings.EqualFold(strings.TrimSpace(intent.Target.Scope), "batch") {
		return
	}
	ids := collectBatchIDs(intent, actionPayload)
	if len(ids) == 0 {
		return
	}
	partition := &models.BatchPartition{
		Scope: "batch",
		Total: len(ids),
		Items: make([]models.BatchItemVerdict, 0, len(ids)),
	}
	setAll := func(v, reason string) {
		for _, id := range ids {
			partition.Items = append(partition.Items, models.BatchItemVerdict{
				ObjectID:   id,
				Verdict:    v,
				ReasonCode: reason,
			})
		}
	}
	switch resp.Verdict {
	case rta.VerdictAllow:
		partition.AllowIDs = append(partition.AllowIDs, ids...)
		setAll(rta.VerdictAllow, resp.ReasonCode)
	case rta.VerdictEscrow:
		partition.EscrowIDs = append(partition.EscrowIDs, ids...)
		setAll(rta.VerdictEscrow, resp.ReasonCode)
	case rta.VerdictDefer:
		partition.DeferIDs = append(partition.DeferIDs, ids...)
		setAll(rta.VerdictDefer, resp.ReasonCode)
	case rta.VerdictShield:
		if sh != nil && sh.Type == shield.ShieldRequireApproval {
			partition.EscrowIDs = append(partition.EscrowIDs, ids...)
			setAll(rta.VerdictEscrow, resp.ReasonCode)
		} else if sh != nil && sh.Type == shield.ShieldSmallBatch {
			allow, deny := extractSmallBatchIDs(resp.Result)
			if len(allow) == 0 && len(deny) == 0 {
				partition.DenyIDs = append(partition.DenyIDs, ids...)
				setAll(rta.VerdictDeny, resp.ReasonCode)
				break
			}
			partition.AllowIDs = append(partition.AllowIDs, allow...)
			partition.DenyIDs = append(partition.DenyIDs, deny...)
			for _, id := range allow {
				partition.Items = append(partition.Items, models.BatchItemVerdict{
					ObjectID:   id,
					Verdict:    rta.VerdictAllow,
					ReasonCode: "SMALL_BATCH_CHUNK_OK",
				})
			}
			for _, id := range deny {
				partition.Items = append(partition.Items, models.BatchItemVerdict{
					ObjectID:   id,
					Verdict:    rta.VerdictDeny,
					ReasonCode: "SMALL_BATCH_CHUNK_FAIL",
				})
			}
		} else {
			partition.DenyIDs = append(partition.DenyIDs, ids...)
			setAll(rta.VerdictDeny, resp.ReasonCode)
		}
	default:
		partition.DenyIDs = append(partition.DenyIDs, ids...)
		setAll(rta.VerdictDeny, resp.ReasonCode)
	}
	resp.Batch = partition
}

func extractSmallBatchIDs(result json.RawMessage) ([]string, []string) {
	if len(result) == 0 {
		return nil, nil
	}
	var parsed struct {
		AllowIDs []string `json:"allow_ids"`
		DenyIDs  []string `json:"deny_ids"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, nil
	}
	return parsed.AllowIDs, parsed.DenyIDs
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

func buildExternalKeyStore(
	client *http.Client,
	provider,
	vaultAddr,
	vaultToken,
	vaultNamespace,
	vaultTransit,
	vaultKeyPrefix string,
	vaultTimeout time.Duration,
	vaultRetries int,
	vaultRetryDelay time.Duration,
) (auth.KeyStore, error) {
	mode := strings.ToLower(strings.TrimSpace(provider))
	switch mode {
	case "", "db":
		return nil, nil
	case "vault_transit":
		if strings.TrimSpace(vaultAddr) == "" {
			return nil, errors.New("KEYSTORE_PROVIDER=vault_transit requires VAULT_ADDR")
		}
		if strings.TrimSpace(vaultToken) == "" {
			return nil, errors.New("KEYSTORE_PROVIDER=vault_transit requires VAULT_TOKEN")
		}
		return auth.VaultTransitKeyStore{
			Client:     client,
			Addr:       vaultAddr,
			Token:      vaultToken,
			Namespace:  vaultNamespace,
			Transit:    vaultTransit,
			KeyPrefix:  vaultKeyPrefix,
			Timeout:    vaultTimeout,
			MaxRetries: vaultRetries,
			RetryDelay: vaultRetryDelay,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported KEYSTORE_PROVIDER %q", provider)
	}
}

func (s *Server) lookupKey(ctx context.Context, kid string) (ed25519.PublicKey, string, error) {
	if strings.TrimSpace(kid) == "" {
		return nil, "", errors.New("kid required")
	}
	row := s.DB.QueryRow(ctx, `SELECT public_key, status FROM key_registry WHERE kid=$1`, kid)
	var pk []byte
	var status string
	if err := row.Scan(&pk, &status); err != nil {
		if s.ExternalKeyStore == nil {
			return nil, "", err
		}
		return s.lookupExternalKey(ctx, kid)
	}
	if len(pk) == 0 && s.ExternalKeyStore != nil {
		return s.lookupExternalKey(ctx, kid)
	}
	if len(pk) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid ed25519 public key size: %d", len(pk))
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "active"
	}
	return ed25519.PublicKey(pk), status, nil
}

func (s *Server) lookupExternalKey(ctx context.Context, kid string) (ed25519.PublicKey, string, error) {
	rec, err := s.ExternalKeyStore.GetKey(ctx, kid)
	if err != nil {
		return nil, "", err
	}
	if rec == nil {
		return nil, "", errors.New("external key store returned empty record")
	}
	if len(rec.PublicKey) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid external ed25519 public key size: %d", len(rec.PublicKey))
	}
	status := strings.ToLower(strings.TrimSpace(rec.Status))
	if status == "" {
		status = "active"
	}
	return ed25519.PublicKey(rec.PublicKey), status, nil
}

func (s *Server) storeDecision(ctx context.Context, tenant, decisionID, idempotencyKey string, resp models.GatewayResponse) {
	payload, _ := json.Marshal(resp)
	cmd, _ := s.DB.Exec(ctx, `
		INSERT INTO decisions(decision_id, tenant, idempotency_key, verdict, reason_code, response_json)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (tenant, idempotency_key) DO NOTHING
	`, decisionID, tenant, idempotencyKey, resp.Verdict, resp.ReasonCode, payload)
	_ = s.Cache.Set(ctx, decisionCacheKey(tenant, idempotencyKey), string(payload), time.Hour)
	if cmd.RowsAffected() > 0 {
		s.publishRefresh()
	}
}

func (s *Server) checkIdempotency(ctx context.Context, tenant, key string) (models.GatewayResponse, bool) {
	if key == "" {
		return models.GatewayResponse{}, false
	}
	if val, err := s.Cache.Get(ctx, decisionCacheKey(tenant, key)); err == nil && val != "" {
		var resp models.GatewayResponse
		if json.Unmarshal([]byte(val), &resp) == nil {
			if !shouldPersistDecision(resp.Verdict) {
				return models.GatewayResponse{}, false
			}
			return resp, true
		}
	}
	row := s.DB.QueryRow(ctx, `SELECT response_json FROM decisions WHERE tenant=$1 AND idempotency_key=$2`, tenant, key)
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		return models.GatewayResponse{}, false
	}
	var resp models.GatewayResponse
	if json.Unmarshal(payload, &resp) == nil {
		if !shouldPersistDecision(resp.Verdict) {
			return models.GatewayResponse{}, false
		}
		return resp, true
	}
	return models.GatewayResponse{}, false
}

func (s *Server) isSubjectRestricted(ctx context.Context, tenant, actorID string) (bool, string, error) {
	actorID = strings.TrimSpace(actorID)
	if actorID == "" {
		return false, "", nil
	}
	actorHash := hashIdentity(actorID)
	var reason string
	if strings.TrimSpace(tenant) != "" {
		err := s.DB.QueryRow(ctx, `
			SELECT reason
			FROM subject_restrictions
			WHERE actor_id_hash=$1
			  AND lifted_at IS NULL
			  AND (tenant=$2 OR tenant='')
			ORDER BY CASE WHEN tenant=$2 THEN 0 ELSE 1 END
			LIMIT 1
		`, actorHash, tenant).Scan(&reason)
		if err == nil {
			return true, reason, nil
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", err
	}
	err := s.DB.QueryRow(ctx, `
		SELECT reason
		FROM subject_restrictions
		WHERE actor_id_hash=$1 AND tenant='' AND lifted_at IS NULL
		LIMIT 1
	`, actorHash).Scan(&reason)
	if err == nil {
		return true, reason, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	return false, "", err
}

func shouldPersistDecision(verdict string) bool {
	return verdict != rta.VerdictDefer
}

func authHeaderMap(header, token string) map[string]string {
	if header == "" || token == "" {
		return nil
	}
	return map[string]string{header: token}
}

func (s *Server) acceptSequence(ctx context.Context, kid, tenant, actorID, policySetID string, seq int, ttl time.Duration) (bool, error) {
	if seq < 0 {
		return false, errors.New("sequence must be non-negative")
	}
	trimmedTenant := strings.ToLower(strings.TrimSpace(tenant))
	trimmedActor := strings.ToLower(strings.TrimSpace(actorID))
	streamKey := kid + "|" + trimmedTenant + "|" + trimmedActor + "|" + policySetID
	cmd, err := s.DB.Exec(ctx, `
		INSERT INTO cert_sequences(stream_key, last_seq)
		VALUES ($1, $2)
		ON CONFLICT (stream_key)
		DO UPDATE SET
			last_seq = EXCLUDED.last_seq,
			updated_at = now()
		WHERE cert_sequences.last_seq < EXCLUDED.last_seq
	`, streamKey, seq)
	if err != nil {
		return false, err
	}
	accepted := cmd.RowsAffected() > 0
	if accepted && ttl > 0 {
		_ = s.Cache.Set(ctx, "seq:"+streamKey, strconv.Itoa(seq), ttl)
	}
	return accepted, nil
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(statusCode int) {
	s.code = statusCode
	s.ResponseWriter.WriteHeader(statusCode)
}

func (srv *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, code: 200}
		next.ServeHTTP(rec, r)
		elapsed := time.Since(start)
		path := r.Method + " " + r.URL.Path
		srv.Metrics.Observe(path, rec.code, elapsed)
		srv.Metrics.ObserveLatency(path, elapsed)
	})
}

func (s *Server) withRoles(h http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(s.AuthMode, "off") {
			h(w, r)
			return
		}
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			s.raiseAuthIncident(r.Context(), "UNAUTHENTICATED")
			httpx.Error(w, 401, "unauthenticated")
			return
		}
		if !auth.HasAnyRole(principal, roles...) {
			s.raiseAuthIncident(r.Context(), "FORBIDDEN")
			httpx.Error(w, 403, "forbidden")
			return
		}
		if !isElevatedPrincipal(principal) && strings.TrimSpace(principal.Tenant) == "" {
			s.raiseAuthIncident(r.Context(), "TENANT_REQUIRED")
			httpx.Error(w, 403, "tenant required")
			return
		}
		h(w, r)
	}
}

func marshalCounterexample(c *models.Counterexample) json.RawMessage {
	if c == nil {
		return nil
	}
	b, _ := json.Marshal(c)
	return b
}

func (s *Server) authorizeIntent(r *http.Request, intent models.ActionIntent, cert models.ActionCert, policy *policyir.PolicySetIR) (bool, string) {
	if strings.EqualFold(s.AuthMode, "off") {
		return true, ""
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		return false, "ACCESS_UNAUTHENTICATED"
	}
	elevated := isElevatedPrincipal(principal)
	if !elevated && strings.TrimSpace(principal.Tenant) == "" {
		return false, "ACCESS_TENANT_REQUIRED"
	}
	if s.StrictActorBinding && !elevated && principal.Subject != "" && intent.Actor.ID != "" &&
		!strings.EqualFold(principal.Subject, intent.Actor.ID) {
		return false, "ACCESS_ACTOR_MISMATCH"
	}
	if !elevated && principal.Tenant != "" && intent.Actor.Tenant != "" &&
		!strings.EqualFold(principal.Tenant, intent.Actor.Tenant) {
		return false, "ACCESS_TENANT_MISMATCH"
	}
	if !elevated && len(intent.Actor.Roles) > 0 && !rolesBoundToPrincipal(intent.Actor.Roles, principal.Roles) {
		return false, "ACCESS_ROLE_MISMATCH"
	}
	domain := strings.ToLower(strings.TrimSpace(intent.Target.Domain))
	if domain == "" {
		return false, "ACCESS_DOMAIN_MISSING"
	}
	if allow, ok := s.DomainRoleAllow[domain]; ok && len(allow) > 0 && !elevated {
		for _, role := range principal.Roles {
			if _, found := allow[strings.ToLower(strings.TrimSpace(role))]; found {
				return true, ""
			}
		}
		return false, "ACCESS_DOMAIN_MISMATCH"
	}
	if s.ABACEnabled && policy != nil && len(policy.ABACRules) > 0 {
		attrs := s.resolveABACAttributes(r.Context(), principal, intent)
		pActor := models.Actor{ID: principal.Subject, Roles: principal.Roles, Tenant: principal.Tenant}
		ctx := smt.BuildContextWithPrincipal(intent, models.BeliefState{}, pActor, attrs)
		decision := abac.Evaluate(policy, ctx)
		if !decision.Allowed {
			return false, decision.Reason
		}
	}
	return true, ""
}

func rolesBoundToPrincipal(intentRoles, principalRoles []string) bool {
	principalSet := make(map[string]struct{}, len(principalRoles))
	for _, role := range principalRoles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		principalSet[role] = struct{}{}
	}
	for _, role := range intentRoles {
		role = strings.ToLower(strings.TrimSpace(role))
		if role == "" {
			continue
		}
		if _, ok := principalSet[role]; !ok {
			return false
		}
	}
	return true
}

func (s *Server) tenantScope(ctx context.Context) (string, bool) {
	if strings.EqualFold(s.AuthMode, "off") {
		return "", false
	}
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return "", false
	}
	if isElevatedPrincipal(principal) {
		return "", false
	}
	if principal.Tenant == "" {
		return "", false
	}
	return principal.Tenant, true
}

func (s *Server) resolveComplianceActor(w http.ResponseWriter, r *http.Request, provided string) (string, bool) {
	provided = strings.TrimSpace(provided)
	if strings.EqualFold(s.AuthMode, "off") {
		if provided == "" {
			httpx.Error(w, 400, "requested_by required")
			return "", false
		}
		return provided, true
	}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.Subject) == "" {
		httpx.Error(w, 401, "unauthenticated")
		return "", false
	}
	if provided != "" && !strings.EqualFold(provided, principal.Subject) {
		httpx.Error(w, 403, "requested_by must match principal")
		return "", false
	}
	return principal.Subject, true
}

func resolveTenant(intent models.ActionIntent, principal auth.Principal) string {
	if intent.Actor.Tenant != "" {
		return intent.Actor.Tenant
	}
	if principal.Tenant != "" {
		return principal.Tenant
	}
	return ""
}

func (s *Server) writeDeny(w http.ResponseWriter, ctx context.Context, reasonCode string, intent models.ActionIntent, cert models.ActionCert, counterexample *models.Counterexample) {
	if counterexample == nil {
		counterexample = &models.Counterexample{
			MinimalFacts: []string{"reason_code=" + reasonCode},
		}
	}
	resp := models.GatewayResponse{
		Verdict:        rta.VerdictDeny,
		ReasonCode:     reasonCode,
		PolicySetID:    cert.PolicySetID,
		PolicyVersion:  cert.PolicyVersion,
		Counterexample: counterexample,
	}
	if isCriticalIncident(resp.Verdict, reasonCode) {
		s.raiseIncident(ctx, "", "SECURITY_POLICY", reasonCode, resp.Verdict, intent, cert, counterexample)
	}
	if s.Metrics != nil {
		s.Metrics.IncVerdict(resp.Verdict)
		s.Metrics.IncReason(resp.ReasonCode)
		s.Metrics.IncVerdictReason(resp.Verdict, resp.ReasonCode)
	}
	httpx.WriteJSON(w, 200, resp)
}

func (s *Server) writeDeferred(w http.ResponseWriter, reasonCode string, cert models.ActionCert, retryAfterMS int) {
	if retryAfterMS <= 0 {
		retryAfterMS = 5000
	}
	resp := models.GatewayResponse{
		Verdict:       rta.VerdictDefer,
		ReasonCode:    reasonCode,
		PolicySetID:   cert.PolicySetID,
		PolicyVersion: cert.PolicyVersion,
		RetryAfterMS:  retryAfterMS,
	}
	if s.Metrics != nil {
		s.Metrics.IncVerdict(resp.Verdict)
		s.Metrics.IncReason(resp.ReasonCode)
		s.Metrics.IncVerdictReason(resp.Verdict, resp.ReasonCode)
	}
	httpx.WriteJSON(w, 200, resp)
}

func parseDomainRoleAllow(raw string) map[string]map[string]struct{} {
	out := map[string]map[string]struct{}{}
	for _, domainSpec := range strings.Split(raw, ";") {
		domainSpec = strings.TrimSpace(domainSpec)
		if domainSpec == "" {
			continue
		}
		parts := strings.SplitN(domainSpec, ":", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(parts[0]))
		if domain == "" {
			continue
		}
		if _, ok := out[domain]; !ok {
			out[domain] = map[string]struct{}{}
		}
		for _, role := range strings.Split(parts[1], ",") {
			role = strings.ToLower(strings.TrimSpace(role))
			if role != "" {
				out[domain][role] = struct{}{}
			}
		}
	}
	return out
}

func parseCIDRs(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if _, cidr, err := net.ParseCIDR(part); err == nil {
				out = append(out, cidr)
			}
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			continue
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out
}

func (s *Server) publishRefresh() {
	if s.Events == nil {
		return
	}
	s.Events.Publish(stream.NewEvent("refresh", nil))
}

func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	if s.Events == nil {
		httpx.Error(w, 503, "stream unavailable")
		return
	}
	opts := &websocket.AcceptOptions{}
	if origins := wsOriginPatterns(env("WS_ALLOWED_ORIGINS", "")); len(origins) > 0 {
		opts.OriginPatterns = origins
	}
	conn, err := websocket.Accept(w, r, opts)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	sub := s.Events.Subscribe(64)
	defer s.Events.Unsubscribe(sub)

	_ = wsjson.Write(ctx, conn, stream.NewEvent("ready", nil))
	readErr := make(chan error, 1)
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				readErr <- err
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "closed")
			return
		case <-readErr:
			_ = conn.Close(websocket.StatusNormalClosure, "closed")
			return
		case evt, ok := <-sub:
			if !ok {
				_ = conn.Close(websocket.StatusNormalClosure, "closed")
				return
			}
			writeCtx, cancelWrite := context.WithTimeout(ctx, 5*time.Second)
			err := wsjson.Write(writeCtx, conn, evt)
			cancelWrite()
			if err != nil {
				_ = conn.Close(websocket.StatusNormalClosure, "write_failed")
				return
			}
		}
	}
}

func wsOriginPatterns(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func policyCacheKey(policyID, version string) string {
	return strings.ToLower(strings.TrimSpace(policyID)) + "@" + strings.ToLower(strings.TrimSpace(version))
}

func (s *Server) loadPolicy(ctx context.Context, policySetID, version string) (*policyir.PolicySetIR, error) {
	if policySetID == "" || version == "" {
		return nil, errors.New("policy id and version required")
	}
	key := policyCacheKey(policySetID, version)
	if s.PolicyCache != nil {
		if cached, ok := s.PolicyCache.Get(key); ok {
			return cached, nil
		}
	}
	row := s.DB.QueryRow(ctx, `SELECT dsl, status FROM policy_versions WHERE policy_set_id=$1 AND version=$2`, policySetID, version)
	var dsl string
	var status string
	if err := row.Scan(&dsl, &status); err != nil {
		return nil, err
	}
	if s.PolicyRequirePublished && status != "PUBLISHED" {
		return nil, errors.New("policy not published")
	}
	policy, err := axiomdsl.ParseDSL(dsl)
	if err != nil {
		return nil, err
	}
	if s.PolicyCache != nil {
		s.PolicyCache.Set(key, policy)
	}
	return policy, nil
}

func (s *Server) approvalPolicy(policy *policyir.PolicySetIR, approvalsRequired int) escrowfsm.ApprovalPolicy {
	ap := escrowfsm.ApprovalPolicy{Required: approvalsRequired, EnforceSoD: true}
	if policy != nil && policy.Approvals != nil {
		if policy.Approvals.Required > 0 && policy.Approvals.Required > ap.Required {
			ap.Required = policy.Approvals.Required
		}
		ap.Roles = append([]string{}, policy.Approvals.Roles...)
		ap.EnforceSoD = policy.Approvals.EnforceSoD
		ap.ExpiresIn = policy.Approvals.ExpiresIn
	}
	if strings.EqualFold(s.AuthMode, "off") {
		ap.Roles = nil
	}
	if ap.Required < 1 {
		ap.Required = 1
	}
	return ap
}

func (s *Server) resolveABACAttributes(ctx context.Context, principal auth.Principal, intent models.ActionIntent) map[string]string {
	if s.ABACAttrURL == "" {
		return map[string]string{}
	}
	cacheKey := "abac:attr:" + strings.TrimSpace(principal.Subject) + ":" + strings.TrimSpace(principal.Tenant) + ":" +
		strings.TrimSpace(intent.Target.Domain) + ":" + strings.TrimSpace(intent.ActionType) + ":" + strings.TrimSpace(intent.Operation.Name)
	if s.Cache != nil {
		if raw, err := s.Cache.Get(ctx, cacheKey); err == nil && raw != "" {
			if attrs := parseAttributes([]byte(raw)); len(attrs) > 0 {
				return attrs
			}
		}
	}
	payload := map[string]string{
		"subject": principal.Subject,
		"tenant":  principal.Tenant,
		"domain":  intent.Target.Domain,
		"action":  intent.Operation.Name,
	}
	body, _ := json.Marshal(payload)
	status, resp, err := httpx.RequestJSON(ctx, s.HTTPClient, http.MethodPost, s.ABACAttrURL, body, authHeaderMap(s.ABACAttrHeader, s.ABACAttrToken), s.UpstreamRetries, s.UpstreamRetryDelay)
	if err != nil || status >= 300 {
		return map[string]string{}
	}
	attrs := parseAttributes(resp)
	if len(attrs) > 0 && s.Cache != nil {
		_ = s.Cache.Set(ctx, cacheKey, string(resp), s.ABACAttrCacheTTL)
	}
	return attrs
}

func parseAttributes(raw []byte) map[string]string {
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return map[string]string{}
	}
	if nested, ok := obj["attributes"].(map[string]interface{}); ok {
		obj = nested
	}
	out := map[string]string{}
	for k, v := range obj {
		switch t := v.(type) {
		case string:
			out[k] = t
		case float64:
			out[k] = strconv.FormatFloat(t, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(t)
		default:
			if b, err := json.Marshal(t); err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}

func isCriticalReason(reasonCode string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(reasonCode))
	if normalized == "" {
		return false
	}
	if _, ok := criticalReasonCodes[normalized]; ok {
		return true
	}
	return strings.HasPrefix(normalized, "SOD_") || strings.HasPrefix(normalized, "ACCESS_")
}

func isCriticalIncident(verdict, reasonCode string) bool {
	if verdict == rta.VerdictDeny && reasonCode != "CERT_EXPIRED" {
		return true
	}
	return isCriticalReason(reasonCode)
}

func (s *Server) checkRateLimit(r *http.Request, intent models.ActionIntent, policy *policyir.PolicySetIR) (bool, int) {
	if !s.RateLimitEnabled || s.RateLimiter == nil {
		return false, 0
	}
	limit := s.RateLimitPerMinute
	window := s.RateLimitWindow
	scope := "actor"
	if policy != nil && policy.RateLimit != nil {
		if policy.RateLimit.Limit > 0 {
			limit = policy.RateLimit.Limit
		}
		if policy.RateLimit.Window > 0 {
			window = policy.RateLimit.Window
		}
		if policy.RateLimit.Scope != "" {
			scope = strings.ToLower(policy.RateLimit.Scope)
		}
	}
	if limit <= 0 {
		return false, 0
	}
	limiter := s.RateLimiter
	if rl, ok := limiter.(*ratelimit.RedisLimiter); ok && window > 0 && rl.Window != window {
		limiter = ratelimit.NewRedis(s.Redis, window)
	}
	subject := intent.Actor.ID
	tenant := intent.Actor.Tenant
	if principal, ok := auth.PrincipalFromContext(r.Context()); ok {
		if principal.Subject != "" {
			subject = principal.Subject
		}
		if principal.Tenant != "" {
			tenant = principal.Tenant
		}
	}
	segment := subject
	switch scope {
	case "tenant":
		segment = tenant
	case "global":
		segment = "global"
	}
	if segment == "" {
		segment = "anonymous"
	}
	clientIP := s.clientIP(r)
	key := strings.ToLower(strings.TrimSpace(intent.Target.Domain)) + ":" + strings.ToLower(strings.TrimSpace(intent.ActionType)) + ":" + scope + ":" + segment + ":" + clientIP
	decision := limiter.Allow(key, limit)
	if decision.Allowed {
		return false, 0
	}
	retryAfter := int(time.Until(decision.ResetAt).Milliseconds())
	if retryAfter < 0 {
		if window > 0 {
			retryAfter = int(window.Milliseconds())
		} else {
			retryAfter = 0
		}
	}
	return true, retryAfter
}

func (s *Server) clientIP(r *http.Request) string {
	remoteIP := parseIP(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = r.RemoteAddr
	}
	if remoteIP != "" && s.isTrustedProxy(remoteIP) {
		if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				candidate := parseIP(strings.TrimSpace(parts[0]))
				if candidate != "" {
					return candidate
				}
			}
		}
		if realIP := parseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != "" {
			return realIP
		}
	}
	if remoteIP == "" {
		return "unknown"
	}
	return remoteIP
}

func (s *Server) isTrustedProxy(ipStr string) bool {
	if len(s.TrustedProxyCIDRs) == 0 {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, cidr := range s.TrustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func parseIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return host
	}
	if net.ParseIP(addr) != nil {
		return addr
	}
	return ""
}

func asInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint64:
		if n > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

func (s *Server) limitRequestBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.MaxRequestBodyBytes > 0 && r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.MaxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err == nil {
		return body, true
	}
	if strings.Contains(strings.ToLower(err.Error()), "request body too large") {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	httpx.Error(w, http.StatusBadRequest, "invalid request body")
	return nil, false
}

func isElevatedPrincipal(principal auth.Principal) bool {
	return auth.HasAnyRole(principal, "securityadmin", "complianceofficer", "platformengineer")
}

func envDurationSec(k string, def int) time.Duration {
	return time.Second * time.Duration(envInt(k, def))
}

func nullIfEmpty(value string) interface{} {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func hashIdentity(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return fmt.Sprintf("%x", sum[:])
}

func scopedIdempotencyKey(tenant, actorID, key string) string {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		return ""
	}
	trimmedTenant := strings.TrimSpace(tenant)
	trimmedActor := strings.TrimSpace(actorID)
	if trimmedTenant != "" {
		if trimmedActor != "" {
			return strings.ToLower(trimmedTenant) + "|" + strings.ToLower(trimmedActor) + "|" + trimmedKey
		}
		return strings.ToLower(trimmedTenant) + "|" + trimmedKey
	}
	if trimmedActor == "" {
		return trimmedKey
	}
	return strings.ToLower(trimmedActor) + "|" + trimmedKey
}

func scopedNonceKey(tenant, actorID, nonce string) string {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return "nonce:"
	}
	trimmedTenant := strings.ToLower(strings.TrimSpace(tenant))
	trimmedActor := strings.ToLower(strings.TrimSpace(actorID))
	if trimmedTenant != "" {
		if trimmedActor != "" {
			return "nonce:" + trimmedTenant + ":" + trimmedActor + ":" + trimmed
		}
		return "nonce:" + trimmedTenant + ":" + trimmed
	}
	if trimmedActor != "" {
		return "nonce:" + trimmedActor + ":" + trimmed
	}
	return "nonce:" + trimmed
}

func decisionCacheKey(tenant, key string) string {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "decision:"
	}
	tenant = strings.ToLower(strings.TrimSpace(tenant))
	if tenant == "" {
		return "decision:" + trimmed
	}
	return "decision:" + tenant + ":" + trimmed
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
