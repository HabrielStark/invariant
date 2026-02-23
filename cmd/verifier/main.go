package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/hardening"
	"axiom/pkg/httpx"
	"axiom/pkg/models"
	"axiom/pkg/policyeval"
	"axiom/pkg/store"
	"axiom/pkg/telemetry"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type verifierDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Server struct {
	DB                  verifierDB
	HTTPClient          *http.Client
	PolicyURL           string
	StateURL            string
	PolicyAuthHeader    string
	PolicyAuthToken     string
	SMTEnabled          bool
	SMTBackend          string
	Z3Path              string
	Z3Timeout           time.Duration
	AuthMode            string
	AuthSecret          string
	ServiceAuthHeader   string
	ServiceAuthToken    string
	MaxRequestBodyBytes int64
	ExternalKeyStore    auth.KeyStore
}

// Testable variables for main()
var (
	logFatalf       = log.Fatalf
	initTelemetryFn = telemetry.Init
	openDBFnV       func(context.Context) (verifierDB, func(), error)
	listenFnV       func(*http.Server) error
)

func main() {
	if err := runVerifier(initTelemetryFn, openDBFnV, listenFnV); err != nil {
		logFatalf("verifier: %v", err)
	}
}

func runVerifier(
	initTelemetry func(context.Context, string) (func(context.Context) error, error),
	openDB func(context.Context) (verifierDB, func(), error),
	listen func(*http.Server) error,
) error {
	if initTelemetry == nil {
		initTelemetry = telemetry.Init
	}
	if openDB == nil {
		openDB = func(ctx context.Context) (verifierDB, func(), error) {
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
	shutdown, err := initTelemetry(ctx, "verifier")
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
		HTTPClient:          telemetry.InstrumentClient(&http.Client{Timeout: time.Millisecond * time.Duration(envInt("UPSTREAM_TIMEOUT_MS", 3000))}),
		PolicyURL:           env("POLICY_URL", "http://localhost:8082"),
		StateURL:            env("STATE_URL", "http://localhost:8083"),
		PolicyAuthHeader:    env("POLICY_AUTH_HEADER", ""),
		PolicyAuthToken:     env("POLICY_AUTH_TOKEN", ""),
		SMTEnabled:          env("SMT_ENABLED", "true") == "true",
		SMTBackend:          env("SMT_BACKEND", "z3"),
		Z3Path:              env("Z3_PATH", "z3"),
		Z3Timeout:           time.Millisecond * time.Duration(envInt("SMT_TIMEOUT_MS", 50)),
		AuthMode:            env("AUTH_MODE", "oidc_hs256"),
		AuthSecret:          env("OIDC_HS256_SECRET", ""),
		ServiceAuthHeader:   env("VERIFIER_AUTH_HEADER", ""),
		ServiceAuthToken:    env("VERIFIER_AUTH_TOKEN", ""),
		MaxRequestBodyBytes: int64(envInt("MAX_REQUEST_BODY_BYTES", 1<<20)),
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
		Service:            "verifier",
		Environment:        runtimeEnv,
		StrictProdSecurity: env("STRICT_PROD_SECURITY", "true"),
		DatabaseRequireTLS: env("DATABASE_REQUIRE_TLS", ""),
		CORSAllowedOrigins: env("CORS_ALLOWED_ORIGINS", ""),
		RequiredServiceSecrets: []hardening.EnvRequirement{
			{Name: "VERIFIER_AUTH_HEADER", Value: s.ServiceAuthHeader},
			{Name: "VERIFIER_AUTH_TOKEN", Value: s.ServiceAuthToken},
			{Name: "POLICY_AUTH_HEADER", Value: s.PolicyAuthHeader},
			{Name: "POLICY_AUTH_TOKEN", Value: s.PolicyAuthToken},
		},
	}); err != nil {
		return err
	}
	if s.MaxRequestBodyBytes <= 0 {
		s.MaxRequestBodyBytes = 1 << 20
	}

	r := chi.NewRouter()
	r.Use(httpx.CORSMiddleware(env("CORS_ALLOWED_ORIGINS", "")))
	r.Use(httpx.SecurityHeadersMiddleware)
	r.Use(telemetry.HTTPMiddleware("verifier"))
	r.Use(s.limitRequestBodyMiddleware)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "verifier"})
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
	secured := chi.NewRouter()
	secured.Use(s.serviceOrAuth(authMw))
	secured.Post("/v1/verify", s.verify)
	r.Mount("/", secured)

	addr := env("ADDR", ":8081")
	log.Printf("verifier listening on %s", addr)
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

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Intent         json.RawMessage `json:"intent"`
		Cert           json.RawMessage `json:"cert"`
		BeliefSnapshot json.RawMessage `json:"belief_state_snapshot"`
		SnapshotID     string          `json:"snapshot_id"`
		Replay         bool            `json:"replay"`
	}
	body, ok := readRequestBody(w, r)
	if !ok {
		return
	}
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
	var cert models.ActionCert
	if err := json.Unmarshal(req.Cert, &cert); err != nil {
		httpx.Error(w, 400, "invalid cert")
		return
	}
	if cert.PolicyVersion == "" || cert.PolicySetID == "" || cert.ExpiresAt == "" || cert.Nonce == "" {
		httpx.Error(w, 400, "cert missing required fields")
		return
	}
	expired, err := certExpired(time.Now().UTC(), cert.ExpiresAt)
	if err != nil {
		httpx.Error(w, 400, "expires_at must be RFC3339")
		return
	}
	if !req.Replay && expired {
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DENY", ReasonCode: "CERT_EXPIRED"})
		return
	}
	// Fetch belief snapshot if needed
	var belief models.BeliefState
	if len(req.BeliefSnapshot) > 0 {
		if err := json.Unmarshal(req.BeliefSnapshot, &belief); err != nil {
			httpx.Error(w, 400, "invalid belief snapshot")
			return
		}
	} else if req.SnapshotID != "" {
		bs, err := s.fetchSnapshot(r.Context(), req.SnapshotID)
		if err != nil {
			httpx.Error(w, 500, "snapshot fetch failed")
			return
		}
		belief = bs
	} else {
		// no snapshot -> unknown state
		belief = models.BeliefState{}
	}

	// Canonical hash check
	canonical, err := models.CanonicalizeJSON(req.Intent)
	if err != nil {
		httpx.Error(w, 400, "canonicalization failed")
		return
	}
	calcHash := models.IntentHash(canonical, cert.PolicyVersion, cert.Nonce)
	if cert.IntentHash != calcHash {
		httpx.WriteJSON(w, 200, models.VerifierResponse{
			Verdict: "DENY", ReasonCode: "INTENT_HASH_MISMATCH",
		})
		return
	}

	// signature verification
	pubKey, status, err := s.lookupKey(r.Context(), cert.Signature.Kid)
	if err != nil || (!req.Replay && status != "active") {
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DENY", ReasonCode: "KEY_INVALID"})
		return
	}
	if err := auth.VerifyEd25519(pubKey, cert); err != nil {
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DENY", ReasonCode: "BAD_SIGNATURE"})
		return
	}

	// fetch policy DSL
	now := time.Now().UTC()
	dsl, err := s.fetchPolicyDSLAt(r.Context(), cert.PolicySetID, cert.PolicyVersion, now, req.Replay)
	if err != nil {
		if errors.Is(err, errPolicyNotActive) {
			httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DENY", ReasonCode: "POLICY_INACTIVE"})
			return
		}
		if errors.Is(err, errPolicyNotPublished) {
			httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DENY", ReasonCode: "POLICY_UNPUBLISHED"})
			return
		}
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DEFER", ReasonCode: "POLICY_UNAVAILABLE"})
		return
	}
	evalRes, err := policyeval.EvaluateWithOptions(dsl, intent, belief, policyeval.Options{
		Backend:   s.SMTBackend,
		Z3Path:    s.Z3Path,
		Z3Timeout: s.Z3Timeout,
	})
	if err != nil {
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "DENY", ReasonCode: "POLICY_PARSE_FAIL"})
		return
	}
	if evalRes.Verdict != "ALLOW" {
		httpx.WriteJSON(w, 200, models.VerifierResponse{
			Verdict:         evalRes.Verdict,
			ReasonCode:      evalRes.ReasonCode,
			Counterexample:  evalRes.Counterexample,
			SuggestedShield: evalRes.SuggestedShield,
		})
		return
	}
	backend := strings.ToLower(strings.TrimSpace(s.SMTBackend))
	formal := backend == "z3" || backend == "z3cgo" || backend == "z3exec"
	if !formal {
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "ESCROW", ReasonCode: "SMT_NON_FORMAL"})
		return
	}
	if !s.SMTEnabled {
		httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "ESCROW", ReasonCode: "SMT_DISABLED"})
		return
	}

	httpx.WriteJSON(w, 200, models.VerifierResponse{Verdict: "ALLOW", ReasonCode: "OK"})
}

var (
	errPolicyNotPublished = errors.New("policy not published")
	errPolicyNotActive    = errors.New("policy not active")
)

func (s *Server) fetchPolicyDSL(ctx context.Context, policyID, version string) (string, error) {
	return s.fetchPolicyDSLAt(ctx, policyID, version, time.Now().UTC(), false)
}

func (s *Server) fetchPolicyDSLAt(ctx context.Context, policyID, version string, now time.Time, replay bool) (string, error) {
	dsl, err := s.fetchPolicyDSLFromDB(ctx, policyID, version, now, replay)
	if err == nil {
		return dsl, nil
	}
	if errors.Is(err, errPolicyNotPublished) || errors.Is(err, errPolicyNotActive) {
		return "", err
	}
	return s.fetchPolicyDSLFromHTTP(ctx, policyID, version, replay)
}

func (s *Server) fetchPolicyDSLFromDB(ctx context.Context, policyID, version string, now time.Time, replay bool) (string, error) {
	if s.DB == nil {
		return "", errors.New("db unavailable")
	}
	row := s.DB.QueryRow(ctx, `
		SELECT dsl, status, effective_from, effective_to
		FROM policy_versions
		WHERE policy_set_id=$1 AND version=$2
	`, policyID, version)
	var (
		dsl           string
		status        string
		effectiveFrom *time.Time
		effectiveTo   *time.Time
	)
	if err := row.Scan(&dsl, &status, &effectiveFrom, &effectiveTo); err != nil {
		return "", err
	}
	if status != "PUBLISHED" {
		return "", errPolicyNotPublished
	}
	if !replay && !policyEffectiveAt(now, effectiveFrom, effectiveTo) {
		return "", errPolicyNotActive
	}
	return dsl, nil
}

func (s *Server) fetchPolicyDSLFromHTTP(ctx context.Context, policyID, version string, replay bool) (string, error) {
	base := strings.TrimSuffix(s.PolicyURL, "/")
	url := base + "/v1/policysets/" + policyID + "/versions/" + version
	headers := map[string]string{}
	if s.PolicyAuthHeader != "" && s.PolicyAuthToken != "" {
		url = base + "/v1/internal/policysets/" + policyID + "/versions/" + version
		if replay {
			url += "?allow_inactive=true"
		}
		headers[s.PolicyAuthHeader] = s.PolicyAuthToken
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("policy not found")
	}
	var out struct {
		DSL string `json:"dsl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.DSL, nil
}

func policyEffectiveAt(now time.Time, from, to *time.Time) bool {
	if from != nil && now.Before(from.UTC()) {
		return false
	}
	if to != nil && !now.Before(to.UTC()) {
		return false
	}
	return true
}

func (s *Server) fetchSnapshot(ctx context.Context, snapshotID string) (models.BeliefState, error) {
	var bs models.BeliefState
	row := s.DB.QueryRow(ctx, `SELECT payload FROM belief_snapshots WHERE snapshot_id=$1`, snapshotID)
	var payload []byte
	if err := row.Scan(&payload); err != nil {
		return bs, err
	}
	if err := json.Unmarshal(payload, &bs); err != nil {
		return bs, err
	}
	return bs, nil
}

func (s *Server) lookupKey(ctx context.Context, kid string) (ed25519.PublicKey, string, error) {
	if kid == "" {
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
		return nil, "", errors.New("invalid ed25519 public key")
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
	if rec == nil || len(rec.PublicKey) != ed25519.PublicKeySize {
		return nil, "", errors.New("external key lookup invalid response")
	}
	status := strings.ToLower(strings.TrimSpace(rec.Status))
	if status == "" {
		status = "active"
	}
	return ed25519.PublicKey(rec.PublicKey), status, nil
}

func certExpired(now time.Time, exp string) (bool, error) {
	exp = strings.TrimSpace(exp)
	if exp == "" {
		return false, errors.New("expires_at required")
	}
	parsed, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		return false, err
	}
	return now.UTC().After(parsed.UTC()), nil
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

func envDurationSec(k string, def int) time.Duration {
	return time.Second * time.Duration(envInt(k, def))
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
		return nil, errors.New("unsupported KEYSTORE_PROVIDER")
	}
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
