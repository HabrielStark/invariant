package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/axiomdsl"
	"axiom/pkg/hardening"
	"axiom/pkg/httpx"
	"axiom/pkg/models"
	"axiom/pkg/policyeval"
	"axiom/pkg/store"
	"axiom/pkg/telemetry"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Server struct {
	DB                  policyDB
	AuthMode            string
	AuthSecret          string
	PolicyAuthHeader    string
	PolicyAuthToken     string
	MaxRequestBodyBytes int64
}

type policyDB interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type policyVersionSummary struct {
	PolicySetID       string     `json:"policy_set_id"`
	Version           string     `json:"version"`
	Status            string     `json:"status"`
	ApprovalsRequired int        `json:"approvals_required"`
	ApprovalsReceived int        `json:"approvals_received"`
	CreatedBy         string     `json:"created_by"`
	ApprovedBy        string     `json:"approved_by,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	SubmittedAt       *time.Time `json:"submitted_at,omitempty"`
	ApprovedAt        *time.Time `json:"approved_at,omitempty"`
}

type versionApproval struct {
	Approver  string    `json:"approver"`
	CreatedAt time.Time `json:"created_at"`
}

// Testable variables for main()
var (
	logFatalf       = log.Fatalf
	initTelemetryFn = telemetry.Init
	openDBFnP       func(context.Context) (policyDB, func(), error)
	listenFnP       func(*http.Server) error
)

func main() {
	if err := runPolicy(initTelemetryFn, openDBFnP, listenFnP); err != nil {
		logFatalf("policy: %v", err)
	}
}

func runPolicy(
	initTelemetry func(context.Context, string) (func(context.Context) error, error),
	openDB func(context.Context) (policyDB, func(), error),
	listen func(*http.Server) error,
) error {
	if initTelemetry == nil {
		initTelemetry = telemetry.Init
	}
	if openDB == nil {
		openDB = func(ctx context.Context) (policyDB, func(), error) {
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
	shutdown, err := initTelemetry(ctx, "policy")
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
		AuthMode:            env("AUTH_MODE", "oidc_hs256"),
		AuthSecret:          env("OIDC_HS256_SECRET", ""),
		PolicyAuthHeader:    env("POLICY_AUTH_HEADER", ""),
		PolicyAuthToken:     env("POLICY_AUTH_TOKEN", ""),
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
		Service:            "policy",
		Environment:        runtimeEnv,
		StrictProdSecurity: env("STRICT_PROD_SECURITY", "true"),
		DatabaseRequireTLS: env("DATABASE_REQUIRE_TLS", ""),
		CORSAllowedOrigins: env("CORS_ALLOWED_ORIGINS", ""),
		RequiredServiceSecrets: []hardening.EnvRequirement{
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
	r.Use(telemetry.HTTPMiddleware("policy"))
	r.Use(s.limitRequestBodyMiddleware)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok", "service": "policy"})
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

	authRouter.Post("/v1/policysets", s.withRoles(s.createPolicySet, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/policysets/{id}/versions", s.withRoles(s.createPolicyVersion, "complianceofficer"))
	authRouter.Get("/v1/policysets/{id}/versions", s.withRoles(s.listPolicyVersions, "complianceofficer", "operator", "securityadmin"))
	authRouter.Get("/v1/policysets/{id}/versions:diff", s.withRoles(s.diffPolicyVersions, "complianceofficer", "operator", "securityadmin"))
	authRouter.Post("/v1/policysets/{id}/versions/{version}/submit", s.withRoles(s.submitPolicyVersion, "complianceofficer"))
	authRouter.Post("/v1/policysets/{id}/versions/{version}/approvals", s.withRoles(s.approvePolicyVersion, "complianceofficer", "securityadmin"))
	authRouter.Post("/v1/policysets/{id}/versions/{version}/approve", s.withRoles(s.approvePolicyVersion, "complianceofficer", "securityadmin"))
	authRouter.Get("/v1/policysets/{id}/versions/{version}/approvals", s.withRoles(s.listVersionApprovals, "complianceofficer", "securityadmin", "operator"))
	authRouter.Post("/v1/policysets/{id}/versions/{version}/evaluate", s.withRoles(s.evaluatePolicyVersion, "complianceofficer", "operator", "securityadmin"))
	authRouter.Get("/v1/policysets/{id}/versions/{version}", s.withRoles(s.getPolicyVersion, "complianceofficer", "operator", "securityadmin"))

	authRouter.Post("/v1/keys", s.withRoles(s.createKey, "securityadmin"))
	authRouter.Get("/v1/keys", s.withRoles(s.listKeys, "securityadmin", "complianceofficer"))
	authRouter.Get("/v1/keys/{kid}", s.withRoles(s.getKey, "securityadmin", "complianceofficer"))
	authRouter.Patch("/v1/keys/{kid}", s.withRoles(s.patchKey, "securityadmin"))
	r.Mount("/", authRouter)

	r.With(s.internalTokenOnly).Get("/v1/internal/policysets/{id}/versions/{version}", s.getPolicyVersionInternal)

	addr := env("ADDR", ":8082")
	log.Printf("policy service listening on %s", addr)
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

func (s *Server) createPolicySet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	_, err := s.DB.Exec(r.Context(), `INSERT INTO policy_sets(id, name, domain) VALUES ($1,$2,$3)`, req.ID, req.Name, req.Domain)
	if err != nil {
		internalServerError(w, "create policy set", err)
		return
	}
	httpx.WriteJSON(w, 201, map[string]string{"id": req.ID})
}

func (s *Server) createPolicyVersion(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	var req struct {
		Version       string `json:"version"`
		DSL           string `json:"dsl"`
		EffectiveFrom string `json:"effective_from"`
		EffectiveTo   string `json:"effective_to"`
		CreatedBy     string `json:"created_by"`
		ApprovalsReq  int    `json:"approvals_required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.Version == "" || req.DSL == "" {
		httpx.Error(w, 400, "version and dsl required")
		return
	}
	if !strings.EqualFold(s.AuthMode, "off") {
		subject, err := s.requireSubject(r)
		if err != nil {
			httpx.Error(w, 401, err.Error())
			return
		}
		if req.CreatedBy != "" && !strings.EqualFold(req.CreatedBy, subject) {
			httpx.Error(w, 403, "created_by must match principal")
			return
		}
		req.CreatedBy = subject
	} else if req.CreatedBy == "" {
		httpx.Error(w, 400, "created_by required")
		return
	}
	if req.ApprovalsReq == 0 {
		req.ApprovalsReq = 2
	}
	if req.ApprovalsReq < 1 || req.ApprovalsReq > 5 {
		httpx.Error(w, 400, "approvals_required must be between 1 and 5")
		return
	}
	if _, err := axiomdsl.ParseDSL(req.DSL); err != nil {
		httpx.Error(w, 400, "dsl parse error: "+err.Error())
		return
	}
	_, err := s.DB.Exec(r.Context(), `
		INSERT INTO policy_versions(policy_set_id, version, dsl, effective_from, effective_to, status, approvals_required, created_by)
		VALUES ($1,$2,$3,$4,$5,'DRAFT',$6,$7)
	`, policyID, req.Version, req.DSL, nullTime(req.EffectiveFrom), nullTime(req.EffectiveTo), req.ApprovalsReq, req.CreatedBy)
	if err != nil {
		internalServerError(w, "create policy version", err)
		return
	}
	httpx.WriteJSON(w, 201, map[string]interface{}{"policy_set_id": policyID, "version": req.Version, "status": "DRAFT", "approvals_required": req.ApprovalsReq})
}

func (s *Server) submitPolicyVersion(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	var req struct {
		Submitter string `json:"submitter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if !strings.EqualFold(s.AuthMode, "off") {
		subject, err := s.requireSubject(r)
		if err != nil {
			httpx.Error(w, 401, err.Error())
			return
		}
		if req.Submitter != "" && !strings.EqualFold(req.Submitter, subject) {
			httpx.Error(w, 403, "submitter must match principal")
			return
		}
		req.Submitter = subject
	} else if req.Submitter == "" {
		httpx.Error(w, 400, "submitter required")
		return
	}
	cmd, err := s.DB.Exec(r.Context(), `
		UPDATE policy_versions
		SET status='PENDING_APPROVAL', submitted_at=now()
		WHERE policy_set_id=$1 AND version=$2 AND status='DRAFT'
	`, policyID, version)
	if err != nil {
		internalServerError(w, "submit policy version", err)
		return
	}
	if cmd.RowsAffected() == 0 {
		httpx.Error(w, 409, "policy version must be DRAFT")
		return
	}
	httpx.WriteJSON(w, 200, map[string]string{"policy_set_id": policyID, "version": version, "status": "PENDING_APPROVAL"})
}

func (s *Server) approvePolicyVersion(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	var req struct {
		Approver string `json:"approver"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if !strings.EqualFold(s.AuthMode, "off") {
		subject, err := s.requireSubject(r)
		if err != nil {
			httpx.Error(w, 401, err.Error())
			return
		}
		if req.Approver != "" && !strings.EqualFold(req.Approver, subject) {
			httpx.Error(w, 403, "approver must match principal")
			return
		}
		req.Approver = subject
	} else if req.Approver == "" {
		httpx.Error(w, 400, "approver required")
		return
	}
	var status, createdBy string
	var approvalsRequired int
	row := s.DB.QueryRow(r.Context(), `
		SELECT status, approvals_required, COALESCE(created_by,'')
		FROM policy_versions
		WHERE policy_set_id=$1 AND version=$2
	`, policyID, version)
	if err := row.Scan(&status, &approvalsRequired, &createdBy); err != nil {
		httpx.Error(w, 404, "policy version not found")
		return
	}
	if status == "DRAFT" {
		httpx.Error(w, 409, "submit policy version first")
		return
	}
	if status == "PUBLISHED" {
		count, countErr := s.countApprovals(r.Context(), policyID, version)
		if countErr != nil {
			internalServerError(w, "count approvals for published policy", countErr)
			return
		}
		httpx.WriteJSON(w, 200, map[string]interface{}{
			"policy_set_id":      policyID,
			"version":            version,
			"status":             "PUBLISHED",
			"approvals_received": count,
			"approvals_required": approvalsRequired,
		})
		return
	}
	if createdBy != "" && createdBy == req.Approver {
		httpx.Error(w, 403, "approver must be different from creator")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `
		INSERT INTO policy_version_approvals(policy_set_id, version, approver)
		VALUES ($1,$2,$3)
		ON CONFLICT DO NOTHING
	`, policyID, version, req.Approver); err != nil {
		internalServerError(w, "insert policy approval", err)
		return
	}
	received, err := s.countApprovals(r.Context(), policyID, version)
	if err != nil {
		internalServerError(w, "count approvals", err)
		return
	}
	outStatus := "PENDING_APPROVAL"
	if received >= approvalsRequired {
		if _, err := s.DB.Exec(r.Context(), `
			UPDATE policy_versions
			SET status='PUBLISHED', approved_by=$3, approved_at=now()
			WHERE policy_set_id=$1 AND version=$2 AND status IN ('PENDING_APPROVAL', 'DRAFT')
		`, policyID, version, req.Approver); err != nil {
			internalServerError(w, "publish policy version", err)
			return
		}
		outStatus = "PUBLISHED"
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{
		"policy_set_id":      policyID,
		"version":            version,
		"status":             outStatus,
		"approvals_received": received,
		"approvals_required": approvalsRequired,
	})
}

func (s *Server) getPolicyVersion(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	var dsl string
	var status string
	var approvalsRequired int
	row := s.DB.QueryRow(r.Context(), `SELECT dsl, status, approvals_required FROM policy_versions WHERE policy_set_id=$1 AND version=$2`, policyID, version)
	if err := row.Scan(&dsl, &status, &approvalsRequired); err != nil {
		httpx.Error(w, 404, "not found")
		return
	}
	if status != "PUBLISHED" {
		httpx.Error(w, 404, "not published")
		return
	}
	received, err := s.countApprovals(r.Context(), policyID, version)
	if err != nil {
		internalServerError(w, "count approvals for get policy version", err)
		return
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{
		"policy_set_id":      policyID,
		"version":            version,
		"dsl":                dsl,
		"status":             status,
		"approvals_required": approvalsRequired,
		"approvals_received": received,
	})
}

func (s *Server) getPolicyVersionInternal(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	var (
		dsl           string
		status        string
		effectiveFrom *time.Time
		effectiveTo   *time.Time
	)
	row := s.DB.QueryRow(r.Context(), `
		SELECT dsl, status, effective_from, effective_to
		FROM policy_versions
		WHERE policy_set_id=$1 AND version=$2
	`, policyID, version)
	if err := row.Scan(&dsl, &status, &effectiveFrom, &effectiveTo); err != nil {
		httpx.Error(w, 404, "not found")
		return
	}
	if status != "PUBLISHED" {
		httpx.Error(w, 404, "not published")
		return
	}
	allowInactive := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("allow_inactive")), "true")
	now := time.Now().UTC()
	if !allowInactive {
		if effectiveFrom != nil && now.Before(effectiveFrom.UTC()) {
			httpx.Error(w, 404, "not active")
			return
		}
		if effectiveTo != nil && !now.Before(effectiveTo.UTC()) {
			httpx.Error(w, 404, "not active")
			return
		}
	}
	resp := map[string]interface{}{
		"policy_set_id": policyID,
		"version":       version,
		"dsl":           dsl,
		"status":        status,
	}
	if effectiveFrom != nil {
		resp["effective_from"] = effectiveFrom.UTC().Format(time.RFC3339)
	}
	if effectiveTo != nil {
		resp["effective_to"] = effectiveTo.UTC().Format(time.RFC3339)
	}
	httpx.WriteJSON(w, 200, resp)
}

func (s *Server) listPolicyVersions(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	rows, err := s.DB.Query(r.Context(), `
		SELECT
			pv.policy_set_id,
			pv.version,
			pv.status,
			pv.approvals_required,
			COALESCE((SELECT COUNT(*) FROM policy_version_approvals pva WHERE pva.policy_set_id=pv.policy_set_id AND pva.version=pv.version), 0) AS approvals_received,
			COALESCE(pv.created_by, ''),
			COALESCE(pv.approved_by, ''),
			pv.created_at,
			pv.submitted_at,
			pv.approved_at
		FROM policy_versions pv
		WHERE pv.policy_set_id=$1
		ORDER BY pv.created_at DESC
	`, policyID)
	if err != nil {
		httpx.Error(w, 500, "query failed")
		return
	}
	defer rows.Close()
	items := make([]policyVersionSummary, 0)
	for rows.Next() {
		var item policyVersionSummary
		if err := rows.Scan(
			&item.PolicySetID,
			&item.Version,
			&item.Status,
			&item.ApprovalsRequired,
			&item.ApprovalsReceived,
			&item.CreatedBy,
			&item.ApprovedBy,
			&item.CreatedAt,
			&item.SubmittedAt,
			&item.ApprovedAt,
		); err != nil {
			httpx.Error(w, 500, "scan failed")
			return
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) listVersionApprovals(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	rows, err := s.DB.Query(r.Context(), `
		SELECT approver, created_at
		FROM policy_version_approvals
		WHERE policy_set_id=$1 AND version=$2
		ORDER BY created_at ASC
	`, policyID, version)
	if err != nil {
		httpx.Error(w, 500, "query failed")
		return
	}
	defer rows.Close()
	items := make([]versionApproval, 0)
	for rows.Next() {
		var item versionApproval
		if err := rows.Scan(&item.Approver, &item.CreatedAt); err != nil {
			httpx.Error(w, 500, "scan failed")
			return
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) evaluatePolicyVersion(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	version := chi.URLParam(r, "version")
	var req struct {
		Intent      json.RawMessage    `json:"intent"`
		BeliefState models.BeliefState `json:"belief_state_snapshot"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if len(req.Intent) == 0 {
		httpx.Error(w, 400, "intent is required")
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
	var dsl string
	if err := s.DB.QueryRow(r.Context(), `SELECT dsl FROM policy_versions WHERE policy_set_id=$1 AND version=$2`, policyID, version).Scan(&dsl); err != nil {
		httpx.Error(w, 404, "policy version not found")
		return
	}
	res, err := policyeval.Evaluate(dsl, intent, req.BeliefState)
	if err != nil {
		httpx.Error(w, 400, "policy parse error: "+err.Error())
		return
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{
		"policy_set_id":    policyID,
		"version":          version,
		"verdict":          res.Verdict,
		"reason_code":      res.ReasonCode,
		"counterexample":   res.Counterexample,
		"suggested_shield": res.SuggestedShield,
	})
}

func (s *Server) diffPolicyVersions(w http.ResponseWriter, r *http.Request) {
	policyID := chi.URLParam(r, "id")
	fromVersion := r.URL.Query().Get("from")
	toVersion := r.URL.Query().Get("to")
	if fromVersion == "" || toVersion == "" {
		httpx.Error(w, 400, "from and to are required")
		return
	}
	var fromDSL string
	if err := s.DB.QueryRow(r.Context(), `SELECT dsl FROM policy_versions WHERE policy_set_id=$1 AND version=$2`, policyID, fromVersion).Scan(&fromDSL); err != nil {
		httpx.Error(w, 404, "from version not found")
		return
	}
	var toDSL string
	if err := s.DB.QueryRow(r.Context(), `SELECT dsl FROM policy_versions WHERE policy_set_id=$1 AND version=$2`, policyID, toVersion).Scan(&toDSL); err != nil {
		httpx.Error(w, 404, "to version not found")
		return
	}
	added, removed := diffLines(fromDSL, toDSL)
	httpx.WriteJSON(w, 200, map[string]interface{}{
		"policy_set_id": policyID,
		"from":          fromVersion,
		"to":            toVersion,
		"added":         added,
		"removed":       removed,
	})
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kid       string `json:"kid"`
		Signer    string `json:"signer"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.Kid == "" {
		req.Kid = uuid.New().String()
	}
	pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		httpx.Error(w, 400, "invalid public_key")
		return
	}
	_, err = s.DB.Exec(r.Context(), `INSERT INTO key_registry(kid, signer, public_key) VALUES ($1,$2,$3)`, req.Kid, req.Signer, pkBytes)
	if err != nil {
		internalServerError(w, "create key", err)
		return
	}
	httpx.WriteJSON(w, 201, map[string]string{"kid": req.Kid})
}

func (s *Server) getKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	var signer string
	var publicKey []byte
	var status string
	row := s.DB.QueryRow(r.Context(), `SELECT signer, public_key, status FROM key_registry WHERE kid=$1`, kid)
	if err := row.Scan(&signer, &publicKey, &status); err != nil {
		httpx.Error(w, 404, "not found")
		return
	}
	b64 := base64.StdEncoding.EncodeToString(publicKey)
	httpx.WriteJSON(w, 200, map[string]string{"kid": kid, "signer": signer, "public_key": b64, "status": status})
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	type keySummary struct {
		Kid       string    `json:"kid"`
		Signer    string    `json:"signer"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
	}
	var (
		rows pgx.Rows
		err  error
	)
	if statusFilter == "" {
		rows, err = s.DB.Query(r.Context(), `SELECT kid, signer, status, created_at FROM key_registry ORDER BY created_at DESC LIMIT $1`, limit)
	} else {
		rows, err = s.DB.Query(r.Context(), `SELECT kid, signer, status, created_at FROM key_registry WHERE status=$1 ORDER BY created_at DESC LIMIT $2`, statusFilter, limit)
	}
	if err != nil {
		httpx.Error(w, 500, "query failed")
		return
	}
	defer rows.Close()
	items := make([]keySummary, 0, limit)
	for rows.Next() {
		var item keySummary
		if err := rows.Scan(&item.Kid, &item.Signer, &item.Status, &item.CreatedAt); err != nil {
			httpx.Error(w, 500, "scan failed")
			return
		}
		items = append(items, item)
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) patchKey(w http.ResponseWriter, r *http.Request) {
	kid := chi.URLParam(r, "kid")
	var req struct {
		Status    string `json:"status"`
		PublicKey string `json:"public_key,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	status := strings.ToLower(req.Status)
	if status != "active" && status != "revoked" {
		httpx.Error(w, 400, "status must be active or revoked")
		return
	}
	if req.PublicKey != "" {
		pkBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil {
			httpx.Error(w, 400, "invalid public_key")
			return
		}
		cmd, err := s.DB.Exec(r.Context(), `UPDATE key_registry SET status=$1, public_key=$2 WHERE kid=$3`, status, pkBytes, kid)
		if err != nil {
			internalServerError(w, "patch key with public key", err)
			return
		}
		if cmd.RowsAffected() == 0 {
			httpx.Error(w, 404, "not found")
			return
		}
		httpx.WriteJSON(w, 200, map[string]string{"kid": kid, "status": status})
		return
	}
	cmd, err := s.DB.Exec(r.Context(), `UPDATE key_registry SET status=$1 WHERE kid=$2`, status, kid)
	if err != nil {
		internalServerError(w, "patch key status", err)
		return
	}
	if cmd.RowsAffected() == 0 {
		httpx.Error(w, 404, "not found")
		return
	}
	httpx.WriteJSON(w, 200, map[string]string{"kid": kid, "status": status})
}

func nullTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

func internalServerError(w http.ResponseWriter, op string, err error) {
	if err != nil {
		log.Printf("policy %s: %v", op, err)
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

func (s *Server) countApprovals(ctx context.Context, policyID, version string) (int, error) {
	var count int
	if err := s.DB.QueryRow(ctx, `SELECT COUNT(*) FROM policy_version_approvals WHERE policy_set_id=$1 AND version=$2`, policyID, version).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func diffLines(fromDSL, toDSL string) ([]string, []string) {
	fromCount := map[string]int{}
	toCount := map[string]int{}
	for _, line := range strings.Split(fromDSL, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		fromCount[trimmed]++
	}
	for _, line := range strings.Split(toDSL, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		toCount[trimmed]++
	}
	added := make([]string, 0)
	removed := make([]string, 0)
	for line, toN := range toCount {
		fromN := fromCount[line]
		for i := 0; i < toN-fromN; i++ {
			added = append(added, line)
		}
	}
	for line, fromN := range fromCount {
		toN := toCount[line]
		for i := 0; i < fromN-toN; i++ {
			removed = append(removed, line)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
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

func (s *Server) withRoles(h http.HandlerFunc, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(s.AuthMode, "off") {
			h(w, r)
			return
		}
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok {
			httpx.Error(w, 401, "unauthenticated")
			return
		}
		if !auth.HasAnyRole(principal, roles...) {
			httpx.Error(w, 403, "forbidden")
			return
		}
		h(w, r)
	}
}

func (s *Server) internalTokenOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.PolicyAuthHeader == "" || s.PolicyAuthToken == "" {
			httpx.Error(w, 503, "internal auth not configured")
			return
		}
		token := r.Header.Get(s.PolicyAuthHeader)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.PolicyAuthToken)) != 1 {
			httpx.Error(w, 401, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireSubject(r *http.Request) (string, error) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok || strings.TrimSpace(principal.Subject) == "" {
		return "", errors.New("unauthenticated")
	}
	return principal.Subject, nil
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
