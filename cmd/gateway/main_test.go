package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/adapters/palantir"
	"axiom/pkg/auth"
	"axiom/pkg/metrics"
	"axiom/pkg/models"
	"axiom/pkg/policyir"
	"axiom/pkg/ratelimit"
	"axiom/pkg/store"
	"axiom/pkg/stream"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestIsStateFresh(t *testing.T) {
	bs := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 5}, {Source: "erp", AgeSec: 3}}}
	if !isStateFresh(bs, 10, []string{"bank"}) {
		t.Fatal("expected fresh")
	}
	if isStateFresh(bs, 4, []string{"bank", "erp"}) {
		t.Fatal("expected stale by age")
	}
	if isStateFresh(bs, 10, []string{"identity"}) {
		t.Fatal("expected stale by missing source")
	}
}

func TestIsStateFreshZeroMaxStaleness(t *testing.T) {
	bs := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 1}}}
	if isStateFresh(bs, 0, []string{"bank"}) {
		t.Fatal("expected stale when max staleness is zero")
	}
	bs.Sources[0].AgeSec = 0
	if !isStateFresh(bs, 0, []string{"bank"}) {
		t.Fatal("expected fresh when age is zero")
	}
}

func TestIsStateFreshStaleThreshold(t *testing.T) {
	bs := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 61}}}
	if isStateFresh(bs, 60, []string{"bank"}) {
		t.Fatal("expected stale when age exceeds threshold")
	}
}

func TestExecuteSmallBatch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ids, _ := body["ids"].([]interface{})
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"count": len(ids)})
	}))
	defer srv.Close()

	s := &Server{
		OntologyExecutor: palantir.HTTPExecutor{Endpoint: srv.URL},
	}
	payload := map[string]interface{}{"op": "delete", "ids": makeIDs(240)}
	raw, _ := json.Marshal(payload)

	out, err := s.executeSmallBatch(context.Background(), "ONTOLOGY_ACTION", raw, 100)
	if err != nil {
		t.Fatalf("executeSmallBatch error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 chunks, got %d", calls)
	}
	var parsed map[string]interface{}
	_ = json.Unmarshal(out, &parsed)
	chunks, ok := parsed["chunks"].([]interface{})
	if !ok || len(chunks) != 3 {
		t.Fatalf("unexpected chunks payload: %v", parsed)
	}
}

func TestExecuteSmallBatchPartialFailures(t *testing.T) {
	calls := 0
	s := &Server{
		OntologyExecutor: execFunc(func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
			calls++
			var body map[string]interface{}
			_ = json.Unmarshal(payload, &body)
			ids, _ := body["ids"].([]interface{})
			if len(ids) == 1 {
				return nil, errors.New("forced chunk failure")
			}
			out, _ := json.Marshal(map[string]any{"count": len(ids)})
			return out, nil
		}),
	}
	raw, _ := json.Marshal(map[string]any{"ids": []string{"a", "b", "c"}})
	out, err := s.executeSmallBatch(context.Background(), "ONTOLOGY_ACTION", raw, 2)
	if err != nil {
		t.Fatalf("executeSmallBatch should continue on chunk failures: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 chunk calls, got %d", calls)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if len(parsed["allow_ids"].([]any)) != 2 {
		t.Fatalf("expected 2 allow_ids, got %v", parsed["allow_ids"])
	}
	if len(parsed["deny_ids"].([]any)) != 1 {
		t.Fatalf("expected 1 deny_id, got %v", parsed["deny_ids"])
	}
}

func makeIDs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "id")
	}
	return out
}

func TestApprovalsRequiredFromClaims(t *testing.T) {
	tests := []struct {
		name   string
		claims []models.Claim
		want   int
	}{
		{
			name: "default one",
			claims: []models.Claim{
				{Type: "SoD", Statement: "actor.id != approver.id"},
			},
			want: 1,
		},
		{
			name: "two person rule",
			claims: []models.Claim{
				{Type: "TwoPersonRule", Statement: "approvals_required >= 2"},
			},
			want: 2,
		},
		{
			name: "max over claims",
			claims: []models.Claim{
				{Type: "Approval", Statement: "approvals_required = 2"},
				{Type: "TwoPersonRule", Statement: "approvals_required >= 3"},
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := approvalsRequiredFromClaims(tt.claims)
			if got != tt.want {
				t.Fatalf("expected %d, got %d", tt.want, got)
			}
		})
	}
}

func TestShouldPersistDecision(t *testing.T) {
	if shouldPersistDecision("DEFER") {
		t.Fatal("DEFER must not be persisted")
	}
	if !shouldPersistDecision("ALLOW") {
		t.Fatal("ALLOW should be persisted")
	}
	if !shouldPersistDecision("SHIELD") {
		t.Fatal("SHIELD should be persisted")
	}
}

func TestAuthorizeIntentTenantMismatch(t *testing.T) {
	s := &Server{AuthMode: "oidc_hs256", StrictActorBinding: true}
	intent := models.ActionIntent{Actor: models.Actor{ID: "actor-1", Tenant: "tenant-b"}, Target: models.Target{Domain: "finance"}}
	cert := models.ActionCert{}
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
	principal := auth.Principal{Subject: "actor-1", Tenant: "tenant-a", Roles: []string{"operator"}}
	req = req.WithContext(auth.WithPrincipal(req.Context(), principal))
	ok, reason := s.authorizeIntent(req, intent, cert, nil)
	if ok {
		t.Fatal("expected tenant mismatch to deny")
	}
	if reason != "ACCESS_TENANT_MISMATCH" {
		t.Fatalf("unexpected reason: %s", reason)
	}
}

func TestTenantScope(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256"}
	req := httptest.NewRequest(http.MethodGet, "/v1/escrows", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "user-1",
		Tenant:  "tenant-a",
		Roles:   []string{"operator"},
	}))
	tenant, scoped := s.tenantScope(req.Context())
	if !scoped || tenant != "tenant-a" {
		t.Fatalf("expected tenant scope tenant-a, got %v %s", scoped, tenant)
	}
	reqElevated := httptest.NewRequest(http.MethodGet, "/v1/escrows", nil)
	reqElevated = reqElevated.WithContext(auth.WithPrincipal(reqElevated.Context(), auth.Principal{
		Subject: "admin",
		Tenant:  "tenant-a",
		Roles:   []string{"securityadmin"},
	}))
	tenant, scoped = s.tenantScope(reqElevated.Context())
	if scoped || tenant != "" {
		t.Fatalf("expected unscoped access for elevated role, got %v %s", scoped, tenant)
	}
}

func TestResolveTenant(t *testing.T) {
	intent := models.ActionIntent{Actor: models.Actor{Tenant: "tenant-a"}}
	principal := auth.Principal{Tenant: "tenant-b"}
	if got := resolveTenant(intent, principal); got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %s", got)
	}
	intent.Actor.Tenant = ""
	if got := resolveTenant(intent, principal); got != "tenant-b" {
		t.Fatalf("expected tenant-b, got %s", got)
	}
}

func TestAttachBatchPartition(t *testing.T) {
	s := &Server{}
	resp := &models.GatewayResponse{Verdict: "DENY", ReasonCode: "SOD_FAIL"}
	intent := models.ActionIntent{
		Target: models.Target{
			Scope:     "batch",
			ObjectIDs: []string{"a", "b"},
		},
	}
	s.attachBatchPartition(resp, intent, nil, nil)
	if resp.Batch == nil {
		t.Fatal("expected batch partition to be attached")
	}
	if resp.Batch.Total != 2 {
		t.Fatalf("expected total=2, got %d", resp.Batch.Total)
	}
	if len(resp.Batch.DenyIDs) != 2 {
		t.Fatalf("expected deny ids, got %#v", resp.Batch.DenyIDs)
	}
	if len(resp.Batch.Items) != 2 {
		t.Fatalf("expected per-item verdicts, got %#v", resp.Batch.Items)
	}
}

func TestTightenBatchVerdict(t *testing.T) {
	partition := &models.BatchPartition{
		Scope:    "batch",
		Total:    3,
		AllowIDs: []string{"a"},
		DenyIDs:  []string{"b"},
	}
	verdict, sh, reason := tightenBatchVerdict("ALLOW", nil, "OK", partition)
	if verdict != "SHIELD" || sh == nil || sh.Type != "SMALL_BATCH" || reason != "BATCH_POLICY_PARTIAL" {
		t.Fatalf("unexpected tighten result verdict=%s shield=%+v reason=%s", verdict, sh, reason)
	}

	partition = &models.BatchPartition{
		Scope:     "batch",
		Total:     2,
		EscrowIDs: []string{"a", "b"},
	}
	verdict, sh, reason = tightenBatchVerdict("ALLOW", nil, "OK", partition)
	if verdict != "ESCROW" || sh == nil || sh.Type != "REQUIRE_APPROVAL" || reason != "BATCH_POLICY_ESCROW" {
		t.Fatalf("unexpected escrow tighten result verdict=%s shield=%+v reason=%s", verdict, sh, reason)
	}
}

func TestEvaluateBatchPolicyPartitionRequireApproval(t *testing.T) {
	s := &Server{}
	policy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:         "Role_guard",
				Requires:   []string{`actor.role contains "FinanceOperator"`},
				ElseShield: `shield("REQUIRE_APPROVAL")`,
			},
		},
	}
	intent := models.ActionIntent{
		Actor: models.Actor{
			ID:     "u-1",
			Roles:  []string{"Viewer"},
			Tenant: "tenant-a",
		},
		Target: models.Target{
			Domain:    "finance",
			Scope:     "batch",
			ObjectIDs: []string{"a", "b"},
		},
		Operation: models.Operation{
			Name:   "bulk_update",
			Params: json.RawMessage(`{"mode":"safe"}`),
		},
	}
	actionPayload := json.RawMessage(`{"ids":["a","b"]}`)
	partition := s.evaluateBatchPolicyPartition(policy, intent, models.BeliefState{}, actionPayload)
	if partition == nil {
		t.Fatal("expected partition")
	}
	if len(partition.EscrowIDs) != 2 || len(partition.AllowIDs) != 0 || len(partition.DenyIDs) != 0 {
		t.Fatalf("unexpected partition: %+v", partition)
	}
}

func TestFilterBatchActionPayloadByIDs(t *testing.T) {
	raw := json.RawMessage(`{"op":"bulk_update","ids":["a","b","c"]}`)
	out, ok := filterBatchActionPayloadByIDs(raw, []string{"b", "c"})
	if !ok {
		t.Fatal("expected filtered payload")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("decode filtered payload: %v", err)
	}
	ids, ok := parsed["ids"].([]interface{})
	if !ok || len(ids) != 2 {
		t.Fatalf("unexpected filtered ids: %v", parsed["ids"])
	}
}

func TestValidateBatchPayloadIntegrity(t *testing.T) {
	intent := models.ActionIntent{
		Target: models.Target{
			Scope:     "batch",
			ObjectIDs: []string{"a", "b"},
		},
	}
	if reason, _ := validateBatchPayloadIntegrity(intent, json.RawMessage(`{"ids":["b","a"]}`)); reason != "" {
		t.Fatalf("expected valid batch integrity, got reason=%s", reason)
	}
	if reason, _ := validateBatchPayloadIntegrity(intent, json.RawMessage(`{"ids":["a","c"]}`)); reason != "BATCH_IDS_MISMATCH" {
		t.Fatalf("expected mismatch reason, got %s", reason)
	}
	if reason, _ := validateBatchPayloadIntegrity(intent, json.RawMessage(`{"ids":"bad"}`)); reason != "BATCH_IDS_INVALID" {
		t.Fatalf("expected invalid ids reason, got %s", reason)
	}
	noIntentIDs := models.ActionIntent{
		Target: models.Target{
			Scope:     "batch",
			ObjectIDs: nil,
		},
	}
	if reason, _ := validateBatchPayloadIntegrity(noIntentIDs, nil); reason != "BATCH_IDS_MISSING" {
		t.Fatalf("expected missing ids reason, got %s", reason)
	}
}

func TestMergeBatchExecutionPartition(t *testing.T) {
	partition := &models.BatchPartition{
		Scope:     "batch",
		Total:     3,
		AllowIDs:  []string{"a", "b"},
		EscrowIDs: []string{"c"},
		Items: []models.BatchItemVerdict{
			{ObjectID: "a", Verdict: "ALLOW"},
			{ObjectID: "b", Verdict: "ALLOW"},
			{ObjectID: "c", Verdict: "ESCROW"},
		},
	}
	result := json.RawMessage(`{"allow_ids":["a"],"deny_ids":["b"]}`)
	mergeBatchExecutionPartition(partition, result, &models.SuggestedShield{Type: "SMALL_BATCH"})
	if len(partition.AllowIDs) != 1 || !containsString(partition.AllowIDs, "a") {
		t.Fatalf("unexpected allow IDs: %+v", partition.AllowIDs)
	}
	if !containsString(partition.DenyIDs, "b") {
		t.Fatalf("unexpected deny IDs: %+v", partition.DenyIDs)
	}
	if !containsString(partition.EscrowIDs, "c") {
		t.Fatalf("unexpected escrow IDs: %+v", partition.EscrowIDs)
	}
}

func TestIsCriticalReason(t *testing.T) {
	if !isCriticalReason("SOD_FAIL") {
		t.Fatal("SOD_FAIL must be critical")
	}
	if !isCriticalReason("access_denied") {
		t.Fatal("ACCESS_* must be critical")
	}
	if isCriticalReason("STATE_STALE") {
		t.Fatal("STATE_STALE must not be critical")
	}
}

func TestIsCriticalIncident(t *testing.T) {
	if !isCriticalIncident("DENY", "BUDGET_FAIL") {
		t.Fatal("DENY must be incident")
	}
	if isCriticalIncident("DENY", "CERT_EXPIRED") {
		t.Fatal("CERT_EXPIRED deny should not open incident")
	}
	if !isCriticalIncident("SHIELD", "SOD_FAIL") {
		t.Fatal("critical shield should open incident")
	}
}

func TestClientIPTrustedProxy(t *testing.T) {
	s := &Server{TrustedProxyCIDRs: parseCIDRs("127.0.0.1/32")}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.2")
	if got := s.clientIP(req); got != "10.0.0.2" {
		t.Fatalf("expected forwarded ip, got %s", got)
	}
	req.RemoteAddr = "10.0.0.9:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.4")
	if got := s.clientIP(req); got != "10.0.0.9" {
		t.Fatalf("expected remote ip, got %s", got)
	}
}

func TestParseDomainRoleAllow(t *testing.T) {
	cfg := parseDomainRoleAllow("finance:financeoperator,financemanager;hr:hroperator")
	if _, ok := cfg["finance"]["financeoperator"]; !ok {
		t.Fatal("missing financeoperator role")
	}
	if _, ok := cfg["finance"]["financemanager"]; !ok {
		t.Fatal("missing financemanager role")
	}
	if _, ok := cfg["hr"]["hroperator"]; !ok {
		t.Fatal("missing hroperator role")
	}
}

func TestAuthorizeIntentABAC(t *testing.T) {
	s := &Server{
		AuthMode:           "oidc_rs256",
		DomainRoleAllow:    parseDomainRoleAllow("finance:financeoperator"),
		StrictActorBinding: true,
	}
	intent := models.ActionIntent{
		Actor:  models.Actor{ID: "user-1", Tenant: "acme"},
		Target: models.Target{Domain: "finance"},
	}
	baseReq := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
	req := baseReq.WithContext(auth.WithPrincipal(baseReq.Context(), auth.Principal{
		Subject: "user-1",
		Tenant:  "acme",
		Roles:   []string{"FinanceOperator"},
	}))
	ok, reason := s.authorizeIntent(req, intent, models.ActionCert{}, nil)
	if !ok || reason != "" {
		t.Fatalf("expected authorize ok, got ok=%v reason=%s", ok, reason)
	}

	reqMismatch := baseReq.WithContext(auth.WithPrincipal(baseReq.Context(), auth.Principal{
		Subject: "user-2",
		Tenant:  "acme",
		Roles:   []string{"FinanceOperator"},
	}))
	ok, reason = s.authorizeIntent(reqMismatch, intent, models.ActionCert{}, nil)
	if ok || reason != "ACCESS_ACTOR_MISMATCH" {
		t.Fatalf("expected actor mismatch, got ok=%v reason=%s", ok, reason)
	}

	reqTenantMismatch := baseReq.WithContext(auth.WithPrincipal(baseReq.Context(), auth.Principal{
		Subject: "user-1",
		Tenant:  "other",
		Roles:   []string{"FinanceOperator"},
	}))
	ok, reason = s.authorizeIntent(reqTenantMismatch, intent, models.ActionCert{}, nil)
	if ok || reason != "ACCESS_TENANT_MISMATCH" {
		t.Fatalf("expected tenant mismatch, got ok=%v reason=%s", ok, reason)
	}
}

func TestAuthorizeIntentRoleBinding(t *testing.T) {
	s := &Server{
		AuthMode:           "oidc_rs256",
		StrictActorBinding: true,
	}
	intent := models.ActionIntent{
		Actor: models.Actor{
			ID:     "user-1",
			Tenant: "acme",
			Roles:  []string{"FinanceOperator"},
		},
		Target: models.Target{Domain: "finance"},
	}
	baseReq := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
	req := baseReq.WithContext(auth.WithPrincipal(baseReq.Context(), auth.Principal{
		Subject: "user-1",
		Tenant:  "acme",
		Roles:   []string{"FinanceOperator", "Operator"},
	}))
	ok, reason := s.authorizeIntent(req, intent, models.ActionCert{}, nil)
	if !ok || reason != "" {
		t.Fatalf("expected role subset to pass, ok=%v reason=%s", ok, reason)
	}

	intent.Actor.Roles = []string{"SecurityAdmin"}
	ok, reason = s.authorizeIntent(req, intent, models.ActionCert{}, nil)
	if ok || reason != "ACCESS_ROLE_MISMATCH" {
		t.Fatalf("expected role mismatch deny, ok=%v reason=%s", ok, reason)
	}
}

func TestHashIdentityStable(t *testing.T) {
	a := hashIdentity("operator-1")
	b := hashIdentity("operator-1")
	c := hashIdentity("operator-2")
	if a == "" || b == "" || c == "" {
		t.Fatal("hash must not be empty")
	}
	if a != b {
		t.Fatalf("hash must be stable, a=%s b=%s", a, b)
	}
	if a == c {
		t.Fatalf("different input must produce different hash")
	}
}

func TestCheckRateLimit(t *testing.T) {
	s := &Server{
		RateLimiter:        ratelimit.NewInMemory(time.Minute),
		RateLimitEnabled:   true,
		RateLimitPerMinute: 1,
		RateLimitWindow:    time.Minute,
	}
	intent := models.ActionIntent{
		ActionType: "TOOL_CALL",
		Actor: models.Actor{
			ID:     "agent-1",
			Tenant: "tenant-a",
		},
		Target: models.Target{
			Domain: "finance",
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
	blocked, _ := s.checkRateLimit(req, intent, nil)
	if blocked {
		t.Fatal("first request must pass rate limit")
	}
	blocked, retryAfter := s.checkRateLimit(req, intent, nil)
	if !blocked {
		t.Fatal("second request must be rate limited")
	}
	if retryAfter <= 0 {
		t.Fatalf("retry_after should be positive, got %d", retryAfter)
	}
}

func TestCheckRateLimitRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis run: %v", err)
	}
	defer mr.Close()
	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer redisClient.Close()
	s := &Server{
		RateLimiter:        ratelimit.NewRedis(redisClient, time.Minute),
		RateLimitEnabled:   true,
		RateLimitPerMinute: 1,
		RateLimitWindow:    time.Minute,
		Redis:              redisClient,
	}
	intent := models.ActionIntent{
		ActionType: "TOOL_CALL",
		Actor:      models.Actor{ID: "agent-redis", Tenant: "tenant-a"},
		Target:     models.Target{Domain: "finance"},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", nil)
	blocked, _ := s.checkRateLimit(req, intent, nil)
	if blocked {
		t.Fatal("first redis request must pass rate limit")
	}
	blocked, retryAfter := s.checkRateLimit(req, intent, nil)
	if !blocked {
		t.Fatal("second redis request must be rate limited")
	}
	if retryAfter <= 0 {
		t.Fatalf("retry_after should be positive, got %d", retryAfter)
	}
}

func TestScopedIdempotencyKey(t *testing.T) {
	if got := scopedIdempotencyKey("", "", "k-1"); got != "k-1" {
		t.Fatalf("unexpected unscoped key: %s", got)
	}
	if got := scopedIdempotencyKey("", "Agent-1", "k-1"); got != "agent-1|k-1" {
		t.Fatalf("unexpected scoped key: %s", got)
	}
	if got := scopedIdempotencyKey("Tenant-A", "Agent-1", "k-1"); got != "tenant-a|agent-1|k-1" {
		t.Fatalf("unexpected tenant scoped key: %s", got)
	}
}

func TestScopedNonceKey(t *testing.T) {
	if got := scopedNonceKey("", "", "n-1"); got != "nonce:n-1" {
		t.Fatalf("unexpected nonce key: %s", got)
	}
	if got := scopedNonceKey("", "Agent-1", "n-1"); got != "nonce:agent-1:n-1" {
		t.Fatalf("unexpected actor-scoped nonce key: %s", got)
	}
	if got := scopedNonceKey("Tenant-A", "Agent-1", "n-1"); got != "nonce:tenant-a:agent-1:n-1" {
		t.Fatalf("unexpected tenant-scoped nonce key: %s", got)
	}
}

func TestWithRolesRequiresTenantForNonElevated(t *testing.T) {
	s := &Server{AuthMode: "oidc_hs256"}
	req := httptest.NewRequest(http.MethodGet, "/v1/verdicts", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "user-1",
		Roles:   []string{"operator"},
	}))
	rr := httptest.NewRecorder()
	handler := s.withRoles(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, "operator")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when tenant missing for non-elevated role, got %d", rr.Code)
	}
}

func TestHasRollbackPlanStrict(t *testing.T) {
	if hasRollbackPlan(models.ActionCert{RollbackPlan: models.Rollback{Type: "NONE"}}) {
		t.Fatal("NONE rollback must not be accepted")
	}
	if hasRollbackPlan(models.ActionCert{RollbackPlan: models.Rollback{Type: "NOOP"}}) {
		t.Fatal("NOOP rollback must not be accepted")
	}
	if !hasRollbackPlan(models.ActionCert{RollbackPlan: models.Rollback{Type: "ESCROW", Steps: []string{"await approval"}}}) {
		t.Fatal("ESCROW rollback with steps should be accepted")
	}
}

func TestAsInt64Uint64Overflow(t *testing.T) {
	if _, ok := asInt64(uint64(math.MaxUint64)); ok {
		t.Fatal("expected overflow conversion to fail")
	}
	got, ok := asInt64(uint64(math.MaxInt64))
	if !ok || got != math.MaxInt64 {
		t.Fatalf("expected max int64 conversion, got %d ok=%v", got, ok)
	}
}

func TestPolicyCacheSetGetExpiry(t *testing.T) {
	cache := newPolicyCache(10 * time.Millisecond)
	if cache.ttl != 10*time.Millisecond {
		t.Fatalf("expected custom ttl, got %s", cache.ttl)
	}
	cache.Set("empty", nil)
	if _, ok := cache.Get("empty"); ok {
		t.Fatal("nil policy should never be cached")
	}
	policy := &policyir.PolicySetIR{ID: "finance", Version: "v1"}
	cache.Set("finance@v1", policy)
	got, ok := cache.Get("finance@v1")
	if !ok || got == nil || got.ID != "finance" {
		t.Fatalf("expected cached policy, got=%v ok=%v", got, ok)
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := cache.Get("finance@v1"); ok {
		t.Fatal("expected cache entry to expire")
	}
}

func TestPolicyCacheDefaultTTL(t *testing.T) {
	cache := newPolicyCache(0)
	if cache.ttl != 30*time.Second {
		t.Fatalf("expected default ttl 30s, got %s", cache.ttl)
	}
}

func TestParseIntentTimeAndShouldExpireDefer(t *testing.T) {
	fallback := time.Date(2026, 2, 5, 10, 0, 0, 0, time.UTC)
	if got := parseIntentTime("", fallback); !got.Equal(fallback) {
		t.Fatalf("expected fallback for empty time, got %s", got)
	}
	if got := parseIntentTime("invalid", fallback); !got.Equal(fallback) {
		t.Fatalf("expected fallback for invalid time, got %s", got)
	}
	valid := "2026-02-05T10:01:00+03:00"
	got := parseIntentTime(valid, fallback)
	want := time.Date(2026, 2, 5, 7, 1, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("expected parsed UTC %s, got %s", want, got)
	}
	now := fallback.Add(2 * time.Minute)
	if !shouldExpireDefer(30*time.Second, fallback, now) {
		t.Fatal("expected defer to expire")
	}
	if shouldExpireDefer(0, fallback, now) {
		t.Fatal("maxDefer <= 0 should never expire")
	}
	if shouldExpireDefer(time.Minute, time.Time{}, now) {
		t.Fatal("zero request time should never expire")
	}
	if shouldExpireDefer(time.Minute, now, fallback) {
		t.Fatal("time reversal should never expire")
	}
}

func TestCallVerifierPaths(t *testing.T) {
	receivedSnapshot := false
	verifySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if snapshotID, ok := payload["snapshot_id"].(string); ok && snapshotID == "snap-1" {
			receivedSnapshot = true
		}
		_ = json.NewEncoder(w).Encode(models.VerifierResponse{Verdict: "ALLOW", ReasonCode: "OK"})
	}))
	defer verifySrv.Close()
	s := &Server{
		HTTPClient:  verifySrv.Client(),
		VerifierURL: verifySrv.URL,
	}
	s.Config.MaxVerifyTime = 200 * time.Millisecond
	resp, unavailable := s.callVerifier(context.Background(), json.RawMessage(`{"intent_id":"i-1"}`), json.RawMessage(`{"policy_version":"v1"}`), models.BeliefState{SnapshotID: "snap-1"}, false)
	if unavailable {
		t.Fatal("expected verifier response, got unavailable")
	}
	if resp == nil || resp.Verdict != "ALLOW" || resp.ReasonCode != "OK" {
		t.Fatalf("unexpected verifier response: %#v", resp)
	}
	if !receivedSnapshot {
		t.Fatal("expected snapshot_id to be forwarded to verifier")
	}

	errorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer errorSrv.Close()
	s.VerifierURL = errorSrv.URL
	if _, unavailable := s.callVerifier(context.Background(), json.RawMessage(`{}`), json.RawMessage(`{}`), models.BeliefState{}, true); !unavailable {
		t.Fatal("expected unavailable=true for non-200 verifier response")
	}

	badJSONSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer badJSONSrv.Close()
	s.VerifierURL = badJSONSrv.URL
	if _, unavailable := s.callVerifier(context.Background(), json.RawMessage(`{}`), json.RawMessage(`{}`), models.BeliefState{}, false); !unavailable {
		t.Fatal("expected unavailable=true for malformed verifier JSON")
	}
}

func TestExecuteShieldMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	defer srv.Close()
	s := &Server{
		ToolExecutor:     palantir.HTTPExecutor{Endpoint: srv.URL, Client: srv.Client()},
		OntologyExecutor: palantir.HTTPExecutor{Endpoint: srv.URL, Client: srv.Client()},
	}
	toolOut, err := s.executeShieldMode(context.Background(), "TOOL_CALL", "READ_ONLY", json.RawMessage(`{"name":"deploy"}`), nil)
	if err != nil {
		t.Fatalf("tool shield execute failed: %v", err)
	}
	var toolResp map[string]interface{}
	if err := json.Unmarshal(toolOut, &toolResp); err != nil {
		t.Fatalf("decode tool response: %v", err)
	}
	if toolResp["mode"] != "READ_ONLY" {
		t.Fatalf("expected READ_ONLY mode, got %v", toolResp["mode"])
	}

	ontOut, err := s.executeShieldMode(context.Background(), "ONTOLOGY_ACTION", "DRY_RUN", nil, json.RawMessage(`{"op":"update"}`))
	if err != nil {
		t.Fatalf("ontology shield execute failed: %v", err)
	}
	var ontResp map[string]interface{}
	if err := json.Unmarshal(ontOut, &ontResp); err != nil {
		t.Fatalf("decode ontology response: %v", err)
	}
	if ontResp["mode"] != "DRY_RUN" {
		t.Fatalf("expected DRY_RUN mode, got %v", ontResp["mode"])
	}

	t.Run("strict_no_commit_does_not_call_upstream", func(t *testing.T) {
		called := false
		s := &Server{
			StrictShieldNoCommit: true,
			ToolExecutor: execFunc(func(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
				called = true
				return nil, errors.New("must not be called")
			}),
		}
		out, err := s.executeShieldMode(context.Background(), "TOOL_CALL", "READ_ONLY", json.RawMessage(`{"name":"deploy"}`), nil)
		if err != nil {
			t.Fatalf("strict shield should return local report, got %v", err)
		}
		if called {
			t.Fatal("upstream executor must not be called in strict no-commit mode")
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(out, &resp); err != nil {
			t.Fatalf("decode strict shield response: %v", err)
		}
		if resp["commit_blocked"] != true || resp["upstream_called"] != false {
			t.Fatalf("expected strict no-commit report, got %#v", resp)
		}
	})
}

func TestAuthHeaderMap(t *testing.T) {
	if got := authHeaderMap("", "x"); got != nil {
		t.Fatalf("expected nil headers, got %#v", got)
	}
	if got := authHeaderMap("X-Test", ""); got != nil {
		t.Fatalf("expected nil headers, got %#v", got)
	}
	got := authHeaderMap("X-Test", "token")
	if got["X-Test"] != "token" {
		t.Fatalf("unexpected header map: %#v", got)
	}
}

func TestMetricsMiddlewareObserve(t *testing.T) {
	s := &Server{Metrics: metrics.NewRegistry()}
	handler := s.metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	snap := s.Metrics.Snapshot()
	stat, ok := snap.Endpoints["POST /v1/execute"]
	if !ok {
		t.Fatalf("expected metrics endpoint entry, snapshot=%#v", snap.Endpoints)
	}
	if stat.Count != 1 || stat.LastStatusCode != http.StatusCreated {
		t.Fatalf("unexpected endpoint stats: %#v", stat)
	}
}

func TestMarshalCounterexample(t *testing.T) {
	if got := marshalCounterexample(nil); got != nil {
		t.Fatalf("expected nil for nil counterexample, got %s", string(got))
	}
	cx := &models.Counterexample{MinimalFacts: []string{"bank.age_sec=61"}, FailedAxioms: []string{"Fresh_bank_feed"}}
	raw := marshalCounterexample(cx)
	var parsed models.Counterexample
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal counterexample failed: %v", err)
	}
	if len(parsed.MinimalFacts) != 1 || parsed.MinimalFacts[0] != "bank.age_sec=61" {
		t.Fatalf("unexpected parsed counterexample: %#v", parsed)
	}
}

func TestWsOriginPatternsAndPolicyCacheKey(t *testing.T) {
	if wsOriginPatterns("  ") != nil {
		t.Fatal("expected nil for empty origin list")
	}
	origins := wsOriginPatterns("https://a.example, https://b.example ")
	if len(origins) != 2 || origins[0] != "https://a.example" || origins[1] != "https://b.example" {
		t.Fatalf("unexpected origins: %#v", origins)
	}
	if got := policyCacheKey(" Finance ", " V17 "); got != "finance@v17" {
		t.Fatalf("unexpected policy cache key: %s", got)
	}
}

func TestApprovalPolicyAndParseAttributes(t *testing.T) {
	s := &Server{AuthMode: "oidc_hs256"}
	policy := &policyir.PolicySetIR{Approvals: &policyir.ApprovalPolicy{
		Required:   3,
		Roles:      []string{"FinanceManager"},
		EnforceSoD: false,
		ExpiresIn:  2 * time.Hour,
	}}
	ap := s.approvalPolicy(policy, 1)
	if ap.Required != 3 || ap.EnforceSoD || len(ap.Roles) != 1 || ap.ExpiresIn != 2*time.Hour {
		t.Fatalf("unexpected approval policy: %#v", ap)
	}
	s.AuthMode = "off"
	ap = s.approvalPolicy(policy, 0)
	if ap.Required != 3 || len(ap.Roles) != 0 {
		t.Fatalf("expected roles cleared in auth off mode: %#v", ap)
	}
	attrs := parseAttributes([]byte(`{"attributes":{"risk":2,"active":true,"region":"eu","meta":{"k":"v"}}}`))
	if attrs["risk"] != "2" || attrs["active"] != "true" || attrs["region"] != "eu" {
		t.Fatalf("unexpected parsed attrs: %#v", attrs)
	}
	if !strings.Contains(attrs["meta"], `"k":"v"`) {
		t.Fatalf("expected serialized map for meta, got %s", attrs["meta"])
	}
}

func TestResolveABACAttributesCaching(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"attributes":{"region":"eu","risk":2}}`))
	}))
	defer srv.Close()
	s := &Server{
		HTTPClient:       srv.Client(),
		ABACAttrURL:      srv.URL,
		ABACAttrCacheTTL: time.Minute,
		Cache:            store.NewMemoryCache(),
	}
	intent := models.ActionIntent{
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance"},
		Operation:  models.Operation{Name: "pay_invoice"},
	}
	principal := auth.Principal{Subject: "u1", Tenant: "acme"}
	attrs1 := s.resolveABACAttributes(context.Background(), principal, intent)
	attrs2 := s.resolveABACAttributes(context.Background(), principal, intent)
	if attrs1["region"] != "eu" || attrs1["risk"] != "2" {
		t.Fatalf("unexpected attrs1: %#v", attrs1)
	}
	if attrs2["region"] != "eu" || attrs2["risk"] != "2" {
		t.Fatalf("unexpected attrs2: %#v", attrs2)
	}
	if hits != 1 {
		t.Fatalf("expected one upstream call due cache, got %d", hits)
	}
}

func TestParseTwoPhaseAndExecuteWithTwoPhase(t *testing.T) {
	raw := json.RawMessage(`{"two_phase":{"prepare":{"step":"prepare"},"commit":{"step":"commit"},"rollback":{"step":"rollback"}}}`)
	prepare, commit, rollback, ok := parseTwoPhasePayload(raw)
	if !ok || len(commit) == 0 {
		t.Fatalf("expected valid two phase payload: ok=%v commit=%s", ok, string(commit))
	}
	if string(prepare) == "" || string(rollback) == "" {
		t.Fatalf("expected prepare and rollback payloads, got prepare=%s rollback=%s", string(prepare), string(rollback))
	}
	if _, _, _, ok := parseTwoPhasePayload(json.RawMessage(`{"two_phase":{"prepare":{}}}`)); ok {
		t.Fatal("expected invalid two phase payload when commit is missing")
	}

	seen := make([]string, 0, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		step, _ := payload["step"].(string)
		if step != "" {
			seen = append(seen, step)
		}
		if step == "commit-fail" {
			http.Error(w, "fail", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	s := &Server{ToolExecutor: palantir.HTTPExecutor{Endpoint: srv.URL, Client: srv.Client()}}

	_, err := s.executeWithTwoPhase(context.Background(), "TOOL_CALL", json.RawMessage(`{"two_phase":{"prepare":{"step":"prepare"},"commit":{"step":"commit-fail"},"rollback":{"step":"rollback"}}}`))
	if err == nil {
		t.Fatal("expected commit failure")
	}
	if !sliceContains(seen, "prepare") || !sliceContains(seen, "commit-fail") || !sliceContains(seen, "rollback") {
		t.Fatalf("expected prepare/commit/rollback sequence, got %#v", seen)
	}
}

func TestExecuteEscrowActionCompensation(t *testing.T) {
	seen := make([]string, 0, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if step, _ := payload["step"].(string); step != "" {
			seen = append(seen, step)
			if step == "execute-fail" {
				http.Error(w, "fail", http.StatusInternalServerError)
				return
			}
		}
		if action, _ := payload["action"].(string); action != "" {
			seen = append(seen, action)
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	s := &Server{ToolExecutor: palantir.HTTPExecutor{Endpoint: srv.URL, Client: srv.Client()}}
	intent := models.ActionIntent{IntentID: "intent-1", Target: models.Target{Domain: "finance"}}
	cert := models.ActionCert{
		RollbackPlan: models.Rollback{Type: "COMPENSATING_ACTION", Steps: []string{"undo-op"}},
	}
	_, compensated, err := s.executeEscrowAction(context.Background(), "TOOL_CALL", json.RawMessage(`{"step":"execute-fail"}`), intent, cert)
	if err == nil {
		t.Fatal("expected primary execution failure")
	}
	if !compensated {
		t.Fatal("expected compensation to run")
	}
	if !sliceContains(seen, "undo-op") {
		t.Fatalf("expected compensation step in calls, got %#v", seen)
	}
}

func TestRunCompensationAndBuildPayload(t *testing.T) {
	s := &Server{}
	if err := s.runCompensation(context.Background(), "TOOL_CALL", models.ActionIntent{}, models.ActionCert{
		RollbackPlan: models.Rollback{Type: "ESCROW", Steps: []string{"undo"}},
	}); err == nil {
		t.Fatal("expected plan type validation error")
	}
	if err := s.runCompensation(context.Background(), "TOOL_CALL", models.ActionIntent{}, models.ActionCert{
		RollbackPlan: models.Rollback{Type: "COMPENSATING_ACTION"},
	}); err == nil {
		t.Fatal("expected empty steps error")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	s.ToolExecutor = palantir.HTTPExecutor{Endpoint: srv.URL, Client: srv.Client()}
	intent := models.ActionIntent{IntentID: "intent-2", Target: models.Target{Domain: "hr"}}
	err := s.runCompensation(context.Background(), "TOOL_CALL", intent, models.ActionCert{
		RollbackPlan: models.Rollback{
			Type:  "COMPENSATING_ACTION",
			Steps: []string{"undo-step", `{"action":"undo-json"}`},
		},
	})
	if err != nil {
		t.Fatalf("expected successful compensation, got %v", err)
	}

	if _, err := buildCompensationPayload("TOOL_CALL", intent, ""); err == nil {
		t.Fatal("expected empty step error")
	}
	rawJSON, err := buildCompensationPayload("TOOL_CALL", intent, `{"action":"undo"}`)
	if err != nil || string(rawJSON) != `{"action":"undo"}` {
		t.Fatalf("expected passthrough json payload, got %s err=%v", string(rawJSON), err)
	}
	rawBuilt, err := buildCompensationPayload("ONTOLOGY_ACTION", intent, "undo-name")
	if err != nil {
		t.Fatalf("buildCompensationPayload failed: %v", err)
	}
	var payload map[string]interface{}
	_ = json.Unmarshal(rawBuilt, &payload)
	if payload["action"] != "undo-name" || payload["ontology"] != "hr" {
		t.Fatalf("unexpected ontology compensation payload: %#v", payload)
	}
}

type failingReadCloser struct{}

func (failingReadCloser) Read(_ []byte) (int, error) { return 0, errors.New("boom") }
func (failingReadCloser) Close() error               { return nil }

func TestReadRequestBodyAndLimitMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/execute", nil)
	req.Body = failingReadCloser{}
	rr := httptest.NewRecorder()
	if _, ok := readRequestBody(rr, req); ok {
		t.Fatal("expected body read failure")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid body, got %d", rr.Code)
	}

	s := &Server{MaxRequestBodyBytes: 8}
	handler := s.limitRequestBodyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := readRequestBody(w, r)
		if ok {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	req = httptest.NewRequest(http.MethodPost, "/v1/execute", strings.NewReader(`{"payload":"0123456789"}`))
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", rr.Code)
	}
}

func TestGatewayUtilityHelpers(t *testing.T) {
	t.Setenv("GW_TEST_STR", "v")
	if got := env("GW_TEST_STR", "x"); got != "v" {
		t.Fatalf("unexpected env string: %s", got)
	}
	if got := env("GW_TEST_STR_MISSING", "x"); got != "x" {
		t.Fatalf("unexpected env default: %s", got)
	}
	t.Setenv("GW_TEST_INT", "41")
	if got := envInt("GW_TEST_INT", 1); got != 41 {
		t.Fatalf("unexpected env int: %d", got)
	}
	t.Setenv("GW_TEST_INT_BAD", "x")
	if got := envInt("GW_TEST_INT_BAD", 7); got != 7 {
		t.Fatalf("expected env int fallback, got %d", got)
	}
	t.Setenv("GW_TEST_DUR", "2")
	if got := envDurationSec("GW_TEST_DUR", 1); got != 2*time.Second {
		t.Fatalf("unexpected env duration: %s", got)
	}
	if got := decisionCacheKey(" Tenant-A ", "k1"); got != "decision:tenant-a:k1" {
		t.Fatalf("unexpected decision key: %s", got)
	}
	if got := decisionCacheKey("", " k1 "); got != "decision:k1" {
		t.Fatalf("unexpected global decision key: %s", got)
	}
	if got := decisionCacheKey("", " "); got != "decision:" {
		t.Fatalf("unexpected empty decision key: %s", got)
	}
	if nullIfEmpty("   ") != nil {
		t.Fatal("expected nil for empty value")
	}
	if nullIfEmpty("x") != "x" {
		t.Fatal("expected string value for non-empty input")
	}
	if got := parseIP("127.0.0.1:8080"); got != "127.0.0.1" {
		t.Fatalf("unexpected parsed host: %s", got)
	}
	if got := parseIP(" 192.0.2.1 "); got != "192.0.2.1" {
		t.Fatalf("unexpected parsed ip: %s", got)
	}
	if got := parseIP("invalid"); got != "" {
		t.Fatalf("expected empty parse for invalid ip, got %s", got)
	}
	if v, ok := asInt64(float64(13.5)); !ok || v != 13 {
		t.Fatalf("unexpected float64 conversion: v=%d ok=%v", v, ok)
	}
}

func TestPublishRefresh(t *testing.T) {
	hub := stream.NewHub()
	s := &Server{Events: hub}
	sub := hub.Subscribe(2)
	defer hub.Unsubscribe(sub)

	s.publishRefresh()
	select {
	case evt := <-sub:
		if evt.Type != "refresh" {
			t.Fatalf("unexpected stream event: %#v", evt)
		}
	case <-time.After(time.Second):
		t.Fatal("expected refresh event")
	}

	s.Events = nil
	s.publishRefresh()
}

func TestLoadPolicyRequiresInputs(t *testing.T) {
	s := &Server{}
	if _, err := s.loadPolicy(context.Background(), "", "v1"); err == nil {
		t.Fatal("expected error for empty policy_set_id")
	}
	if _, err := s.loadPolicy(context.Background(), "finance", ""); err == nil {
		t.Fatal("expected error for empty version")
	}
}

func TestWithRolesAuthOffAndAuthOn(t *testing.T) {
	s := &Server{AuthMode: "off"}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/execute", nil)
	handler := s.withRoles(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, "operator")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected pass-through in auth off mode, got %d", rr.Code)
	}

	s.AuthMode = "oidc_hs256"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without principal, got %d", rr.Code)
	}
}

func sliceContains(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func TestHandleExecuteValidationGuards(t *testing.T) {
	s := &Server{AuthMode: "off"}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{bad`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{},"cert":{}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing intent/cert payload, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay","params":{"amount":1.5}}},"cert":{"policy_set_id":"ps","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z","signature":{"kid":"kid-1"}}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for floating numeric token, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":[],"cert":{}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid intent, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"ONTOLOGY_ACTION","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for action_type mismatch, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":[]}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid cert, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"","policy_version":""}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing policy fields, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"ps","policy_version":"v1"}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing expires_at, got %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/tool/execute", strings.NewReader(`{"intent":{"intent_id":"i-1","action_type":"TOOL_CALL","target":{"domain":"finance"},"operation":{"name":"pay"}},"cert":{"policy_set_id":"ps","policy_version":"v1","expires_at":"2099-01-01T00:00:00Z"}}`))
	s.handleToolExecute(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing signature.kid, got %d", rr.Code)
	}
}
