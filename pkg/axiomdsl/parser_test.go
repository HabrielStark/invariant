package axiomdsl

import (
	"testing"
	"time"
)

func TestParseDSLExtras(t *testing.T) {
	dsl := `policyset finance v2:
# metadata
 domain finance
 rate limit 120 per minute scope tenant
 approvals required 2
 approvals roles ["complianceofficer","securityadmin"]
 approvals sod false
 approvals expires_in 1h
 invariant action.scope == "single"
 abac allow when principal.role contains "complianceofficer"
 abac deny when actor.role contains "intern"
 axiom Fresh_bank_feed:
  when action.name == "pay_invoice"
  require source("bank").age_sec <= 30
  else shield("READ_ONLY")`

	policy, err := ParseDSL(dsl)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if policy.ID != "finance" || policy.Version != "v2" {
		t.Fatalf("unexpected header: %#v", policy)
	}
	if policy.Domain != "finance" {
		t.Fatalf("expected domain finance, got %q", policy.Domain)
	}
	if policy.RateLimit == nil || policy.RateLimit.Limit != 120 || policy.RateLimit.Scope != "tenant" {
		t.Fatalf("unexpected rate limit: %#v", policy.RateLimit)
	}
	if policy.RateLimit.Window != time.Minute {
		t.Fatalf("unexpected rate limit window: %v", policy.RateLimit.Window)
	}
	if policy.Approvals == nil || policy.Approvals.Required != 2 {
		t.Fatalf("unexpected approvals: %#v", policy.Approvals)
	}
	if policy.Approvals.EnforceSoD {
		t.Fatalf("expected EnforceSoD=false")
	}
	if policy.Approvals.ExpiresIn != time.Hour {
		t.Fatalf("unexpected approvals expires_in: %v", policy.Approvals.ExpiresIn)
	}
	if len(policy.Invariants) != 1 {
		t.Fatalf("expected invariant")
	}
	if len(policy.ABACRules) != 2 {
		t.Fatalf("expected abac rules")
	}
	if len(policy.Axioms) != 1 {
		t.Fatalf("expected axiom")
	}
}
