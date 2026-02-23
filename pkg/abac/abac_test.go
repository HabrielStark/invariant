package abac

import (
	"testing"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
	"axiom/pkg/smt"
)

func TestABACAllowDeny(t *testing.T) {
	policy := &policyir.PolicySetIR{ABACRules: []policyir.ABACRule{
		{Effect: "DENY", When: "actor.role contains \"Intern\""},
		{Effect: "ALLOW", When: "principal.role contains \"ComplianceOfficer\""},
	}}
	intent := models.ActionIntent{Actor: models.Actor{ID: "u1", Roles: []string{"Employee"}}, Target: models.Target{Domain: "finance"}}
	principal := models.Actor{ID: "u2", Roles: []string{"ComplianceOfficer"}, Tenant: "acme"}
	ctx := smt.BuildContextWithPrincipal(intent, models.BeliefState{}, principal, nil)
	decision := Evaluate(policy, ctx)
	if !decision.Allowed {
		t.Fatalf("expected allowed, got %s", decision.Reason)
	}

	intent.Actor.Roles = []string{"Intern"}
	ctx = smt.BuildContextWithPrincipal(intent, models.BeliefState{}, principal, nil)
	decision = Evaluate(policy, ctx)
	if decision.Allowed || decision.Reason != ReasonDeny {
		t.Fatalf("expected deny, got %+v", decision)
	}
}

func TestABACTenantRule(t *testing.T) {
	policy := &policyir.PolicySetIR{ABACRules: []policyir.ABACRule{
		{Effect: "ALLOW", When: "principal.tenant == \"acme\""},
	}}
	intent := models.ActionIntent{Actor: models.Actor{ID: "u1"}, Target: models.Target{Domain: "finance"}}
	principal := models.Actor{ID: "u1", Tenant: "acme"}
	ctx := smt.BuildContextWithPrincipal(intent, models.BeliefState{}, principal, nil)
	decision := Evaluate(policy, ctx)
	if !decision.Allowed {
		t.Fatalf("expected allow, got %s", decision.Reason)
	}

	principal.Tenant = "other"
	ctx = smt.BuildContextWithPrincipal(intent, models.BeliefState{}, principal, nil)
	decision = Evaluate(policy, ctx)
	if decision.Allowed || decision.Reason != ReasonNoMatch {
		t.Fatalf("expected deny due to no match, got %+v", decision)
	}
}
