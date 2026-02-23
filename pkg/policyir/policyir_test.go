package policyir

import (
	"testing"
	"time"
)

func TestPolicySetIR_ZeroValue(t *testing.T) {
	var p PolicySetIR
	if p.ID != "" || p.Version != "" || p.Domain != "" {
		t.Fatal("zero value should have empty strings")
	}
	if p.RateLimit != nil || p.Approvals != nil {
		t.Fatal("zero value should have nil pointers")
	}
	if len(p.Axioms) != 0 || len(p.ABACRules) != 0 || len(p.Invariants) != 0 {
		t.Fatal("zero value should have empty slices")
	}
}

func TestPolicySetIR_WithFields(t *testing.T) {
	p := PolicySetIR{
		ID:      "finance-v2",
		Version: "2.0",
		Domain:  "finance",
		RateLimit: &RateLimit{
			Limit:     100,
			Window:    time.Minute,
			Scope:     "actor",
			PerTenant: true,
		},
		Approvals: &ApprovalPolicy{
			Required:   2,
			Roles:      []string{"approver", "manager"},
			EnforceSoD: true,
			ExpiresIn:  24 * time.Hour,
		},
		Invariants: []string{"actor.role != 'root'"},
		ABACRules: []ABACRule{
			{Effect: "DENY", When: "actor.clearance < target.classification"},
		},
		Axioms: []Axiom{
			{
				ID:         "fresh_data",
				When:       "action.type == 'WRITE'",
				Requires:   []string{"state.bank.age_sec < 60"},
				ElseShield: "shield(\"REQUIRE_APPROVAL\")",
			},
		},
	}
	if p.ID != "finance-v2" {
		t.Fatalf("ID = %q, want finance-v2", p.ID)
	}
	if p.RateLimit.Limit != 100 || p.RateLimit.Window != time.Minute {
		t.Fatalf("RateLimit mismatch: %+v", p.RateLimit)
	}
	if p.Approvals.Required != 2 || !p.Approvals.EnforceSoD {
		t.Fatalf("Approvals mismatch: %+v", p.Approvals)
	}
	if len(p.Axioms) != 1 || p.Axioms[0].ID != "fresh_data" {
		t.Fatalf("Axioms mismatch: %+v", p.Axioms)
	}
	if len(p.ABACRules) != 1 || p.ABACRules[0].Effect != "DENY" {
		t.Fatalf("ABACRules mismatch: %+v", p.ABACRules)
	}
}

func TestAxiom_Fields(t *testing.T) {
	a := Axiom{
		ID:         "sod_guard",
		When:       "always",
		Requires:   []string{"actor.id != approver.id"},
		ElseShield: "shield(\"REQUIRE_APPROVAL\")",
	}
	if a.ID != "sod_guard" {
		t.Fatalf("ID = %q", a.ID)
	}
	if len(a.Requires) != 1 {
		t.Fatalf("Requires length = %d", len(a.Requires))
	}
}

func TestConstraint_Fields(t *testing.T) {
	c := Constraint{ID: "c1", AxiomID: "sod_guard", Expr: "actor.id != approver.id"}
	if c.ID != "c1" || c.AxiomID != "sod_guard" {
		t.Fatalf("Constraint mismatch: %+v", c)
	}
}

func TestRateLimit_PerTenant(t *testing.T) {
	rl := RateLimit{Limit: 50, Window: 30 * time.Second, Scope: "tenant", PerTenant: true}
	if !rl.PerTenant || rl.Scope != "tenant" {
		t.Fatalf("RateLimit: %+v", rl)
	}
}

func TestApprovalPolicy_Defaults(t *testing.T) {
	ap := ApprovalPolicy{Required: 1}
	if ap.EnforceSoD || ap.ExpiresIn != 0 || len(ap.Roles) != 0 {
		t.Fatalf("unexpected defaults: %+v", ap)
	}
}

func TestABACRule_Fields(t *testing.T) {
	r := ABACRule{Effect: "ALLOW", When: "actor.clearance >= target.classification"}
	if r.Effect != "ALLOW" {
		t.Fatalf("Effect = %q", r.Effect)
	}
}
