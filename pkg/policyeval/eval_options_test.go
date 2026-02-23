package policyeval

import (
	"encoding/json"
	"testing"
	"time"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func policyIntent() models.ActionIntent {
	return models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
}

func TestEvaluateWithOptionsBackends(t *testing.T) {
	goDSL := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`
	smtExecDSL := `policyset finance v1:
axiom Const_rule:
  when action.name == "pay_invoice"
  require 1 <= 2`
	intent := policyIntent()
	state := models.BeliefState{}

	res, err := EvaluateWithOptions(goDSL, intent, state, Options{Backend: "go"})
	if err != nil {
		t.Fatalf("go backend evaluate: %v", err)
	}
	if res.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW on go backend, got %s", res.Verdict)
	}

	res, err = EvaluateWithOptions(goDSL, intent, state, Options{Backend: "z3", Z3Path: "/definitely/missing/z3", Z3Timeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("z3 backend should return defer on unavailable backend, got err=%v", err)
	}
	if res.Verdict != "DEFER" || res.ReasonCode != "SMT_UNAVAILABLE" {
		t.Fatalf("expected DEFER/SMT_UNAVAILABLE, got %+v", res)
	}

	res, err = EvaluateWithOptions(smtExecDSL, intent, state, Options{Backend: "z3exec", Z3Path: "/definitely/missing/z3", Z3Timeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("z3exec backend should return defer on unavailable backend, got err=%v", err)
	}
	if res.Verdict != "DEFER" || res.ReasonCode != "SMT_UNAVAILABLE" {
		t.Fatalf("expected DEFER/SMT_UNAVAILABLE, got %+v", res)
	}

	res, err = EvaluateWithOptions(goDSL, intent, state, Options{Backend: "z3cgo", Z3Path: "/definitely/missing/z3", Z3Timeout: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("z3cgo backend should return defer on unavailable backend, got err=%v", err)
	}
	if res.Verdict != "DEFER" || res.ReasonCode != "SMT_UNAVAILABLE" {
		t.Fatalf("expected DEFER/SMT_UNAVAILABLE, got %+v", res)
	}
}

func TestEvaluateInvalidDSL(t *testing.T) {
	if _, err := EvaluateWithOptions("invalid dsl", policyIntent(), models.BeliefState{}, Options{}); err == nil {
		t.Fatal("expected parse error for invalid dsl")
	}
}

func TestShieldParsingAndInvariants(t *testing.T) {
	shield := ShieldFromAxiom(policyir.Axiom{ElseShield: `shield("REQUIRE_APPROVAL", max=25, dry=true, reason="manual review", ratio=0.75)`})
	if shield == nil {
		t.Fatal("expected parsed shield")
	}
	if shield.Type != "REQUIRE_APPROVAL" {
		t.Fatalf("unexpected shield type: %s", shield.Type)
	}
	if shield.Params["max"] != int64(25) {
		t.Fatalf("expected max=25, got %#v", shield.Params["max"])
	}
	if shield.Params["dry"] != true {
		t.Fatalf("expected dry=true, got %#v", shield.Params["dry"])
	}
	if shield.Params["reason"] != "manual review" {
		t.Fatalf("expected reason string, got %#v", shield.Params["reason"])
	}
	if shield.Params["ratio"] != 0.75 {
		t.Fatalf("expected ratio=0.75, got %#v", shield.Params["ratio"])
	}

	if ShieldFromAxiom(policyir.Axiom{ElseShield: ""}) != nil {
		t.Fatal("expected nil shield for empty else shield")
	}
	if ShieldFromAxiom(policyir.Axiom{ElseShield: "noop"}) != nil {
		t.Fatal("expected nil shield for non-shield expression")
	}

	policy := &policyir.PolicySetIR{
		Invariants: []string{
			`action.scope == "single"`,
			`action.name == "pay_invoice"`,
		},
		Axioms: []policyir.Axiom{
			{ID: "Role_guard", Requires: []string{`actor.role contains "FinanceOperator"`}},
		},
	}
	applyInvariants(policy)
	if len(policy.Axioms) != 3 {
		t.Fatalf("expected 3 axioms after invariant expansion, got %d", len(policy.Axioms))
	}
	if policy.Axioms[0].ID != "Invariant#1" || len(policy.Axioms[0].Requires) != 1 {
		t.Fatalf("unexpected first invariant axiom: %+v", policy.Axioms[0])
	}
	if policy.Axioms[2].ID != "Role_guard" {
		t.Fatalf("expected original axiom to remain last, got %+v", policy.Axioms[2])
	}
}
