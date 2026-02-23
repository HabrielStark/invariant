package smt

import (
	"encoding/json"
	"testing"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func TestEvalConstraints(t *testing.T) {
	intent := models.ActionIntent{
		Actor:     models.Actor{Roles: []string{"FinanceOperator"}},
		Target:    models.Target{Scope: "single"},
		Operation: models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 10}}}
	ctx := BuildContext(intent, belief)
	constraints := []policyir.Constraint{
		{ID: "c1", AxiomID: "a1", Expr: `source("bank").age_sec <= 30`},
		{ID: "c2", AxiomID: "a2", Expr: `actor.role contains "FinanceOperator"`},
	}
	failed := EvalConstraints(constraints, ctx)
	if len(failed) != 0 {
		t.Fatalf("expected no failures")
	}
}

func TestEvalPolicyHonorsWhen(t *testing.T) {
	intent := models.ActionIntent{
		Actor:     models.Actor{Roles: []string{"FinanceOperator"}},
		Target:    models.Target{Scope: "single"},
		Operation: models.Operation{Name: "refund", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 10}}}
	ctx := BuildContext(intent, belief)
	policy := &policyir.PolicySetIR{Axioms: []policyir.Axiom{
		{ID: "A1", When: `action.name == "pay_invoice"`, Requires: []string{`actor.role contains "Admin"`}},
		{ID: "A2", When: `action.name == "refund"`, Requires: []string{`source("bank").age_sec <= 30`}},
	}}
	failure := EvalPolicy(policy, ctx)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
}

func TestEvalPolicyReturnsFirstFailure(t *testing.T) {
	intent := models.ActionIntent{
		Actor:     models.Actor{Roles: []string{"FinanceOperator"}},
		Target:    models.Target{Scope: "single", ObjectIDs: []string{"1", "2", "3"}},
		Operation: models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 50}}}
	ctx := BuildContext(intent, belief)
	policy := &policyir.PolicySetIR{Axioms: []policyir.Axiom{
		{ID: "A1", When: `action.name == "pay_invoice" and action.scope == "single"`, Requires: []string{`source("bank").age_sec <= 30`}, ElseShield: `shield("READ_ONLY")`},
	}}
	failure := EvalPolicy(policy, ctx)
	if failure == nil {
		t.Fatal("expected failure")
	}
	if failure.Axiom.ID != "A1" {
		t.Fatalf("unexpected axiom: %s", failure.Axiom.ID)
	}
	if failure.Constraint.Expr != `source("bank").age_sec <= 30` {
		t.Fatalf("unexpected expr: %s", failure.Constraint.Expr)
	}
}

func TestEvalExprBudgetAndEps(t *testing.T) {
	intent := models.ActionIntent{
		Actor:     models.Actor{Roles: []string{"FinanceOperator"}},
		Target:    models.Target{Scope: "single"},
		Operation: models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"100.50","budget_ap_remaining":"100.00"}`)},
	}
	ctx := BuildContext(intent, models.BeliefState{})
	ok, err := EvalExpr(`action.params.amount <= budget.remaining("AP") + eps(1.00)`, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected budget expression to pass")
	}
}

func TestEvalExprSourceHealthAndLag(t *testing.T) {
	intent := models.ActionIntent{
		Actor:     models.Actor{Roles: []string{"FinanceOperator"}},
		Target:    models.Target{Scope: "single"},
		Operation: models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 10, HealthScore: 0.97, LagSec: 2}}}
	ctx := BuildContext(intent, belief)
	ok, err := EvalExpr(`source("bank").health_score >= 0.95 and source("bank").lag_sec <= 3`, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected health/lag expression to pass")
	}
}

func TestMinimalFactsNumericBound(t *testing.T) {
	intent := models.ActionIntent{
		Actor:     models.Actor{Roles: []string{"FinanceOperator"}},
		Target:    models.Target{Scope: "single"},
		Operation: models.Operation{Name: "pay_invoice"},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 61}}}
	ctx := BuildContext(intent, belief)
	facts := MinimalFacts(`source("bank").age_sec <= 30`, ctx)
	if len(facts) == 0 {
		t.Fatal("expected minimal facts")
	}
	hasAge := false
	hasMax := false
	for _, fact := range facts {
		if fact == `source("bank").age_sec=61` {
			hasAge = true
		}
		if fact == "max=30" {
			hasMax = true
		}
	}
	if !hasAge || !hasMax {
		t.Fatalf("unexpected facts: %#v", facts)
	}
}

func TestMinimalFactsContainsRole(t *testing.T) {
	intent := models.ActionIntent{
		Actor: models.Actor{Roles: []string{"Viewer"}},
	}
	ctx := BuildContext(intent, models.BeliefState{})
	facts := MinimalFacts(`actor.role contains "FinanceOperator"`, ctx)
	if len(facts) == 0 {
		t.Fatal("expected minimal facts")
	}
	if facts[0] == "" {
		t.Fatal("expected non-empty fact")
	}
}
