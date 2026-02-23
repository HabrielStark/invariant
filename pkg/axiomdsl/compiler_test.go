package axiomdsl

import (
	"testing"

	"axiom/pkg/policyir"
)

func TestCompileConstraints(t *testing.T) {
	policy := &policyir.PolicySetIR{
		Invariants: []string{
			`source("bank").age_sec <= 30`,
			`batch.size <= 100`,
		},
		Axioms: []policyir.Axiom{
			{
				ID:       "Role_guard",
				Requires: []string{`actor.role contains "FinanceOperator"`},
			},
			{
				ID:       "Budget_limit",
				Requires: []string{`action.params.amount <= budget.remaining("AP") + eps(1.00)`, `batch.size <= 500`},
			},
		},
	}

	constraints := Compile(policy)
	if len(constraints) != 5 {
		t.Fatalf("expected 5 constraints, got %d", len(constraints))
	}
	if constraints[0].ID != "Invariant#1" || constraints[0].AxiomID != "Invariant#1" {
		t.Fatalf("unexpected invariant constraint[0]: %+v", constraints[0])
	}
	if constraints[1].ID != "Invariant#2" || constraints[1].AxiomID != "Invariant#2" {
		t.Fatalf("unexpected invariant constraint[1]: %+v", constraints[1])
	}
	if constraints[2].ID != "Role_guard#1" || constraints[2].AxiomID != "Role_guard" {
		t.Fatalf("unexpected axiom constraint[2]: %+v", constraints[2])
	}
	if constraints[3].ID != "Budget_limit#1" || constraints[3].AxiomID != "Budget_limit" {
		t.Fatalf("unexpected axiom constraint[3]: %+v", constraints[3])
	}
	if constraints[4].ID != "Budget_limit#2" || constraints[4].AxiomID != "Budget_limit" {
		t.Fatalf("unexpected axiom constraint[4]: %+v", constraints[4])
	}
}
