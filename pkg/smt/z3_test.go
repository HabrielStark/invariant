package smt

import (
	"encoding/json"
	"strings"
	"testing"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func TestToSMTBoolExprNumeric(t *testing.T) {
	intent := models.ActionIntent{
		Operation: models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"100.50","budget_ap_remaining":"100.00"}`)},
	}
	ctx := BuildContext(intent, models.BeliefState{})
	expr, ok := toSMTBoolExpr(`action.params.amount <= budget.remaining("AP") + eps(1.00)`, ctx)
	if !ok {
		t.Fatal("expected conversion to SMT")
	}
	if expr == "" {
		t.Fatal("empty SMT expression")
	}
}

func TestBuildSMTLIBAndParseUnsatCore(t *testing.T) {
	constraints := []z3Constraint{
		{Constraint: policyir.Constraint{ID: "Fresh_bank_feed#1"}, SMTExpr: "(<= 61 30)"},
		{Constraint: policyir.Constraint{ID: "Budget_limit#1"}, SMTExpr: "(<= 10 100)"},
	}
	script := buildSMTLIB(constraints)
	if !strings.Contains(script, ":named Fresh_bank_feed_1") {
		t.Fatalf("missing named assertion: %s", script)
	}
	status, core := parseZ3Output("unsat\n(Fresh_bank_feed_1)")
	if status != "unsat" {
		t.Fatalf("expected unsat, got %s", status)
	}
	if len(core) != 1 || core[0] != "Fresh_bank_feed_1" {
		t.Fatalf("unexpected core: %#v", core)
	}
}

func TestParseSatOutput(t *testing.T) {
	status, core := parseZ3Output("sat\n")
	if status != "sat" {
		t.Fatalf("expected sat, got %s", status)
	}
	if len(core) != 0 {
		t.Fatalf("expected empty core, got %#v", core)
	}
}
