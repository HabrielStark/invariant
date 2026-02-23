package smt

import (
	"encoding/json"
	"testing"
	"time"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func z3BranchCtx() Context {
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00","budget_ap_remaining":"9.00"}`)},
	}
	return BuildContext(intent, models.BeliefState{})
}

func TestToSMTBoolExprBranches(t *testing.T) {
	ctx := z3BranchCtx()

	if _, ok := toSMTBoolExpr("", ctx); ok {
		t.Fatal("expected empty bool expr to fail")
	}
	if _, ok := toSMTBoolExpr(`unknown <= 1`, ctx); ok {
		t.Fatal("expected bool conversion to fail when arithmetic term cannot be resolved")
	}
	if _, ok := toSMTBoolExpr(`foo(bar)`, ctx); ok {
		t.Fatal("expected unsupported bool expr to fail")
	}

	expr, ok := toSMTBoolExpr(`action.params.amount <= budget.remaining("AP") + eps(1.00) and action.params.amount > 0`, ctx)
	if !ok {
		t.Fatal("expected boolean and conversion to succeed")
	}
	if expr == "" {
		t.Fatal("expected non-empty SMT bool expression")
	}

	for _, tc := range []string{
		`action.params.amount <= 11`,
		`action.params.amount >= 9`,
		`action.params.amount < 11`,
		`action.params.amount > 9`,
		`action.params.amount == 10`,
		`action.params.amount != 11`,
	} {
		if _, ok := toSMTBoolExpr(tc, ctx); !ok {
			t.Fatalf("expected conversion success for %q", tc)
		}
	}
}

func TestToSMTArithExprBranches(t *testing.T) {
	ctx := z3BranchCtx()

	if _, ok := toSMTArithExpr("", ctx); ok {
		t.Fatal("expected empty arithmetic expr to fail")
	}
	if _, ok := toSMTArithExpr(`foo(bar)`, ctx); ok {
		t.Fatal("expected unknown arithmetic expression to fail")
	}
	if _, ok := toSMTArithExpr(`1 + unknown_term`, ctx); ok {
		t.Fatal("expected arithmetic expression with invalid term to fail")
	}
	if _, ok := toSMTArithExpr(`1 + (2`, ctx); ok {
		t.Fatal("expected malformed arithmetic expression to fail")
	}

	if expr, ok := toSMTArithExpr(`action.params.amount`, ctx); !ok || expr != "10" {
		t.Fatalf("expected numeric conversion to 10, got %q ok=%v", expr, ok)
	}
	if expr, ok := toSMTArithExpr(`eps(1.25)`, ctx); !ok || expr != "1.25" {
		t.Fatalf("expected eps conversion to 1.25, got %q ok=%v", expr, ok)
	}
}

func TestEvalPolicyZ3ExecUnknownCoreBranch(t *testing.T) {
	ctx := z3BranchCtx()
	fake := writeFakeZ3(t, "echo unsat\necho '(Unknown_label)'")
	policy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:       "Budget_limit",
				Requires: []string{`action.params.amount <= budget.remaining("AP") + eps(1.00)`},
			},
		},
	}
	failure, err := EvalPolicyZ3Exec(policy, ctx, Z3Options{Binary: fake, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected z3 exec error: %v", err)
	}
	if failure != nil {
		t.Fatalf("expected nil failure for unsat core label not mapped to known constraint, got %+v", failure)
	}
}

func TestFormatSMTNumberExponentBranch(t *testing.T) {
	s := formatSMTNumber(1e20)
	if s == "" {
		t.Fatal("expected non-empty formatted number")
	}
}
