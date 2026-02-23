package smt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func TestEvalExprAndFactsAdditionalBranches(t *testing.T) {
	ctx := BuildContext(models.ActionIntent{
		Actor: models.Actor{
			ID:    "a1",
			Roles: []string{"Operator"},
		},
		Target: models.Target{
			Domain: "finance",
			Scope:  "single",
		},
		Operation: models.Operation{
			Name:   "pay_invoice",
			Params: json.RawMessage(`{"amount":"11.5"}`),
		},
	}, models.BeliefState{})
	ctx.Principal = models.Actor{ID: "p1", Roles: []string{"Viewer"}, Tenant: "tenant-a"}

	ok, err := EvalExpr(`actor.role contains "Nope"`, ctx)
	if err != nil || ok {
		t.Fatalf("expected actor contains false branch, ok=%v err=%v", ok, err)
	}
	ok, err = EvalExpr(`principal.role contains "Nope"`, ctx)
	if err != nil || ok {
		t.Fatalf("expected principal contains false branch, ok=%v err=%v", ok, err)
	}
	ok, err = EvalExpr(`action.params.amount < 20`, ctx)
	if err != nil || !ok {
		t.Fatalf("expected numeric less-than true, ok=%v err=%v", ok, err)
	}
	ok, err = EvalExpr(`action.params.amount > 20`, ctx)
	if err != nil || ok {
		t.Fatalf("expected numeric greater-than false, ok=%v err=%v", ok, err)
	}

	facts := MinimalFacts(`action.params.amount == "11.5"`, ctx)
	if len(facts) == 0 {
		t.Fatal("expected facts for comparison")
	}
	foundLiteral := false
	for _, f := range facts {
		if strings.HasPrefix(f, `"11.5"=`) {
			foundLiteral = true
		}
	}
	if !foundLiteral {
		t.Fatalf("expected quoted-literal fact key, got %#v", facts)
	}
}

func TestBuildContextWithPrincipalJsonNumberBudgetPatterns(t *testing.T) {
	intent := models.ActionIntent{
		DataRequirements: models.DataRequirements{
			UncertaintyBudget: map[string]interface{}{
				" ap ": json.Number("3.25"),
				"bad":  json.Number("bad"),
			},
		},
		Operation: models.Operation{
			Name: "pay",
			Params: json.RawMessage(`{
				"budget_ap_remaining": 4.5,
				"budget_remaining_ops": 6.75,
				"plain":"x"
			}`),
		},
	}
	ctx := BuildContextWithPrincipal(intent, models.BeliefState{}, models.Actor{}, nil)
	if ctx.Budgets["AP"] != 3.25 {
		t.Fatalf("expected AP budget from uncertainty budget, got %v", ctx.Budgets["AP"])
	}
	if _, ok := ctx.Budgets["OPS"]; ok {
		t.Fatalf("did not expect OPS budget from numeric JSON literal path, got %v", ctx.Budgets["OPS"])
	}
	if _, ok := ctx.Attributes["x"]; ok {
		t.Fatalf("unexpected attributes side effect: %#v", ctx.Attributes)
	}
}

func TestEvalPolicyZ3ExecAdditionalBranches(t *testing.T) {
	ctx := testContext()

	nonSMTPolicy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:       "Role_guard",
				Requires: []string{`actor.role contains "FinanceManager"`},
			},
		},
	}
	failure, err := EvalPolicyZ3Exec(nonSMTPolicy, ctx, Z3Options{})
	if err != nil {
		t.Fatalf("expected failure without transport error, got err=%v", err)
	}
	if failure == nil || failure.Axiom.ID != "Role_guard" {
		t.Fatalf("expected Role_guard failure, got %+v", failure)
	}

	noopPolicy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:       "Skip",
				When:     `action.name == "refund"`,
				Requires: []string{`action.params.amount <= 10`},
			},
		},
	}
	failure, err = EvalPolicyZ3Exec(noopPolicy, ctx, Z3Options{})
	if err != nil || failure != nil {
		t.Fatalf("expected nil result for non-applicable policy, failure=%+v err=%v", failure, err)
	}

	arithPolicy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:       "Budget_limit",
				Requires: []string{`action.params.amount <= budget.remaining("AP") + eps(1.00)`},
			},
		},
	}
	if _, err := EvalPolicyZ3Exec(arithPolicy, ctx, Z3Options{Binary: "not-z3"}); err == nil {
		t.Fatal("expected z3 binary resolution error")
	}

	satZ3 := writeFakeZ3(t, "cat >/dev/null\necho sat")
	failure, err = EvalPolicyZ3Exec(arithPolicy, ctx, Z3Options{Binary: satZ3, Timeout: 5 * time.Second})
	if err != nil || failure != nil {
		t.Fatalf("expected SAT nil result, failure=%+v err=%v", failure, err)
	}
}

func TestZ3ParsingAndLabelBranches(t *testing.T) {
	status, core := parseZ3Output("")
	if status != "unknown" || core != nil {
		t.Fatalf("expected unknown status for empty output, status=%q core=%#v", status, core)
	}
	status, core = parseZ3Output("unsat\n()")
	if status != "unsat" || core != nil {
		t.Fatalf("expected empty unsat core, status=%q core=%#v", status, core)
	}
	if got := sanitizeLabel(""); got != "c0" {
		t.Fatalf("expected empty label normalization, got %q", got)
	}
}

func TestRunZ3CoreExecCommandErrorDefaultTimeoutBranch(t *testing.T) {
	// exits non-zero to trigger wrapped command error branch with default timeout path.
	failZ3 := writeFakeZ3(t, "cat >/dev/null\nexit 7")
	constraints := []z3Constraint{
		{Constraint: policyir.Constraint{ID: "c1"}, SMTExpr: "(<= 1 2)"},
	}
	if _, err := runZ3CoreExec(constraints, Z3Options{Binary: failZ3}); err == nil {
		t.Fatal("expected z3 exec failed error")
	}
}
