package smt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func writeFakeZ3(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "z3")
	content := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake z3: %v", err)
	}
	return path
}

func testContext() Context {
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"Viewer"}, Tenant: "tenant-a"},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00","budget_ap_remaining":"1.00"}`)},
	}
	return BuildContext(intent, models.BeliefState{})
}

func TestResolveZ3Binary(t *testing.T) {
	if _, err := resolveZ3Binary("z3 bad"); err == nil {
		t.Fatal("expected invalid binary path error for spaces")
	}
	if _, err := resolveZ3Binary("cat"); err == nil {
		t.Fatal("expected unsupported binary error")
	}

	fake := writeFakeZ3(t, "cat >/dev/null\necho sat")
	resolved, err := resolveZ3Binary(fake)
	if err != nil {
		t.Fatalf("resolve fake z3: %v", err)
	}
	if resolved == "" {
		t.Fatal("expected resolved binary path")
	}
}

func TestRunZ3CoreExecBranches(t *testing.T) {
	core, err := runZ3CoreExec(nil, Z3Options{})
	if err != nil {
		t.Fatalf("empty constraints should be no-op, got err=%v", err)
	}
	if core != nil {
		t.Fatalf("expected nil core for empty constraints, got %#v", core)
	}

	constraints := []z3Constraint{
		{Constraint: policyir.Constraint{ID: "Fresh_bank_feed#1"}, SMTExpr: "(<= 61 30)"},
	}
	if _, err := runZ3CoreExec(constraints, Z3Options{Binary: "not-z3"}); err == nil {
		t.Fatal("expected resolve binary error")
	}

	satZ3 := writeFakeZ3(t, "cat >/dev/null\necho sat")
	core, err = runZ3CoreExec(constraints, Z3Options{Binary: satZ3, Timeout: time.Second})
	if err != nil {
		t.Fatalf("sat fake z3 failed: %v", err)
	}
	if core != nil {
		t.Fatalf("expected nil core for sat, got %#v", core)
	}

	unsatZ3 := writeFakeZ3(t, "cat >/dev/null\necho unsat\necho '(Fresh_bank_feed_1)'")
	core, err = runZ3CoreExec(constraints, Z3Options{Binary: unsatZ3, Timeout: time.Second})
	if err != nil {
		t.Fatalf("unsat fake z3 failed: %v", err)
	}
	if len(core) != 1 || core[0] != "Fresh_bank_feed_1" {
		t.Fatalf("unexpected unsat core: %#v", core)
	}

	unknownZ3 := writeFakeZ3(t, "cat >/dev/null\necho unknown")
	if _, err := runZ3CoreExec(constraints, Z3Options{Binary: unknownZ3, Timeout: time.Second}); err == nil {
		t.Fatal("expected unknown status error")
	}

	slowZ3 := writeFakeZ3(t, "sleep 1\necho sat")
	if _, err := runZ3CoreExec(constraints, Z3Options{Binary: slowZ3, Timeout: 10 * time.Millisecond}); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestPrepareConstraintsAndExecWrapper(t *testing.T) {
	ctx := testContext()
	policy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:       "Budget_limit",
				When:     `action.name == "pay_invoice"`,
				Requires: []string{`action.params.amount <= budget.remaining("AP") + eps(1.00)`},
			},
		},
	}
	converted, labelMap, failure, err := prepareZ3Constraints(policy, ctx)
	if err != nil {
		t.Fatalf("prepareZ3Constraints: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	if len(converted) != 1 {
		t.Fatalf("expected one converted constraint, got %d", len(converted))
	}
	if _, ok := labelMap["Budget_limit_1"]; !ok {
		t.Fatalf("expected label map to include Budget_limit_1, got %#v", labelMap)
	}

	policy.Axioms = []policyir.Axiom{
		{
			ID:       "Role_guard",
			When:     `action.name == "pay_invoice"`,
			Requires: []string{`actor.role contains "FinanceOperator"`},
		},
	}
	converted, labelMap, failure, err = prepareZ3Constraints(policy, ctx)
	if err != nil {
		t.Fatalf("prepareZ3Constraints non-smt: %v", err)
	}
	if converted != nil || labelMap != nil {
		t.Fatalf("expected direct failure path for non-SMT unmet axiom, got converted=%#v labelMap=%#v", converted, labelMap)
	}
	if failure == nil || failure.Axiom.ID != "Role_guard" {
		t.Fatalf("expected Role_guard failure, got %+v", failure)
	}

	emptyPolicy := &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{ID: "Skip_me", When: `action.name == "refund"`, Requires: []string{`action.params.amount <= 10`}},
		},
	}
	converted, labelMap, failure, err = prepareZ3Constraints(emptyPolicy, ctx)
	if err != nil || failure != nil {
		t.Fatalf("unexpected error/failure for non-applicable axiom: err=%v failure=%+v", err, failure)
	}
	if len(converted) != 0 || len(labelMap) != 0 {
		t.Fatalf("expected empty constraints for non-applicable axiom, got converted=%d labels=%d", len(converted), len(labelMap))
	}

	fake := writeFakeZ3(t, "cat >/dev/null\necho unsat\necho '(Budget_limit_1)'")
	policy = &policyir.PolicySetIR{
		Axioms: []policyir.Axiom{
			{
				ID:       "Budget_limit",
				Requires: []string{`action.params.amount <= budget.remaining("AP") + eps(1.00)`},
			},
		},
	}
	failure, err = EvalPolicyZ3Exec(policy, ctx, Z3Options{Binary: fake, Timeout: time.Second})
	if err != nil {
		t.Fatalf("EvalPolicyZ3Exec unsat: %v", err)
	}
	if failure == nil || failure.Axiom.ID != "Budget_limit" {
		t.Fatalf("expected Budget_limit failure, got %+v", failure)
	}

	failure, err = EvalPolicyZ3(policy, ctx, Z3Options{})
	if err == nil {
		t.Fatal("expected z3cgo backend error in non-z3cgo build")
	}
	if failure != nil {
		t.Fatalf("expected nil failure on z3cgo backend error, got %+v", failure)
	}
}

func TestHelpers(t *testing.T) {
	if got := sortedLabels([]string{"b", "a", "c"}); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("unexpected sorted labels: %#v", got)
	}
	if got := sanitizeLabel("1.bad/id"); got != "c_1_bad_id" {
		t.Fatalf("unexpected sanitized label: %s", got)
	}
}
