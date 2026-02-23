package smt

import (
	"encoding/json"
	"testing"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

func TestBoundKeyAllBranches(t *testing.T) {
	tests := []struct {
		op    string
		side  string
		want  string
		label string
	}{
		{op: "<", side: "left", want: "min", label: "lt-left"},
		{op: "<", side: "right", want: "max", label: "lt-right"},
		{op: "<=", side: "left", want: "min", label: "lte-left"},
		{op: "<=", side: "right", want: "max", label: "lte-right"},
		{op: ">", side: "left", want: "max", label: "gt-left"},
		{op: ">", side: "right", want: "min", label: "gt-right"},
		{op: ">=", side: "left", want: "max", label: "gte-left"},
		{op: ">=", side: "right", want: "min", label: "gte-right"},
		{op: "==", side: "left", want: "eq", label: "eq"},
		{op: "!=", side: "right", want: "neq", label: "neq"},
		{op: "??", side: "left", want: "value", label: "default"},
	}
	for _, tc := range tests {
		if got := boundKey(tc.op, tc.side); got != tc.want {
			t.Fatalf("%s: expected %q, got %q", tc.label, tc.want, got)
		}
	}
}

func TestCollectComparisonFactsBranches(t *testing.T) {
	ctx := BuildContext(models.ActionIntent{
		Operation: models.Operation{
			Name:   "pay_invoice",
			Params: json.RawMessage(`{"amount":"10.5"}`),
		},
	}, models.BeliefState{})
	ctx.Principal = models.Actor{ID: "u1"}

	facts := map[string]struct{}{}
	collectComparisonFacts("10", "20", "<=", ctx, facts)
	if _, ok := facts["min=10"]; !ok {
		t.Fatalf("expected min fact for left literal, got %#v", facts)
	}
	if _, ok := facts["max=20"]; !ok {
		t.Fatalf("expected max fact for right literal, got %#v", facts)
	}

	facts = map[string]struct{}{}
	collectComparisonFacts("action.params.amount", `"USD"`, "==", ctx, facts)
	if _, ok := facts["action.params.amount=10.5"]; !ok {
		t.Fatalf("expected resolved amount fact, got %#v", facts)
	}
	if _, ok := facts["\"USD\"=USD"]; !ok {
		t.Fatalf("expected string literal fact, got %#v", facts)
	}

	facts = map[string]struct{}{}
	collectComparisonFacts("action.params.amount", `"USD"`, "!=", ctx, facts)
	if _, ok := facts["\"USD\"=USD"]; !ok {
		t.Fatalf("expected quoted literal fact for != branch behavior, got %#v", facts)
	}
}

func TestParseLiteralNumberExtraBranches(t *testing.T) {
	if _, ok := parseLiteralNumber(""); ok {
		t.Fatal("empty string must not parse as number")
	}
	if _, ok := parseLiteralNumber("1.2.3"); ok {
		t.Fatal("invalid float token must fail")
	}
	if v, ok := parseLiteralNumber("+1.25e2"); !ok || v != 125 {
		t.Fatalf("expected scientific notation parse, got v=%v ok=%v", v, ok)
	}
}

func TestEvalConstraintsErrorBranch(t *testing.T) {
	ctx := Context{}
	constraints := []policyir.Constraint{
		{ID: "c1", AxiomID: "a1", Expr: `unsupported(expr)`},
	}
	failed := EvalConstraints(constraints, ctx)
	if len(failed) != 1 {
		t.Fatalf("expected constraint failure on eval error, got %#v", failed)
	}
}

func TestBuildContextWithPrincipalInvalidParamsAndAttrs(t *testing.T) {
	intent := models.ActionIntent{
		DataRequirements: models.DataRequirements{
			UncertaintyBudget: map[string]any{
				"ap":  json.Number("7.5"),
				"bad": json.Number("x"),
			},
		},
		Operation: models.Operation{
			Name:   "pay",
			Params: json.RawMessage(`{"amount":`),
		},
	}
	attrs := map[string]string{"risk": "2"}
	ctx := BuildContextWithPrincipal(intent, models.BeliefState{}, models.Actor{ID: "p1"}, attrs)
	if ctx.Budgets["AP"] != 7.5 {
		t.Fatalf("expected AP budget from json.Number, got %v", ctx.Budgets["AP"])
	}
	if len(ctx.Params) != 0 {
		t.Fatalf("expected params to stay empty on invalid params JSON, got %#v", ctx.Params)
	}
	if ctx.Attributes["risk"] != "2" {
		t.Fatalf("expected provided attrs to be preserved, got %#v", ctx.Attributes)
	}
}
