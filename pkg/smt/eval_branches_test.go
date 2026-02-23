package smt

import (
	"encoding/json"
	"strings"
	"testing"

	"axiom/pkg/models"
)

func branchCtx() Context {
	intent := models.ActionIntent{
		Actor: models.Actor{
			ID:     "actor-1",
			Roles:  []string{"Viewer"},
			Tenant: "tenant-a",
		},
		Target: models.Target{
			Domain:    "finance",
			Scope:     "batch",
			ObjectIDs: []string{"1", "2", "3"},
		},
		Operation: models.Operation{
			Name:   "pay_invoice",
			Params: json.RawMessage(`{"amount":"10.50","bad_num":"oops","budget_ap_remaining":"7.00","budget_remaining_hr":"5.50"}`),
		},
	}
	belief := models.BeliefState{
		Sources: []models.SourceState{
			{Source: "bank", AgeSec: 61, HealthScore: 0.81, LagSec: 9},
		},
	}
	principal := models.Actor{
		ID:     "principal-1",
		Tenant: "tenant-b",
		Roles:  []string{"securityadmin"},
	}
	attrs := map[string]string{
		"risk":       "high",
		"num_limit":  "42.5",
		"bad_number": "NaN-nope",
	}
	return BuildContextWithPrincipal(intent, belief, principal, attrs)
}

func TestEvalExprBranchCoverage(t *testing.T) {
	ctx := branchCtx()

	if _, err := EvalExpr("", ctx); err == nil {
		t.Fatal("expected empty expression error")
	}

	ok, err := EvalExpr(`action.name in ["pay_invoice","refund"]`, ctx)
	if err != nil || !ok {
		t.Fatalf("expected in-list expression true, ok=%v err=%v", ok, err)
	}
	if _, err := EvalExpr(`unknown.left in ["x"]`, ctx); err == nil {
		t.Fatal("expected unknown left error for in-list expression")
	}

	ok, err = EvalExpr(`principal.role contains "securityadmin"`, ctx)
	if err != nil || !ok {
		t.Fatalf("expected principal contains true, ok=%v err=%v", ok, err)
	}
	if _, err := EvalExpr(`unsupported contains "x"`, ctx); err == nil {
		t.Fatal("expected unknown contains error")
	}

	ok, err = EvalExpr(`action.name == "pay_invoice"`, ctx)
	if err != nil || !ok {
		t.Fatalf("expected string equality true, ok=%v err=%v", ok, err)
	}
	ok, err = EvalExpr(`action.name != "refund"`, ctx)
	if err != nil || !ok {
		t.Fatalf("expected string inequality true, ok=%v err=%v", ok, err)
	}
	if _, err := EvalExpr(`action.name <= "pay_invoice"`, ctx); err == nil {
		t.Fatal("expected unsupported numeric comparison error")
	}
	if _, err := EvalExpr(`something totally unsupported`, ctx); err == nil {
		t.Fatal("expected unsupported expression error")
	}
}

func TestMinimalFactsAndHelpersCoverage(t *testing.T) {
	ctx := branchCtx()

	facts := MinimalFacts(`action.name in ["pay_invoice","refund"]`, ctx)
	if len(facts) == 0 {
		t.Fatal("expected minimal facts for in-list expression")
	}
	foundAllowed := false
	for _, fact := range facts {
		if strings.HasPrefix(fact, "allowed=") {
			foundAllowed = true
		}
	}
	if !foundAllowed {
		t.Fatalf("expected allowed=... fact, got %#v", facts)
	}

	facts = MinimalFacts(`action.name != "refund"`, ctx)
	if len(facts) == 0 {
		t.Fatal("expected minimal facts for string comparison")
	}
	foundQuotedLiteral := false
	for _, fact := range facts {
		if strings.HasPrefix(fact, `"refund"=`) {
			foundQuotedLiteral = true
		}
	}
	if !foundQuotedLiteral {
		t.Fatalf("expected quoted literal fact for string comparison, got %#v", facts)
	}

	if _, ok := parseLiteralNumber("abc"); ok {
		t.Fatal("expected parseLiteralNumber to reject non-number")
	}
	if _, ok := parseLiteralString("abc"); ok {
		t.Fatal("expected parseLiteralString to reject non-quoted")
	}
	if got := boundKey("?", "left"); got != "value" {
		t.Fatalf("expected default bound key 'value', got %q", got)
	}
	if got := literalStringKey("=="); got != "expected" {
		t.Fatalf("expected default literal key 'expected', got %q", got)
	}
	if got := literalStringKey("!="); got != "forbidden" {
		t.Fatalf("expected not-equal literal key 'forbidden', got %q", got)
	}
	if got := formatFactNumber(10.0); got != "10" {
		t.Fatalf("expected integer formatting, got %q", got)
	}
	if got := formatFactNumber(10.25); got != "10.25" {
		t.Fatalf("expected float formatting, got %q", got)
	}

	m := map[string]struct{}{}
	addFact(m, "", "x")
	addFact(m, "x", "")
	if len(m) != 0 {
		t.Fatalf("expected addFact to ignore empty key/value, got %#v", m)
	}
}

func TestResolveStringAndNumberCoverage(t *testing.T) {
	ctx := branchCtx()

	if got, ok := resolveString("principal.subject", ctx); !ok || got != "principal-1" {
		t.Fatalf("expected principal.subject to resolve, got %q ok=%v", got, ok)
	}
	if got, ok := resolveString("principal.tenant", ctx); !ok || got != "tenant-b" {
		t.Fatalf("expected principal.tenant to resolve, got %q ok=%v", got, ok)
	}
	if got, ok := resolveString("principal.attr.risk", ctx); !ok || got != "high" {
		t.Fatalf("expected principal.attr.risk to resolve, got %q ok=%v", got, ok)
	}
	if got, ok := resolveString("attr.risk", ctx); !ok || got != "high" {
		t.Fatalf("expected attr.risk to resolve, got %q ok=%v", got, ok)
	}
	if _, ok := resolveString("missing.key", ctx); ok {
		t.Fatal("expected missing string key to fail")
	}

	if got, ok := resolveNumber("batch.size", ctx); !ok || got != 3 {
		t.Fatalf("expected batch.size=3, got %v ok=%v", got, ok)
	}
	if got, ok := resolveNumber(`source("bank").health_score`, ctx); !ok || got != 0.81 {
		t.Fatalf("expected bank health score, got %v ok=%v", got, ok)
	}
	if got, ok := resolveNumber(`source("bank").lag_sec`, ctx); !ok || got != 9 {
		t.Fatalf("expected bank lag_sec=9, got %v ok=%v", got, ok)
	}
	if got, ok := resolveNumber(`source("bank").age_sec`, ctx); !ok || got != 61 {
		t.Fatalf("expected bank age_sec=61, got %v ok=%v", got, ok)
	}
	if got, ok := resolveNumber(`budget.remaining("AP")`, ctx); !ok || got != 7 {
		t.Fatalf("expected AP budget from params, got %v ok=%v", got, ok)
	}
	if got, ok := resolveNumber(`budget.remaining("HR")`, ctx); !ok || got != 5.5 {
		t.Fatalf("expected HR budget from params, got %v ok=%v", got, ok)
	}
	if _, ok := resolveNumber("action.params.bad_num", ctx); ok {
		t.Fatal("expected non-numeric action param to fail numeric resolution")
	}
	if got, ok := resolveNumber("principal.attr.num_limit", ctx); !ok || got != 42.5 {
		t.Fatalf("expected numeric principal attr, got %v ok=%v", got, ok)
	}
	if _, ok := resolveNumber("attr.bad_number", ctx); ok {
		t.Fatal("expected invalid numeric attr to fail")
	}
	if _, ok := resolveNumber(`source("missing").age_sec`, ctx); ok {
		t.Fatal("expected missing source age to fail")
	}
	if _, ok := resolveNumber(`budget.remaining("MISSING")`, ctx); ok {
		t.Fatal("expected missing budget code to fail")
	}
}

func TestNumericParsingAndSplitCoverage(t *testing.T) {
	ctx := branchCtx()

	if got, err := parseNumber(`"10.25"`); err != nil || got != 10.25 {
		t.Fatalf("expected quoted number parse, got %v err=%v", got, err)
	}
	if got, err := parseNumber(`eps(1.50)`); err != nil || got != 1.5 {
		t.Fatalf("expected eps parse, got %v err=%v", got, err)
	}
	if got := sourceKey(`source("bank").age_sec`, "age_sec"); got != "bank" {
		t.Fatalf("expected sourceKey=bank, got %q", got)
	}

	if _, err := evalNumeric("", ctx); err == nil {
		t.Fatal("expected empty numeric expression error")
	}
	if got, err := evalNumeric(`budget.remaining("AP")`, ctx); err != nil || got != 7 {
		t.Fatalf("expected numeric lookup for budget, got %v err=%v", got, err)
	}
	if got, err := evalNumeric(`eps(1.25)`, ctx); err != nil || got != 1.25 {
		t.Fatalf("expected numeric eps parsing, got %v err=%v", got, err)
	}
	if _, err := evalNumeric(`unknown_term`, ctx); err == nil {
		t.Fatal("expected unknown numeric term error")
	}
	if _, err := evalNumeric(`1 + unknown_term`, ctx); err == nil {
		t.Fatal("expected invalid term error in additive expression")
	}
	if _, err := evalNumeric(`1 + (2`, ctx); err == nil {
		t.Fatal("expected splitAddSub unbalanced expression error")
	}

	if _, err := splitAddSub(`1 + (2`); err == nil {
		t.Fatal("expected splitAddSub unbalanced parentheses error")
	}
	if _, err := splitAddSub(`"unterminated`); err == nil {
		t.Fatal("expected splitAddSub unterminated quote error")
	}
	toks, err := splitAddSub(`1 + "a\"b" - eps(1.0)`)
	if err != nil {
		t.Fatalf("expected splitAddSub success with escaped quote, got %v", err)
	}
	if len(toks) == 0 {
		t.Fatal("expected non-empty tokens")
	}
}

func TestBuildContextWithPrincipalCoverage(t *testing.T) {
	intent := models.ActionIntent{
		DataRequirements: models.DataRequirements{
			UncertaintyBudget: map[string]interface{}{
				"ap":      "1.25",
				"hr":      2.5,
				"legal":   json.Number("3.75"),
				"bad":     json.Number("not-a-num"),
				"ignored": map[string]string{"x": "y"},
			},
		},
		Operation: models.Operation{
			Name: "pay_invoice",
			Params: json.RawMessage(`{
				"amount":"10.50",
				"BUDGET_AP_REMAINING":"7.00",
				"BUDGET_REMAINING_HR":"8.50",
				"numeric_json":"11.25",
				"bad_json":"x"
			}`),
		},
	}
	principal := models.Actor{ID: "p1"}
	ctx := BuildContextWithPrincipal(intent, models.BeliefState{}, principal, nil)

	if ctx.Principal.ID != "p1" {
		t.Fatalf("expected principal to be copied, got %+v", ctx.Principal)
	}
	if ctx.Attributes == nil {
		t.Fatal("expected attrs map to be initialized")
	}
	if ctx.Budgets["AP"] != 7.0 {
		t.Fatalf("expected AP budget from operation params override, got %v", ctx.Budgets["AP"])
	}
	if ctx.Budgets["HR"] != 8.5 {
		t.Fatalf("expected HR budget from operation params override, got %v", ctx.Budgets["HR"])
	}
	if ctx.Budgets["LEGAL"] != 3.75 {
		t.Fatalf("expected LEGAL budget from uncertainty budget, got %v", ctx.Budgets["LEGAL"])
	}
	if ctx.Params["amount"] != "10.50" {
		t.Fatalf("expected amount param extraction, got %q", ctx.Params["amount"])
	}
}
