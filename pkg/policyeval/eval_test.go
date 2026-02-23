package policyeval

import (
	"encoding/json"
	"testing"

	"axiom/pkg/models"
)

func TestEvaluateAllow(t *testing.T) {
	dsl := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"`
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	res, err := Evaluate(dsl, intent, models.BeliefState{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Verdict != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s", res.Verdict)
	}
}

func TestEvaluateShieldAndCounterexample(t *testing.T) {
	dsl := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
  else shield("REQUIRE_APPROVAL")`
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"Viewer"}},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	res, err := Evaluate(dsl, intent, models.BeliefState{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Verdict != "SHIELD" {
		t.Fatalf("expected SHIELD, got %s", res.Verdict)
	}
	if res.SuggestedShield == nil || res.SuggestedShield.Type != "REQUIRE_APPROVAL" {
		t.Fatalf("expected REQUIRE_APPROVAL shield, got %#v", res.SuggestedShield)
	}
	if res.Counterexample == nil || len(res.Counterexample.FailedAxioms) == 0 {
		t.Fatal("expected counterexample")
	}
	if len(res.Counterexample.MinimalFacts) == 0 {
		t.Fatal("expected minimal facts")
	}
}

func TestShieldParamsParsed(t *testing.T) {
	dsl := `policyset finance v1:
axiom Batch_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
  else shield("SMALL_BATCH", max=25)`
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"Viewer"}},
		ActionType: "ONTOLOGY_ACTION",
		Target:     models.Target{Domain: "finance", Scope: "batch"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"ids":["1","2"]}`)},
	}
	res, err := Evaluate(dsl, intent, models.BeliefState{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.SuggestedShield == nil || res.SuggestedShield.Type != "SMALL_BATCH" {
		t.Fatalf("expected SMALL_BATCH shield, got %#v", res.SuggestedShield)
	}
	if res.SuggestedShield.Params == nil {
		t.Fatalf("expected params")
	}
	if v, ok := res.SuggestedShield.Params["max"]; !ok || v.(int64) != 25 {
		t.Fatalf("expected max=25, got %#v", res.SuggestedShield.Params)
	}
}
