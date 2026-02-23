package policyeval

import (
	"encoding/json"
	"testing"

	"axiom/pkg/models"
)

const evalAllocBaseline = 450.0

func TestEvaluateAllocBudget(t *testing.T) {
	dsl := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
axiom Fresh_bank_feed:
  when action.name == "pay_invoice"
  require source("bank").age_sec <= 30`
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 5}}}
	allocs := testing.AllocsPerRun(50, func() {
		_, _ = Evaluate(dsl, intent, belief)
	})
	maxAllowed := evalAllocBaseline * 1.2
	if allocs > maxAllowed {
		t.Fatalf("allocs %.1f exceeded budget %.1f", allocs, maxAllowed)
	}
}

func BenchmarkEvaluatePolicy(b *testing.B) {
	dsl := `policyset finance v1:
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
axiom Fresh_bank_feed:
  when action.name == "pay_invoice"
  require source("bank").age_sec <= 30`
	intent := models.ActionIntent{
		Actor:      models.Actor{ID: "u1", Roles: []string{"FinanceOperator"}, Tenant: "tenant-a"},
		ActionType: "TOOL_CALL",
		Target:     models.Target{Domain: "finance", Scope: "single"},
		Operation:  models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"10.00"}`)},
	}
	belief := models.BeliefState{Sources: []models.SourceState{{Source: "bank", AgeSec: 5}}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = Evaluate(dsl, intent, belief)
	}
}
