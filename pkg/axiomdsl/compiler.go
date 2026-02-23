package axiomdsl

import (
	"fmt"

	"axiom/pkg/policyir"
)

// Compile produces labeled constraints.
func Compile(policy *policyir.PolicySetIR) []policyir.Constraint {
	var out []policyir.Constraint
	invIndex := 0
	for _, inv := range policy.Invariants {
		invIndex++
		id := fmt.Sprintf("Invariant#%d", invIndex)
		out = append(out, policyir.Constraint{ID: id, AxiomID: id, Expr: inv})
	}
	for _, ax := range policy.Axioms {
		for i, req := range ax.Requires {
			id := fmt.Sprintf("%s#%d", ax.ID, i+1)
			out = append(out, policyir.Constraint{ID: id, AxiomID: ax.ID, Expr: req})
		}
	}
	return out
}
