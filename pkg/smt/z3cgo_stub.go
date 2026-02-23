//go:build !z3cgo

package smt

import (
	"errors"

	"axiom/pkg/policyir"
)

func EvalPolicyZ3Cgo(policy *policyir.PolicySetIR, ctx Context, opts Z3Options) (*AxiomFailure, error) {
	return nil, errors.New("z3cgo backend not built")
}
