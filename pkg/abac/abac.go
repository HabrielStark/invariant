package abac

import (
	"strings"

	"axiom/pkg/policyir"
	"axiom/pkg/smt"
)

const (
	ReasonAllow   = "ABAC_ALLOW"
	ReasonDeny    = "ABAC_DENY"
	ReasonNoMatch = "ABAC_NO_MATCH"
)

type Decision struct {
	Allowed bool
	Reason  string
}

// Evaluate applies ABAC rules. Deny rules take precedence.
func Evaluate(policy *policyir.PolicySetIR, ctx smt.Context) Decision {
	if policy == nil || len(policy.ABACRules) == 0 {
		return Decision{Allowed: true, Reason: ReasonAllow}
	}
	allowMatched := false
	for _, rule := range policy.ABACRules {
		expr := strings.TrimSpace(rule.When)
		if expr == "" {
			continue
		}
		ok, err := smt.EvalExpr(expr, ctx)
		if err != nil || !ok {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(rule.Effect)) {
		case "DENY":
			return Decision{Allowed: false, Reason: ReasonDeny}
		case "ALLOW":
			allowMatched = true
		}
	}
	if allowMatched {
		return Decision{Allowed: true, Reason: ReasonAllow}
	}
	return Decision{Allowed: false, Reason: ReasonNoMatch}
}
