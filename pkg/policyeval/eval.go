package policyeval

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/axiomdsl"
	"axiom/pkg/models"
	"axiom/pkg/policyir"
	"axiom/pkg/smt"
)

type Result struct {
	Verdict         string
	ReasonCode      string
	Counterexample  *models.Counterexample
	SuggestedShield *models.SuggestedShield
}

type Options struct {
	Backend   string
	Z3Path    string
	Z3Timeout time.Duration
}

func Evaluate(dsl string, intent models.ActionIntent, belief models.BeliefState) (Result, error) {
	return EvaluateWithOptions(dsl, intent, belief, Options{Backend: "go"})
}

func EvaluateWithOptions(dsl string, intent models.ActionIntent, belief models.BeliefState, opts Options) (Result, error) {
	policy, err := axiomdsl.ParseDSL(dsl)
	if err != nil {
		return Result{}, err
	}
	applyInvariants(policy)
	ctx := smt.BuildContext(intent, belief)
	failure := (*smt.AxiomFailure)(nil)
	switch strings.ToLower(strings.TrimSpace(opts.Backend)) {
	case "", "go":
		failure = smt.EvalPolicy(policy, ctx)
	case "z3":
		failure, err = smt.EvalPolicyZ3Cgo(policy, ctx, smt.Z3Options{
			Binary:  opts.Z3Path,
			Timeout: opts.Z3Timeout,
		})
		if err != nil {
			return Result{Verdict: "DEFER", ReasonCode: "SMT_UNAVAILABLE"}, nil
		}
	case "z3exec":
		failure, err = smt.EvalPolicyZ3Exec(policy, ctx, smt.Z3Options{
			Binary:  opts.Z3Path,
			Timeout: opts.Z3Timeout,
		})
		if err != nil {
			return Result{Verdict: "DEFER", ReasonCode: "SMT_UNAVAILABLE"}, nil
		}
	case "z3cgo":
		failure, err = smt.EvalPolicyZ3Cgo(policy, ctx, smt.Z3Options{
			Binary:  opts.Z3Path,
			Timeout: opts.Z3Timeout,
		})
		if err != nil {
			return Result{Verdict: "DEFER", ReasonCode: "SMT_UNAVAILABLE"}, nil
		}
	default:
		failure = smt.EvalPolicy(policy, ctx)
	}
	if failure == nil {
		return Result{Verdict: "ALLOW", ReasonCode: "OK"}, nil
	}
	facts := append([]string{}, failure.Facts...)
	if len(facts) == 0 && failure.Constraint.Expr != "" {
		facts = []string{failure.Constraint.Expr}
	}
	res := Result{
		Verdict:    "SHIELD",
		ReasonCode: "AXIOM_FAIL",
		Counterexample: &models.Counterexample{
			MinimalFacts: facts,
			FailedAxioms: []string{failure.Axiom.ID},
		},
	}
	if sh := ShieldFromAxiom(failure.Axiom); sh != nil {
		res.SuggestedShield = sh
	}
	return res, nil
}

func ShieldFromAxiom(ax policyir.Axiom) *models.SuggestedShield {
	if ax.ElseShield == "" || !strings.HasPrefix(ax.ElseShield, "shield(") {
		return nil
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(ax.ElseShield, "shield("), ")"))
	if inner == "" {
		return nil
	}
	shieldType, params := parseShieldArgs(inner)
	if shieldType == "" {
		return nil
	}
	return &models.SuggestedShield{Type: shieldType, Params: params}
}

func parseShieldArgs(spec string) (string, map[string]interface{}) {
	args := splitShieldArgs(spec)
	if len(args) == 0 {
		return "", nil
	}
	shieldType := strings.Trim(args[0], " \"")
	if shieldType == "" {
		return "", nil
	}
	params := map[string]interface{}{}
	for _, arg := range args[1:] {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}
		if strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"") {
			params[key] = strings.Trim(val, "\"")
			continue
		}
		if strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'") {
			params[key] = strings.Trim(val, "'")
			continue
		}
		switch strings.ToLower(val) {
		case "true":
			params[key] = true
			continue
		case "false":
			params[key] = false
			continue
		}
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			params[key] = i
			continue
		}
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			params[key] = f
			continue
		}
		params[key] = val
	}
	return shieldType, params
}

func splitShieldArgs(spec string) []string {
	out := []string{}
	var buf strings.Builder
	var quote byte
	inQuote := false
	for i := 0; i < len(spec); i++ {
		ch := spec[i]
		switch ch {
		case '"', '\'':
			if inQuote && ch == quote {
				inQuote = false
			} else if !inQuote {
				inQuote = true
				quote = ch
			}
			buf.WriteByte(ch)
		case ',':
			if inQuote {
				buf.WriteByte(ch)
				continue
			}
			part := strings.TrimSpace(buf.String())
			if part != "" {
				out = append(out, part)
			}
			buf.Reset()
		default:
			buf.WriteByte(ch)
		}
	}
	last := strings.TrimSpace(buf.String())
	if last != "" {
		out = append(out, last)
	}
	return out
}

func applyInvariants(policy *policyir.PolicySetIR) {
	if policy == nil || len(policy.Invariants) == 0 {
		return
	}
	axioms := make([]policyir.Axiom, 0, len(policy.Invariants)+len(policy.Axioms))
	for i, inv := range policy.Invariants {
		id := fmt.Sprintf("Invariant#%d", i+1)
		axioms = append(axioms, policyir.Axiom{ID: id, Requires: []string{inv}})
	}
	axioms = append(axioms, policy.Axioms...)
	policy.Axioms = axioms
}
