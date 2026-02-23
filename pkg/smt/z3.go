package smt

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/policyir"
)

type Z3Options struct {
	Binary  string
	Timeout time.Duration
}

type z3Constraint struct {
	Constraint policyir.Constraint
	SMTExpr    string
}

func EvalPolicyZ3(policy *policyir.PolicySetIR, ctx Context, opts Z3Options) (*AxiomFailure, error) {
	return EvalPolicyZ3Cgo(policy, ctx, opts)
}

func EvalPolicyZ3Exec(policy *policyir.PolicySetIR, ctx Context, opts Z3Options) (*AxiomFailure, error) {
	converted, labelMap, failure, err := prepareZ3Constraints(policy, ctx)
	if err != nil || failure != nil {
		return failure, err
	}
	if len(converted) == 0 {
		return nil, nil
	}
	core, err := runZ3CoreExec(converted, opts)
	if err != nil {
		return nil, err
	}
	if len(core) == 0 {
		return nil, nil
	}
	for _, label := range core {
		if cons, ok := labelMap[label]; ok {
			return &AxiomFailure{Axiom: policyir.Axiom{ID: cons.AxiomID}, Constraint: cons, Facts: MinimalFacts(cons.Expr, ctx)}, nil
		}
	}
	first := core[0]
	if cons, ok := labelMap[first]; ok {
		return &AxiomFailure{Axiom: policyir.Axiom{ID: cons.AxiomID}, Constraint: cons, Facts: MinimalFacts(cons.Expr, ctx)}, nil
	}
	return nil, nil
}

func prepareZ3Constraints(policy *policyir.PolicySetIR, ctx Context) ([]z3Constraint, map[string]policyir.Constraint, *AxiomFailure, error) {
	converted := make([]z3Constraint, 0)
	labelMap := map[string]policyir.Constraint{}
	for _, ax := range policy.Axioms {
		applicable := true
		if strings.TrimSpace(ax.When) != "" {
			ok, err := EvalExpr(ax.When, ctx)
			if err != nil || !ok {
				applicable = false
			}
		}
		if !applicable {
			continue
		}
		for i, req := range ax.Requires {
			cons := policyir.Constraint{ID: fmt.Sprintf("%s#%d", ax.ID, i+1), AxiomID: ax.ID, Expr: req}
			smtExpr, ok := toSMTBoolExpr(req, ctx)
			if ok {
				converted = append(converted, z3Constraint{Constraint: cons, SMTExpr: smtExpr})
				labelMap[sanitizeLabel(cons.ID)] = cons
				continue
			}
			pass, err := EvalExpr(req, ctx)
			if err != nil || !pass {
				return nil, nil, &AxiomFailure{Axiom: ax, Constraint: cons, Facts: MinimalFacts(req, ctx)}, nil
			}
		}
	}
	return converted, labelMap, nil, nil
}

func buildSMTLIB(constraints []z3Constraint) string {
	var b strings.Builder
	b.WriteString("(set-option :produce-unsat-cores true)\n")
	b.WriteString(buildSMTAssertions(constraints))
	b.WriteString("(check-sat)\n")
	b.WriteString("(get-unsat-core)\n")
	return b.String()
}

func runZ3CoreExec(constraints []z3Constraint, opts Z3Options) ([]string, error) {
	if len(constraints) == 0 {
		return nil, nil
	}
	bin, err := resolveZ3Binary(opts.Binary)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- `bin` is constrained to z3/z3.exe and resolved via LookPath in resolveZ3Binary.
	cmd := exec.CommandContext(ctx, bin, "-in", "-smt2")
	cmd.Stdin = strings.NewReader(buildSMTLIB(constraints))
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, errors.New("z3 exec timeout")
	}
	if err != nil {
		return nil, fmt.Errorf("z3 exec failed: %w", err)
	}
	status, core := parseZ3Output(string(out))
	switch status {
	case "sat":
		return nil, nil
	case "unsat":
		return sortedLabels(core), nil
	default:
		if status == "" {
			status = "unknown"
		}
		return nil, fmt.Errorf("z3 unknown: %s", status)
	}
}

func resolveZ3Binary(raw string) (string, error) {
	bin := strings.TrimSpace(raw)
	if bin == "" {
		bin = "z3"
	}
	if strings.ContainsAny(bin, " \t\n\r") {
		return "", errors.New("invalid z3 binary path")
	}
	base := filepath.Base(bin)
	if base != "z3" && base != "z3.exe" {
		return "", fmt.Errorf("unsupported z3 binary %q", base)
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		return "", fmt.Errorf("z3 binary not found: %w", err)
	}
	return resolved, nil
}

func buildSMTAssertions(constraints []z3Constraint) string {
	var b strings.Builder
	b.WriteString("(set-logic QF_LRA)\n")
	for _, c := range constraints {
		b.WriteString("(assert (! ")
		b.WriteString(c.SMTExpr)
		b.WriteString(" :named ")
		b.WriteString(sanitizeLabel(c.Constraint.ID))
		b.WriteString("))\n")
	}
	return b.String()
}

func parseZ3Output(out string) (string, []string) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	status := ""
	coreLine := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "sat" || line == "unsat" || line == "unknown" {
			status = line
			continue
		}
		if status == "unsat" && coreLine == "" {
			coreLine = line
		}
	}
	if status == "" {
		return "unknown", nil
	}
	if status != "unsat" {
		return status, nil
	}
	coreLine = strings.TrimPrefix(coreLine, "(")
	coreLine = strings.TrimSuffix(coreLine, ")")
	if strings.TrimSpace(coreLine) == "" {
		return status, nil
	}
	parts := strings.Fields(coreLine)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return status, parts
}

func sanitizeLabel(label string) string {
	replacer := strings.NewReplacer("#", "_", "-", "_", ".", "_", "/", "_", ":", "_")
	out := replacer.Replace(label)
	if out == "" {
		out = "c0"
	}
	if len(out) > 0 && out[0] >= '0' && out[0] <= '9' {
		out = "c_" + out
	}
	return out
}

func toSMTBoolExpr(expr string, ctx Context) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	if strings.Contains(expr, " and ") {
		parts := strings.Split(expr, " and ")
		smtParts := make([]string, 0, len(parts))
		for _, part := range parts {
			s, ok := toSMTBoolExpr(strings.TrimSpace(part), ctx)
			if !ok {
				return "", false
			}
			smtParts = append(smtParts, s)
		}
		if len(smtParts) == 1 {
			return smtParts[0], true
		}
		return "(and " + strings.Join(smtParts, " ") + ")", true
	}
	ops := []string{"<=", ">=", "==", "!=", "<", ">"}
	for _, op := range ops {
		split := " " + op + " "
		if strings.Contains(expr, split) {
			parts := strings.SplitN(expr, split, 2)
			if len(parts) != 2 {
				return "", false
			}
			left, okL := toSMTArithExpr(strings.TrimSpace(parts[0]), ctx)
			right, okR := toSMTArithExpr(strings.TrimSpace(parts[1]), ctx)
			if !okL || !okR {
				return "", false
			}
			switch op {
			case "<=":
				return "(<= " + left + " " + right + ")", true
			case ">=":
				return "(>= " + left + " " + right + ")", true
			case "<":
				return "(< " + left + " " + right + ")", true
			case ">":
				return "(> " + left + " " + right + ")", true
			case "==":
				return "(= " + left + " " + right + ")", true
			case "!=":
				return "(not (= " + left + " " + right + "))", true
			}
		}
	}
	return "", false
}

func toSMTArithExpr(expr string, ctx Context) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", false
	}
	if n, err := evalNumeric(expr, ctx); err == nil {
		return formatSMTNumber(n), true
	}
	toks, err := splitAddSub(expr)
	if err != nil || len(toks) == 0 {
		return "", false
	}
	if len(toks) == 1 {
		if n, err := evalNumeric(strings.TrimSpace(toks[0]), ctx); err == nil {
			return formatSMTNumber(n), true
		}
		return "", false
	}
	total, err := evalNumeric(expr, ctx)
	if err != nil {
		return "", false
	}
	return formatSMTNumber(total), true
}

func formatSMTNumber(n float64) string {
	if n == float64(int64(n)) {
		return strconv.FormatInt(int64(n), 10)
	}
	s := strconv.FormatFloat(n, 'f', -1, 64)
	if strings.ContainsAny(s, "eE") {
		s = strconv.FormatFloat(n, 'f', 8, 64)
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	return s
}

func sortedLabels(labels []string) []string {
	out := append([]string(nil), labels...)
	sort.Strings(out)
	return out
}
