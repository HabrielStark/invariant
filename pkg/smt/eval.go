package smt

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"axiom/pkg/models"
	"axiom/pkg/policyir"
)

type Context struct {
	Intent     models.ActionIntent
	Params     map[string]string
	Budgets    map[string]float64
	Belief     models.BeliefState
	Principal  models.Actor
	Attributes map[string]string
}

type AxiomFailure struct {
	Axiom      policyir.Axiom
	Constraint policyir.Constraint
	Facts      []string
}

// EvalConstraints evaluates constraints and returns failed constraints.
func EvalConstraints(constraints []policyir.Constraint, ctx Context) (failed []policyir.Constraint) {
	for _, c := range constraints {
		ok, err := EvalExpr(c.Expr, ctx)
		if err != nil || !ok {
			failed = append(failed, c)
		}
	}
	return failed
}

// EvalPolicy evaluates policy axioms honoring `when` predicates.
func EvalPolicy(policy *policyir.PolicySetIR, ctx Context) *AxiomFailure {
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
			ok, err := EvalExpr(req, ctx)
			if err != nil || !ok {
				return &AxiomFailure{
					Axiom:      ax,
					Constraint: policyir.Constraint{ID: fmt.Sprintf("%s#%d", ax.ID, i+1), AxiomID: ax.ID, Expr: req},
					Facts:      MinimalFacts(req, ctx),
				}
			}
		}
	}
	return nil
}

// EvalExpr evaluates a supported expression.
func EvalExpr(expr string, ctx Context) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false, fmt.Errorf("empty expr")
	}
	if strings.Contains(expr, " and ") {
		parts := strings.Split(expr, " and ")
		for _, p := range parts {
			ok, err := EvalExpr(p, ctx)
			if err != nil || !ok {
				return false, err
			}
		}
		return true, nil
	}
	if strings.Contains(expr, " in [") {
		parts := strings.SplitN(expr, " in [", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSuffix(parts[1], "]")
		items := strings.Split(right, ",")
		lv, ok := resolveString(left, ctx)
		if !ok {
			return false, fmt.Errorf("unknown left")
		}
		for _, it := range items {
			item := strings.Trim(strings.TrimSpace(it), "\"")
			if lv == item {
				return true, nil
			}
		}
		return false, nil
	}
	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		if left == "actor.role" || left == "actor.roles" {
			for _, r := range ctx.Intent.Actor.Roles {
				if r == right {
					return true, nil
				}
			}
			return false, nil
		}
		if left == "principal.role" || left == "principal.roles" {
			for _, r := range ctx.Principal.Roles {
				if r == right {
					return true, nil
				}
			}
			return false, nil
		}
		return false, fmt.Errorf("unknown contains")
	}
	for _, op := range []string{"<=", ">=", "==", "!=", "<", ">"} {
		if strings.Contains(expr, " "+op+" ") {
			parts := strings.SplitN(expr, " "+op+" ", 2)
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			ln, lerr := evalNumeric(left, ctx)
			rn, rerr := evalNumeric(right, ctx)
			if lerr == nil && rerr == nil {
				switch op {
				case "<=":
					return ln <= rn, nil
				case ">=":
					return ln >= rn, nil
				case "<":
					return ln < rn, nil
				case ">":
					return ln > rn, nil
				case "==":
					return math.Abs(ln-rn) < 1e-9, nil
				case "!=":
					return math.Abs(ln-rn) >= 1e-9, nil
				}
			}
			if op == "==" || op == "!=" {
				lv, ok := resolveString(left, ctx)
				if !ok {
					return false, fmt.Errorf("unsupported comparison")
				}
				rv := strings.Trim(right, "\"")
				if op == "==" {
					return lv == rv, nil
				}
				return lv != rv, nil
			}
			return false, fmt.Errorf("unsupported numeric comparison")
		}
	}
	return false, fmt.Errorf("unsupported expr")
}

func MinimalFacts(expr string, ctx Context) []string {
	facts := map[string]struct{}{}
	collectFacts(expr, ctx, facts)
	out := make([]string, 0, len(facts))
	for fact := range facts {
		out = append(out, fact)
	}
	sort.Strings(out)
	return out
}

func collectFacts(expr string, ctx Context, facts map[string]struct{}) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return
	}
	if strings.Contains(expr, " and ") {
		parts := strings.Split(expr, " and ")
		for _, part := range parts {
			collectFacts(part, ctx, facts)
		}
		return
	}
	if strings.Contains(expr, " in [") {
		parts := strings.SplitN(expr, " in [", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.TrimSuffix(parts[1], "]")
		if lv, ok := resolveValue(left, ctx); ok {
			addFact(facts, left, lv)
		}
		list := strings.Join(strings.FieldsFunc(right, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }), ",")
		if list != "" {
			addFact(facts, "allowed", "["+list+"]")
		}
		return
	}
	if strings.Contains(expr, " contains ") {
		parts := strings.SplitN(expr, " contains ", 2)
		left := strings.TrimSpace(parts[0])
		right := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch left {
		case "actor.role", "actor.roles":
			if len(ctx.Intent.Actor.Roles) > 0 {
				addFact(facts, "actor.roles", strings.Join(ctx.Intent.Actor.Roles, ","))
			}
		case "principal.role", "principal.roles":
			if len(ctx.Principal.Roles) > 0 {
				addFact(facts, "principal.roles", strings.Join(ctx.Principal.Roles, ","))
			}
		}
		if right != "" {
			addFact(facts, "required", right)
		}
		return
	}
	for _, op := range []string{"<=", ">=", "==", "!=", "<", ">"} {
		if strings.Contains(expr, " "+op+" ") {
			parts := strings.SplitN(expr, " "+op+" ", 2)
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			collectComparisonFacts(left, right, op, ctx, facts)
			return
		}
	}
}

func collectComparisonFacts(left, right, op string, ctx Context, facts map[string]struct{}) {
	if lv, ok := resolveValue(left, ctx); ok {
		addFact(facts, left, lv)
	} else if lit, ok := parseLiteralNumber(left); ok {
		addFact(facts, boundKey(op, "left"), formatFactNumber(lit))
	}
	if rv, ok := resolveValue(right, ctx); ok {
		addFact(facts, right, rv)
	} else if lit, ok := parseLiteralNumber(right); ok {
		addFact(facts, boundKey(op, "right"), formatFactNumber(lit))
	} else if s, ok := parseLiteralString(right); ok {
		addFact(facts, literalStringKey(op), s)
	}
}

func resolveValue(expr string, ctx Context) (string, bool) {
	if _, ok := parseLiteralNumber(expr); ok {
		return "", false
	}
	if s, ok := parseLiteralString(expr); ok {
		return s, true
	}
	if n, err := evalNumeric(expr, ctx); err == nil {
		return formatFactNumber(n), true
	}
	if s, ok := resolveString(expr, ctx); ok {
		return s, true
	}
	return "", false
}

func parseLiteralNumber(expr string) (float64, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, false
	}
	for _, r := range expr {
		if !(unicode.IsDigit(r) || r == '.' || r == '-' || r == '+' || r == 'e' || r == 'E') {
			return 0, false
		}
	}
	v, err := strconv.ParseFloat(expr, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func parseLiteralString(expr string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if len(expr) < 2 {
		return "", false
	}
	if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") {
		return strings.Trim(expr, "\""), true
	}
	return "", false
}

func boundKey(op, side string) string {
	switch op {
	case "<", "<=":
		if side == "right" {
			return "max"
		}
		return "min"
	case ">", ">=":
		if side == "right" {
			return "min"
		}
		return "max"
	case "==":
		return "eq"
	case "!=":
		return "neq"
	default:
		return "value"
	}
}

func literalStringKey(op string) string {
	switch op {
	case "!=":
		return "forbidden"
	default:
		return "expected"
	}
}

func formatFactNumber(n float64) string {
	if n == float64(int64(n)) {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'f', -1, 64)
}

func addFact(facts map[string]struct{}, key, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	facts[key+"="+value] = struct{}{}
}

func resolveString(key string, ctx Context) (string, bool) {
	switch key {
	case "action.name":
		return ctx.Intent.Operation.Name, true
	case "action.scope":
		return ctx.Intent.Target.Scope, true
	case "actor.id":
		return ctx.Intent.Actor.ID, true
	case "actor.tenant":
		return ctx.Intent.Actor.Tenant, true
	case "target.domain":
		return ctx.Intent.Target.Domain, true
	case "principal.id", "principal.subject":
		return ctx.Principal.ID, true
	case "principal.tenant":
		return ctx.Principal.Tenant, true
	default:
		if strings.HasPrefix(key, "principal.attr.") {
			if v, ok := ctx.Attributes[strings.TrimPrefix(key, "principal.attr.")]; ok {
				return v, true
			}
		}
		if strings.HasPrefix(key, "attr.") {
			if v, ok := ctx.Attributes[strings.TrimPrefix(key, "attr.")]; ok {
				return v, true
			}
		}
		return "", false
	}
}

func resolveNumber(key string, ctx Context) (float64, bool) {
	switch {
	case key == "batch.size":
		return float64(len(ctx.Intent.Target.ObjectIDs)), true
	case strings.HasPrefix(key, "source(\"") && strings.HasSuffix(key, "\").health_score"):
		source := sourceKey(key, "health_score")
		for _, s := range ctx.Belief.Sources {
			if s.Source == source {
				return s.HealthScore, true
			}
		}
		return 0, false
	case strings.HasPrefix(key, "source(\"") && strings.HasSuffix(key, "\").lag_sec"):
		source := sourceKey(key, "lag_sec")
		for _, s := range ctx.Belief.Sources {
			if s.Source == source {
				return float64(s.LagSec), true
			}
		}
		return 0, false
	case key == "source(\"bank\").age_sec" || (strings.HasPrefix(key, "source(\"") && strings.HasSuffix(key, "\").age_sec")):
		source := sourceKey(key, "age_sec")
		for _, s := range ctx.Belief.Sources {
			if s.Source == source {
				return float64(s.AgeSec), true
			}
		}
		return 0, false
	case strings.HasPrefix(key, "budget.remaining(\"") && strings.HasSuffix(key, "\")"):
		code := strings.TrimSuffix(strings.TrimPrefix(key, "budget.remaining(\""), "\")")
		if v, ok := ctx.Budgets[strings.ToUpper(code)]; ok {
			return v, true
		}
		return 0, false
	case strings.HasPrefix(key, "action.params."):
		param := strings.TrimPrefix(key, "action.params.")
		if v, ok := ctx.Params[param]; ok {
			fv, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, false
			}
			return fv, true
		}
	case strings.HasPrefix(key, "principal.attr."):
		if v, ok := ctx.Attributes[strings.TrimPrefix(key, "principal.attr.")]; ok {
			fv, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, false
			}
			return fv, true
		}
	case strings.HasPrefix(key, "attr."):
		if v, ok := ctx.Attributes[strings.TrimPrefix(key, "attr.")]; ok {
			fv, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return 0, false
			}
			return fv, true
		}
	}
	return 0, false
}

func parseNumber(s string) (float64, error) {
	s = strings.Trim(s, "\"")
	if strings.HasPrefix(s, "eps(") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "eps("), ")")
	}
	return strconv.ParseFloat(s, 64)
}

func sourceKey(expr string, field string) string {
	prefix := "source(\""
	suffix := "\")." + field
	return strings.TrimSuffix(strings.TrimPrefix(expr, prefix), suffix)
}

func evalNumeric(expr string, ctx Context) (float64, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return 0, fmt.Errorf("empty numeric expr")
	}
	if v, ok := resolveNumber(expr, ctx); ok {
		return v, nil
	}
	if strings.HasPrefix(expr, "eps(") && strings.HasSuffix(expr, ")") {
		return parseNumber(expr)
	}
	if n, err := parseNumber(expr); err == nil {
		return n, nil
	}
	tokens, err := splitAddSub(expr)
	if err != nil {
		return 0, err
	}
	if len(tokens) == 0 {
		return 0, fmt.Errorf("invalid numeric expr")
	}
	if len(tokens) == 1 && strings.TrimSpace(tokens[0]) == expr {
		return 0, fmt.Errorf("unknown numeric term")
	}
	total := 0.0
	sign := 1.0
	for i, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if tok == "+" {
			sign = 1
			continue
		}
		if tok == "-" {
			sign = -1
			continue
		}
		v, err := evalNumeric(tok, ctx)
		if err != nil {
			if i == 0 {
				return 0, err
			}
			return 0, fmt.Errorf("invalid term %q: %w", tok, err)
		}
		total += sign * v
		sign = 1
	}
	return total, nil
}

func splitAddSub(expr string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	depth := 0
	inQuote := false
	escaped := false
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if escaped {
			cur.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && inQuote {
			cur.WriteByte(ch)
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			cur.WriteByte(ch)
			continue
		}
		if inQuote {
			cur.WriteByte(ch)
			continue
		}
		switch ch {
		case '(':
			depth++
			cur.WriteByte(ch)
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced parentheses")
			}
			cur.WriteByte(ch)
		case '+', '-':
			if depth == 0 {
				if strings.TrimSpace(cur.String()) != "" {
					tokens = append(tokens, cur.String())
					cur.Reset()
				}
				tokens = append(tokens, string(ch))
			} else {
				cur.WriteByte(ch)
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if depth != 0 || inQuote {
		return nil, fmt.Errorf("unterminated expression")
	}
	if strings.TrimSpace(cur.String()) != "" {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}

// BuildContext builds SMT context from intent and belief.
func BuildContext(intent models.ActionIntent, belief models.BeliefState) Context {
	return BuildContextWithPrincipal(intent, belief, models.Actor{}, nil)
}

// BuildContextWithPrincipal builds SMT context with principal and attributes.
func BuildContextWithPrincipal(intent models.ActionIntent, belief models.BeliefState, principal models.Actor, attrs map[string]string) Context {
	params := map[string]string{}
	budgets := map[string]float64{}
	for k, v := range intent.DataRequirements.UncertaintyBudget {
		code := strings.ToUpper(strings.TrimSpace(k))
		if code == "" {
			continue
		}
		switch t := v.(type) {
		case string:
			if fv, err := strconv.ParseFloat(t, 64); err == nil {
				budgets[code] = fv
			}
		case float64:
			budgets[code] = t
		case json.Number:
			if fv, err := strconv.ParseFloat(t.String(), 64); err == nil {
				budgets[code] = fv
			}
		}
	}
	if len(intent.Operation.Params) > 0 {
		var raw map[string]interface{}
		if err := json.Unmarshal(intent.Operation.Params, &raw); err == nil {
			for k, v := range raw {
				switch t := v.(type) {
				case string:
					params[k] = t
					if fv, err := strconv.ParseFloat(t, 64); err == nil {
						up := strings.ToUpper(k)
						if strings.HasPrefix(up, "BUDGET_") && strings.HasSuffix(up, "_REMAINING") {
							code := strings.TrimSuffix(strings.TrimPrefix(up, "BUDGET_"), "_REMAINING")
							budgets[code] = fv
						}
						if strings.HasPrefix(up, "BUDGET_REMAINING_") {
							code := strings.TrimPrefix(up, "BUDGET_REMAINING_")
							budgets[code] = fv
						}
					}
				case json.Number:
					params[k] = t.String()
					if fv, err := strconv.ParseFloat(t.String(), 64); err == nil {
						up := strings.ToUpper(k)
						if strings.HasPrefix(up, "BUDGET_") && strings.HasSuffix(up, "_REMAINING") {
							code := strings.TrimSuffix(strings.TrimPrefix(up, "BUDGET_"), "_REMAINING")
							budgets[code] = fv
						}
						if strings.HasPrefix(up, "BUDGET_REMAINING_") {
							code := strings.TrimPrefix(up, "BUDGET_REMAINING_")
							budgets[code] = fv
						}
					}
				}
			}
		}
	}
	if attrs == nil {
		attrs = map[string]string{}
	}
	return Context{Intent: intent, Params: params, Budgets: budgets, Belief: belief, Principal: principal, Attributes: attrs}
}
