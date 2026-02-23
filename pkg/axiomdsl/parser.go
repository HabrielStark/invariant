package axiomdsl

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/policyir"
)

// ParseDSL parses policy DSL into IR.
func ParseDSL(input string) (*policyir.PolicySetIR, error) {
	scanner := bufio.NewScanner(strings.NewReader(input))
	var policy policyir.PolicySetIR
	var current *policyir.Axiom
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "policyset ") {
			// policyset name vX:
			parts := strings.Fields(line)
			if len(parts) < 3 {
				return nil, fmt.Errorf("invalid policyset header at line %d", lineNo)
			}
			policy.ID = parts[1]
			policy.Version = strings.TrimSuffix(parts[2], ":")
			if strings.HasSuffix(policy.Version, ":") {
				policy.Version = strings.TrimSuffix(policy.Version, ":")
			}
			current = nil
			continue
		}
		if strings.HasPrefix(line, "axiom ") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "axiom "), ":")
			ax := policyir.Axiom{ID: name}
			policy.Axioms = append(policy.Axioms, ax)
			current = &policy.Axioms[len(policy.Axioms)-1]
			continue
		}
		if strings.HasPrefix(line, "domain ") {
			if current != nil {
				return nil, fmt.Errorf("domain must appear before axioms at line %d", lineNo)
			}
			policy.Domain = strings.TrimSpace(strings.TrimPrefix(line, "domain "))
			continue
		}
		if strings.HasPrefix(line, "invariant ") {
			if current != nil {
				return nil, fmt.Errorf("invariant must appear before axioms at line %d", lineNo)
			}
			policy.Invariants = append(policy.Invariants, strings.TrimSpace(strings.TrimPrefix(line, "invariant ")))
			continue
		}
		if strings.HasPrefix(line, "abac ") {
			if current != nil {
				return nil, fmt.Errorf("abac rules must appear before axioms at line %d", lineNo)
			}
			rule, err := parseABACRule(line)
			if err != nil {
				return nil, fmt.Errorf("abac rule error at line %d: %w", lineNo, err)
			}
			policy.ABACRules = append(policy.ABACRules, rule)
			continue
		}
		if strings.HasPrefix(line, "rate limit ") {
			if current != nil {
				return nil, fmt.Errorf("rate limit must appear before axioms at line %d", lineNo)
			}
			rl, err := parseRateLimit(line)
			if err != nil {
				return nil, fmt.Errorf("rate limit error at line %d: %w", lineNo, err)
			}
			policy.RateLimit = rl
			continue
		}
		if strings.HasPrefix(line, "approvals ") {
			if current != nil {
				return nil, fmt.Errorf("approvals must appear before axioms at line %d", lineNo)
			}
			ap, err := parseApprovals(policy.Approvals, line)
			if err != nil {
				return nil, fmt.Errorf("approvals error at line %d: %w", lineNo, err)
			}
			policy.Approvals = ap
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("dangling statement at line %d", lineNo)
		}
		switch {
		case strings.HasPrefix(line, "when "):
			current.When = strings.TrimPrefix(line, "when ")
		case strings.HasPrefix(line, "require "):
			current.Requires = append(current.Requires, strings.TrimPrefix(line, "require "))
		case strings.HasPrefix(line, "else shield("):
			current.ElseShield = strings.TrimPrefix(line, "else ")
		default:
			return nil, fmt.Errorf("unknown statement at line %d: %s", lineNo, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &policy, nil
}

func parseABACRule(line string) (policyir.ABACRule, error) {
	// abac allow when <expr>
	// abac deny when <expr>
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return policyir.ABACRule{}, fmt.Errorf("expected 'abac <allow|deny> when <expr>'")
	}
	if strings.ToLower(parts[0]) != "abac" {
		return policyir.ABACRule{}, fmt.Errorf("invalid abac prefix")
	}
	effect := strings.ToLower(parts[1])
	if effect != "allow" && effect != "deny" {
		return policyir.ABACRule{}, fmt.Errorf("effect must be allow or deny")
	}
	if strings.ToLower(parts[2]) != "when" {
		return policyir.ABACRule{}, fmt.Errorf("missing 'when'")
	}
	expr := strings.TrimSpace(strings.TrimPrefix(line, strings.Join(parts[:3], " ")))
	expr = strings.TrimSpace(strings.TrimPrefix(expr, "when "))
	if expr == "" {
		return policyir.ABACRule{}, fmt.Errorf("missing expression")
	}
	return policyir.ABACRule{Effect: strings.ToUpper(effect), When: expr}, nil
}

func parseRateLimit(line string) (*policyir.RateLimit, error) {
	// rate limit <n> per <duration|minute|hour|second> [scope <actor|tenant|global>]
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return nil, fmt.Errorf("expected 'rate limit <n> per <duration>'")
	}
	if strings.ToLower(parts[0]) != "rate" || strings.ToLower(parts[1]) != "limit" {
		return nil, fmt.Errorf("invalid rate limit prefix")
	}
	limit, err := strconv.Atoi(parts[2])
	if err != nil || limit <= 0 {
		return nil, fmt.Errorf("invalid limit")
	}
	if strings.ToLower(parts[3]) != "per" {
		return nil, fmt.Errorf("expected 'per'")
	}
	durToken := strings.ToLower(parts[4])
	window, err := parseWindow(durToken)
	if err != nil {
		return nil, err
	}
	scope := "actor"
	if len(parts) > 5 {
		for i := 5; i < len(parts); i++ {
			if strings.ToLower(parts[i]) == "scope" && i+1 < len(parts) {
				scope = strings.ToLower(parts[i+1])
				break
			}
		}
	}
	rl := &policyir.RateLimit{Limit: limit, Window: window, Scope: scope}
	if scope == "tenant" {
		rl.PerTenant = true
	}
	return rl, nil
}

func parseWindow(token string) (time.Duration, error) {
	switch token {
	case "second", "sec", "s":
		return time.Second, nil
	case "minute", "min", "m":
		return time.Minute, nil
	case "hour", "hr", "h":
		return time.Hour, nil
	case "day", "d":
		return time.Hour * 24, nil
	default:
		if d, err := time.ParseDuration(token); err == nil {
			return d, nil
		}
		return 0, fmt.Errorf("invalid duration %q", token)
	}
}

func parseApprovals(existing *policyir.ApprovalPolicy, line string) (*policyir.ApprovalPolicy, error) {
	ap := existing
	if ap == nil {
		ap = &policyir.ApprovalPolicy{Required: 1, EnforceSoD: true}
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "approvals "))
	if rest == "" {
		return nil, fmt.Errorf("approvals statement missing body")
	}
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return nil, fmt.Errorf("approvals statement missing body")
	}
	switch strings.ToLower(parts[0]) {
	case "required":
		if len(parts) < 2 {
			return nil, fmt.Errorf("approvals required missing number")
		}
		val, err := strconv.Atoi(parts[1])
		if err != nil || val < 1 {
			return nil, fmt.Errorf("invalid approvals required")
		}
		ap.Required = val
	case "roles":
		rolesRaw := strings.TrimSpace(strings.TrimPrefix(rest, parts[0]))
		roles := parseRoleList(rolesRaw)
		if len(roles) == 0 {
			return nil, fmt.Errorf("approvals roles empty")
		}
		ap.Roles = roles
	case "sod":
		if len(parts) == 1 {
			ap.EnforceSoD = true
			return ap, nil
		}
		val := strings.ToLower(strings.TrimSpace(parts[1]))
		ap.EnforceSoD = val == "true" || val == "1" || val == "yes"
	case "expires_in":
		if len(parts) < 2 {
			return nil, fmt.Errorf("approvals expires_in missing duration")
		}
		d, err := parseWindow(parts[1])
		if err != nil {
			return nil, err
		}
		ap.ExpiresIn = d
	default:
		return nil, fmt.Errorf("unknown approvals clause %q", parts[0])
	}
	return ap, nil
}

func parseRoleList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "roles")
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.Trim(strings.TrimSpace(p), "\"")
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
