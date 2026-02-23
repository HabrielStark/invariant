package axiomdsl

import (
	"strings"
	"testing"
	"time"
)

func TestParseDSLValidationErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		dsl  string
		want string
	}{
		{
			name: "invalid_header",
			dsl:  "policyset onlytwo\n",
			want: "invalid policyset header",
		},
		{
			name: "dangling_statement",
			dsl:  "policyset finance v1:\nrequire x == y\n",
			want: "dangling statement",
		},
		{
			name: "domain_after_axiom",
			dsl:  "policyset finance v1:\naxiom A:\ndomain finance\n",
			want: "domain must appear before axioms",
		},
		{
			name: "invariant_after_axiom",
			dsl:  "policyset finance v1:\naxiom A:\ninvariant x == y\n",
			want: "invariant must appear before axioms",
		},
		{
			name: "abac_after_axiom",
			dsl:  "policyset finance v1:\naxiom A:\nabac allow when x\n",
			want: "abac rules must appear before axioms",
		},
		{
			name: "rate_limit_after_axiom",
			dsl:  "policyset finance v1:\naxiom A:\nrate limit 1 per minute\n",
			want: "rate limit must appear before axioms",
		},
		{
			name: "approvals_after_axiom",
			dsl:  "policyset finance v1:\naxiom A:\napprovals required 2\n",
			want: "approvals must appear before axioms",
		},
		{
			name: "unknown_statement",
			dsl:  "policyset finance v1:\naxiom A:\nunknown clause\n",
			want: "unknown statement",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDSL(tc.dsl)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParseABACRuleBranches(t *testing.T) {
	t.Parallel()

	if _, err := parseABACRule("abac"); err == nil {
		t.Fatal("expected short rule error")
	}
	if _, err := parseABACRule("wrong allow when x"); err == nil {
		t.Fatal("expected invalid prefix error")
	}
	if _, err := parseABACRule("abac maybe when x"); err == nil {
		t.Fatal("expected invalid effect error")
	}
	if _, err := parseABACRule("abac allow x"); err == nil {
		t.Fatal("expected missing when error")
	}
	if _, err := parseABACRule("abac allow when   "); err == nil {
		t.Fatal("expected missing expression error")
	}
	rule, err := parseABACRule("abac deny when actor.tenant == principal.tenant")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if rule.Effect != "DENY" || rule.When == "" {
		t.Fatalf("unexpected rule: %#v", rule)
	}
}

func TestParseRateLimitBranches(t *testing.T) {
	t.Parallel()

	if _, err := parseRateLimit("rate"); err == nil {
		t.Fatal("expected short rate-limit error")
	}
	if _, err := parseRateLimit("bad limit 1 per minute"); err == nil {
		t.Fatal("expected invalid prefix error")
	}
	if _, err := parseRateLimit("rate limit 0 per minute"); err == nil {
		t.Fatal("expected invalid limit error")
	}
	if _, err := parseRateLimit("rate limit 1 each minute"); err == nil {
		t.Fatal("expected missing per error")
	}
	if _, err := parseRateLimit("rate limit 1 per nonsense"); err == nil {
		t.Fatal("expected invalid duration error")
	}
	rl, err := parseRateLimit("rate limit 2 per 5m scope tenant")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if rl.Window != 5*time.Minute || rl.Scope != "tenant" || !rl.PerTenant {
		t.Fatalf("unexpected rate-limit policy: %#v", rl)
	}
}

func TestParseWindowAliases(t *testing.T) {
	t.Parallel()

	cases := map[string]time.Duration{
		"second": time.Second,
		"sec":    time.Second,
		"s":      time.Second,
		"minute": time.Minute,
		"min":    time.Minute,
		"m":      time.Minute,
		"hour":   time.Hour,
		"hr":     time.Hour,
		"h":      time.Hour,
		"day":    24 * time.Hour,
		"d":      24 * time.Hour,
		"90s":    90 * time.Second,
	}
	for token, want := range cases {
		got, err := parseWindow(token)
		if err != nil {
			t.Fatalf("unexpected parse error for %q: %v", token, err)
		}
		if got != want {
			t.Fatalf("token %q: expected %v, got %v", token, want, got)
		}
	}
	if _, err := parseWindow("bogus-window"); err == nil {
		t.Fatal("expected invalid duration error")
	}
}

func TestParseApprovalsBranches(t *testing.T) {
	t.Parallel()

	if _, err := parseApprovals(nil, "approvals "); err == nil {
		t.Fatal("expected empty approvals body error")
	}
	if _, err := parseApprovals(nil, "approvals required"); err == nil {
		t.Fatal("expected missing approvals number error")
	}
	if _, err := parseApprovals(nil, "approvals required 0"); err == nil {
		t.Fatal("expected invalid approvals number error")
	}
	if _, err := parseApprovals(nil, "approvals roles []"); err == nil {
		t.Fatal("expected empty roles error")
	}
	if _, err := parseApprovals(nil, "approvals expires_in"); err == nil {
		t.Fatal("expected missing expires_in duration error")
	}
	if _, err := parseApprovals(nil, "approvals expires_in nope"); err == nil {
		t.Fatal("expected invalid expires_in duration error")
	}
	if _, err := parseApprovals(nil, "approvals something_else 1"); err == nil {
		t.Fatal("expected unknown approvals clause error")
	}

	ap, err := parseApprovals(nil, "approvals required 2")
	if err != nil {
		t.Fatalf("unexpected required parse error: %v", err)
	}
	ap, err = parseApprovals(ap, "approvals roles [\"manager\",\"security\"]")
	if err != nil {
		t.Fatalf("unexpected roles parse error: %v", err)
	}
	ap, err = parseApprovals(ap, "approvals sod no")
	if err != nil {
		t.Fatalf("unexpected sod parse error: %v", err)
	}
	ap, err = parseApprovals(ap, "approvals expires_in 1h")
	if err != nil {
		t.Fatalf("unexpected expires_in parse error: %v", err)
	}
	if ap.Required != 2 || ap.EnforceSoD || ap.ExpiresIn != time.Hour || len(ap.Roles) != 2 {
		t.Fatalf("unexpected approvals policy: %#v", ap)
	}
}

func TestParseRoleList(t *testing.T) {
	t.Parallel()

	if roles := parseRoleList(""); roles != nil {
		t.Fatalf("expected nil roles, got %#v", roles)
	}
	roles := parseRoleList(`roles ["a","b", ""]`)
	if len(roles) != 2 || roles[0] != "a" || roles[1] != "b" {
		t.Fatalf("unexpected roles: %#v", roles)
	}
}
