package policyir

import "time"

// PolicySetIR is compiled representation.
type PolicySetIR struct {
	ID         string
	Version    string
	Domain     string
	RateLimit  *RateLimit
	Approvals  *ApprovalPolicy
	Invariants []string
	ABACRules  []ABACRule
	Axioms     []Axiom
}

type Axiom struct {
	ID         string
	When       string
	Requires   []string
	ElseShield string
}

type Constraint struct {
	ID      string
	AxiomID string
	Expr    string
}

type RateLimit struct {
	Limit     int
	Window    time.Duration
	Scope     string
	PerTenant bool
}

type ApprovalPolicy struct {
	Required   int
	Roles      []string
	EnforceSoD bool
	ExpiresIn  time.Duration
}

type ABACRule struct {
	Effect string
	When   string
}
