package models

import (
	"encoding/json"
	"time"
)

// ActionIntent represents a requested action.
type ActionIntent struct {
	IntentID         string           `json:"intent_id"`
	IdempotencyKey   string           `json:"idempotency_key"`
	Actor            Actor            `json:"actor"`
	ActionType       string           `json:"action_type"`
	Target           Target           `json:"target"`
	Operation        Operation        `json:"operation"`
	Time             TimeSpec         `json:"time"`
	DataRequirements DataRequirements `json:"data_requirements"`
	SafetyMode       string           `json:"safety_mode"`
}

type Actor struct {
	ID     string   `json:"id"`
	Roles  []string `json:"roles"`
	Tenant string   `json:"tenant"`
}

type Target struct {
	Domain      string   `json:"domain"`
	ObjectTypes []string `json:"object_types"`
	ObjectIDs   []string `json:"object_ids"`
	Scope       string   `json:"scope"`
}

type Operation struct {
	Name   string          `json:"name"`
	Params json.RawMessage `json:"params"`
}

type TimeSpec struct {
	EventTime   string `json:"event_time"`
	RequestTime string `json:"request_time"`
}

type DataRequirements struct {
	MaxStalenessSec   int                    `json:"max_staleness_sec"`
	RequiredSources   []string               `json:"required_sources"`
	UncertaintyBudget map[string]interface{} `json:"uncertainty_budget"`
}

// ActionCert is proof-carrying certificate
// Signature is computed over cert binding fields (see signer).
type ActionCert struct {
	CertID        string      `json:"cert_id"`
	IntentHash    string      `json:"intent_hash"`
	PolicySetID   string      `json:"policy_set_id"`
	PolicyVersion string      `json:"policy_version"`
	Claims        []Claim     `json:"claims"`
	Assumptions   Assumptions `json:"assumptions"`
	Evidence      Evidence    `json:"evidence"`
	RollbackPlan  Rollback    `json:"rollback_plan"`
	ExpiresAt     string      `json:"expires_at"`
	Nonce         string      `json:"nonce"`
	Sequence      *int        `json:"sequence,omitempty"`
	Signature     Signature   `json:"signature"`
}

type Claim struct {
	Type      string `json:"type"`
	Statement string `json:"statement"`
}

type Assumptions struct {
	OpenSystemTerms    []OpenTerm             `json:"open_system_terms"`
	UncertaintyBudget  map[string]interface{} `json:"uncertainty_budget"`
	AllowedTimeSkewSec int                    `json:"allowed_time_skew_sec"`
}

type OpenTerm struct {
	Name       string  `json:"name"`
	MaxRate    float64 `json:"max_rate"`
	WindowDays int     `json:"window_days"`
}

type Evidence struct {
	StateSnapshotRefs []StateSnapshotRef `json:"state_snapshot_refs"`
	Attestations      []Attestation      `json:"attestations"`
}

type StateSnapshotRef struct {
	Source     string `json:"source"`
	SnapshotID string `json:"snapshot_id"`
	AgeSec     int    `json:"age_sec"`
}

type Attestation struct {
	Issuer string `json:"issuer"`
	Type   string `json:"type"`
	Sig    string `json:"sig"`
}

type Rollback struct {
	Type  string   `json:"type"`
	Steps []string `json:"steps"`
}

type Signature struct {
	Signer string `json:"signer"`
	Alg    string `json:"alg"`
	Sig    string `json:"sig"`
	Kid    string `json:"kid,omitempty"`
}

// VerifierResponse is returned by verifier.
type VerifierResponse struct {
	Verdict         string           `json:"verdict"`
	ReasonCode      string           `json:"reason_code"`
	Counterexample  *Counterexample  `json:"counterexample,omitempty"`
	SuggestedShield *SuggestedShield `json:"suggested_shield,omitempty"`
	RetryAfterMS    int              `json:"retry_after_ms,omitempty"`
}

type Counterexample struct {
	MinimalFacts []string `json:"minimal_facts"`
	FailedAxioms []string `json:"failed_axioms"`
}

type SuggestedShield struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`
}

// GatewayResponse is returned by gateway endpoints.
type GatewayResponse struct {
	Verdict        string           `json:"verdict"`
	ReasonCode     string           `json:"reason_code"`
	PolicySetID    string           `json:"policy_set_id,omitempty"`
	PolicyVersion  string           `json:"policy_version,omitempty"`
	RetryAfterMS   int              `json:"retry_after_ms,omitempty"`
	Result         json.RawMessage  `json:"result,omitempty"`
	Shield         *SuggestedShield `json:"shield,omitempty"`
	Escrow         *EscrowRef       `json:"escrow,omitempty"`
	Batch          *BatchPartition  `json:"batch,omitempty"`
	Counterexample *Counterexample  `json:"counterexample,omitempty"`
}

type BatchItemVerdict struct {
	ObjectID   string `json:"object_id"`
	Verdict    string `json:"verdict"`
	ReasonCode string `json:"reason_code,omitempty"`
}

type BatchPartition struct {
	Scope     string             `json:"scope"`
	Total     int                `json:"total"`
	AllowIDs  []string           `json:"allow_ids,omitempty"`
	EscrowIDs []string           `json:"escrow_ids,omitempty"`
	DenyIDs   []string           `json:"deny_ids,omitempty"`
	DeferIDs  []string           `json:"defer_ids,omitempty"`
	Items     []BatchItemVerdict `json:"items,omitempty"`
}

type EscrowRef struct {
	EscrowID string `json:"escrow_id"`
	Status   string `json:"status"`
	TTL      string `json:"ttl"`
}

// BeliefState snapshot
type BeliefState struct {
	SnapshotID string        `json:"snapshot_id"`
	Tenant     string        `json:"tenant,omitempty"`
	Domain     string        `json:"domain"`
	Sources    []SourceState `json:"sources"`
	CreatedAt  string        `json:"created_at"`
}

type SourceState struct {
	Source      string  `json:"source"`
	AgeSec      int     `json:"age_sec"`
	HealthScore float64 `json:"health_score"`
	LagSec      int     `json:"lag_sec"`
	JitterSec   int     `json:"jitter_sec"`
}

// Policy structures

type PolicySet struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Domain        string `json:"domain"`
	Version       string `json:"version"`
	EffectiveFrom string `json:"effective_from"`
	EffectiveTo   string `json:"effective_to"`
	DSL           string `json:"dsl"`
}

// Escrow

type Escrow struct {
	EscrowID          string    `json:"escrow_id"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	ApprovalsRequired int       `json:"approvals_required"`
	ApprovalsReceived int       `json:"approvals_received"`
}

type DecisionSummary struct {
	DecisionID     string    `json:"decision_id"`
	IdempotencyKey string    `json:"idempotency_key"`
	Verdict        string    `json:"verdict"`
	ReasonCode     string    `json:"reason_code"`
	CreatedAt      time.Time `json:"created_at"`
}

type Incident struct {
	IncidentID     string          `json:"incident_id"`
	DecisionID     string          `json:"decision_id,omitempty"`
	Severity       string          `json:"severity"`
	Category       string          `json:"category"`
	ReasonCode     string          `json:"reason_code"`
	Status         string          `json:"status"`
	Title          string          `json:"title"`
	Details        json.RawMessage `json:"details,omitempty"`
	AcknowledgedBy string          `json:"acknowledged_by,omitempty"`
	ResolvedBy     string          `json:"resolved_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	ResolvedAt     *time.Time      `json:"resolved_at,omitempty"`
}

type SubjectRestriction struct {
	Tenant      string     `json:"tenant,omitempty"`
	ActorIDHash string     `json:"actor_id_hash"`
	Reason      string     `json:"reason"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LiftedBy    string     `json:"lifted_by,omitempty"`
	LiftedAt    *time.Time `json:"lifted_at,omitempty"`
}
