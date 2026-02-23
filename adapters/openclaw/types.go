package openclaw

import (
	"encoding/json"

	"axiom/pkg/models"
)

// InvokeRequest is the canonical OpenClaw->Invariant adapter input payload.
type InvokeRequest struct {
	Tool            string            `json:"tool,omitempty"`
	Command         string            `json:"command,omitempty"`
	Action          string            `json:"action,omitempty"`
	Args            json.RawMessage   `json:"args,omitempty"`
	Params          json.RawMessage   `json:"params,omitempty"`
	Payload         json.RawMessage   `json:"payload,omitempty"`
	IdempotencyKey  string            `json:"idempotency_key,omitempty"`
	ActorID         string            `json:"actor_id,omitempty"`
	Roles           []string          `json:"roles,omitempty"`
	Tenant          string            `json:"tenant,omitempty"`
	Workspace       string            `json:"workspace,omitempty"`
	RequestTime     string            `json:"request_time,omitempty"`
	EventTime       string            `json:"event_time,omitempty"`
	MaxStalenessSec *int              `json:"max_staleness_sec,omitempty"`
	SafetyMode      string            `json:"safety_mode,omitempty"`
	Nonce           string            `json:"nonce,omitempty"`
	ExpiresAt       string            `json:"expires_at,omitempty"`
	ActionType      string            `json:"action_type,omitempty"`
	RollbackPlan    *models.Rollback  `json:"rollback_plan,omitempty"`
	SideEffecting   *bool             `json:"side_effecting,omitempty"`
	SnapshotID      string            `json:"snapshot_id,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	Source          string            `json:"source,omitempty"`
}

// InvokeResponse is adapter output for OpenClaw callers.
type InvokeResponse struct {
	OK             bool                    `json:"ok"`
	Verdict        string                  `json:"verdict,omitempty"`
	ReasonCode     string                  `json:"reason_code,omitempty"`
	Result         json.RawMessage         `json:"result,omitempty"`
	Preview        json.RawMessage         `json:"preview,omitempty"`
	RetryAfterMS   int                     `json:"retry_after_ms,omitempty"`
	Shield         *models.SuggestedShield `json:"shield,omitempty"`
	Escrow         *models.EscrowRef       `json:"escrow,omitempty"`
	Batch          *models.BatchPartition  `json:"batch,omitempty"`
	Counterexample *models.Counterexample  `json:"counterexample,omitempty"`
	Error          *InvokeError            `json:"error,omitempty"`
}

type InvokeError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type GatewayExecuteRequest struct {
	Intent      json.RawMessage `json:"intent"`
	Cert        json.RawMessage `json:"cert"`
	ToolPayload json.RawMessage `json:"tool_payload,omitempty"`
}
