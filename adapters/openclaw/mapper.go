package openclaw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"axiom/pkg/models"
)

type MappedInvocation struct {
	Intent             models.ActionIntent
	IntentRawCanonical json.RawMessage
	ToolPayload        json.RawMessage
	OperationName      string
	Nonce              string
	ExpiresAt          time.Time
	SideEffecting      bool
}

func MapInvocation(cfg Config, req InvokeRequest, now time.Time) (MappedInvocation, error) {
	now = now.UTC()
	operation := pickFirstNonEmpty(req.Command, req.Tool, req.Action)
	if operation == "" {
		return MappedInvocation{}, fmt.Errorf("tool or command required")
	}
	paramsRaw := req.Params
	if len(paramsRaw) == 0 {
		paramsRaw = req.Args
	}
	paramsCanonical, err := sanitizeAndCanonicalizeParams(paramsRaw)
	if err != nil {
		return MappedInvocation{}, fmt.Errorf("sanitize params: %w", err)
	}
	payload := req.Payload
	if len(strings.TrimSpace(string(payload))) == 0 {
		payload = paramsCanonical
	}

	actorID := pickFirstNonEmpty(req.ActorID, cfg.DefaultActorID)
	if actorID == "" {
		actorID = "openclaw-agent"
	}
	tenant := pickFirstNonEmpty(req.Tenant, cfg.DefaultTenant)
	roles := req.Roles
	if len(roles) == 0 {
		roles = cfg.DefaultRoles
	}
	requestTime := parseRFC3339OrDefault(req.RequestTime, now)
	eventTime := parseRFC3339OrDefault(req.EventTime, requestTime)
	safetyMode := normalizeSafetyMode(pickFirstNonEmpty(req.SafetyMode, cfg.DefaultSafetyMode))
	actionType := normalizeActionType(pickFirstNonEmpty(req.ActionType, cfg.DefaultActionType))
	maxStalenessSec := resolveMaxStaleness(cfg, operation, req.MaxStalenessSec)
	if maxStalenessSec < 0 {
		maxStalenessSec = 0
	}
	idem := strings.TrimSpace(req.IdempotencyKey)
	if idem == "" {
		idem = deriveIdempotencyKey(actorID, tenant, operation, paramsCanonical)
	}

	intent := models.ActionIntent{
		IntentID:       deriveIntentID(idem, operation),
		IdempotencyKey: idem,
		Actor: models.Actor{
			ID:     actorID,
			Roles:  roles,
			Tenant: tenant,
		},
		ActionType: actionType,
		Target: models.Target{
			Domain:      pickFirstNonEmpty(req.Workspace, cfg.DefaultWorkspace, "openclaw"),
			ObjectTypes: []string{"openclaw"},
			ObjectIDs:   []string{operation},
			Scope:       "workspace",
		},
		Operation: models.Operation{
			Name:   operation,
			Params: paramsCanonical,
		},
		Time: models.TimeSpec{
			RequestTime: requestTime.Format(time.RFC3339),
			EventTime:   eventTime.Format(time.RFC3339),
		},
		DataRequirements: models.DataRequirements{
			MaxStalenessSec: maxStalenessSec,
		},
		SafetyMode: safetyMode,
	}
	intentRaw, err := json.Marshal(intent)
	if err != nil {
		return MappedInvocation{}, fmt.Errorf("marshal intent: %w", err)
	}
	intentCanonical, err := models.CanonicalizeJSON(intentRaw)
	if err != nil {
		return MappedInvocation{}, fmt.Errorf("canonicalize intent: %w", err)
	}

	sideEffecting := true
	if req.SideEffecting != nil {
		sideEffecting = *req.SideEffecting
	} else {
		_, sideEffectFree := cfg.SideEffectFreeOps[strings.ToLower(operation)]
		sideEffecting = !sideEffectFree
	}
	expiresAt := now.Add(cfg.CertTTL)
	if expRaw := strings.TrimSpace(req.ExpiresAt); expRaw != "" {
		if expParsed, err := time.Parse(time.RFC3339, expRaw); err == nil {
			expiresAt = expParsed.UTC()
		}
	}
	nonce := strings.TrimSpace(req.Nonce)
	if nonce == "" {
		nonce = deriveNonce(idem, intentCanonical, cfg.PolicyVersion)
	}
	return MappedInvocation{
		Intent:             intent,
		IntentRawCanonical: intentCanonical,
		ToolPayload:        payload,
		OperationName:      operation,
		Nonce:              nonce,
		ExpiresAt:          expiresAt,
		SideEffecting:      sideEffecting,
	}, nil
}

func resolveMaxStaleness(cfg Config, operation string, override *int) int {
	if override != nil {
		return *override
	}
	if val, ok := cfg.MaxStalenessByOperation[strings.ToLower(strings.TrimSpace(operation))]; ok {
		return val
	}
	return cfg.DefaultMaxStalenessSec
}

func deriveIdempotencyKey(actorID, tenant, operation string, paramsCanonical json.RawMessage) string {
	h := sha256.Sum256([]byte(strings.ToLower(actorID) + "|" + strings.ToLower(tenant) + "|" + strings.ToLower(operation) + "|" + string(paramsCanonical)))
	return "ocw-" + hex.EncodeToString(h[:12])
}

func deriveIntentID(idempotencyKey, operation string) string {
	h := sha256.Sum256([]byte(operation + "|" + idempotencyKey))
	return "intent-" + hex.EncodeToString(h[:10])
}

func deriveNonce(idempotencyKey string, intentCanonical json.RawMessage, policyVersion string) string {
	h := sha256.Sum256([]byte(idempotencyKey + "|" + policyVersion + "|" + string(intentCanonical)))
	return hex.EncodeToString(h[:])
}

func parseRFC3339OrDefault(raw string, fallback time.Time) time.Time {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback.UTC()
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return fallback.UTC()
	}
	return parsed.UTC()
}
