package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"axiom/pkg/models"
)

func TestRedactIntentRemovesParams(t *testing.T) {
	intent := models.ActionIntent{
		IntentID:       "intent-1",
		IdempotencyKey: "idem-1",
		Actor:          models.Actor{ID: "actor-1", Roles: []string{"r1"}, Tenant: "t1"},
		ActionType:     "TOOL_CALL",
		Target:         models.Target{Domain: "finance", ObjectTypes: []string{"Invoice"}, ObjectIDs: []string{"inv-1"}, Scope: "single"},
		Operation:      models.Operation{Name: "pay", Params: json.RawMessage(`{"amount":"123.45","ssn":"999-11-2222"}`)},
		Time:           models.TimeSpec{EventTime: "2026-02-03T11:00:00Z", RequestTime: "2026-02-03T11:00:02Z"},
		DataRequirements: models.DataRequirements{
			MaxStalenessSec: 30,
			RequiredSources: []string{"bank"},
			UncertaintyBudget: map[string]interface{}{
				"amount_abs": "1.00",
			},
		},
		SafetyMode: "NORMAL",
	}
	raw, _ := json.Marshal(intent)
	redacted := redactIntent(raw, []byte("salt"))
	if strings.Contains(string(redacted), "ssn") || strings.Contains(string(redacted), "999-11-2222") {
		t.Fatalf("expected params to be redacted: %s", string(redacted))
	}
	if !strings.Contains(string(redacted), "intent_id_hash") {
		t.Fatalf("expected hashed intent id: %s", string(redacted))
	}
}

func TestRedactCertRemovesSignature(t *testing.T) {
	cert := models.ActionCert{
		CertID:        "cert-1",
		IntentHash:    "hash",
		PolicySetID:   "finance",
		PolicyVersion: "v1",
		Claims:        []models.Claim{{Type: "Freshness", Statement: "ok"}},
		Assumptions:   models.Assumptions{AllowedTimeSkewSec: 10},
		Evidence:      models.Evidence{StateSnapshotRefs: []models.StateSnapshotRef{{Source: "bank", SnapshotID: "s1", AgeSec: 3}}},
		RollbackPlan:  models.Rollback{Type: "COMPENSATING_ACTION", Steps: []string{"reverse"}},
		ExpiresAt:     "2026-02-03T11:02:00Z",
		Nonce:         "nonce",
		Signature:     models.Signature{Signer: "s1", Alg: "ed25519", Sig: "rawsig", Kid: "kid-1"},
	}
	raw, _ := json.Marshal(cert)
	redacted := redactCert(raw, []byte("salt"))
	if strings.Contains(string(redacted), "rawsig") {
		t.Fatalf("expected signature to be redacted: %s", string(redacted))
	}
	if !strings.Contains(string(redacted), "sig_hash") {
		t.Fatalf("expected signature hash: %s", string(redacted))
	}
}
