package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"axiom/pkg/models"
)

func redactRecord(rec Record, salt []byte) Record {
	rec.IntentRaw = redactIntent(rec.IntentRaw, salt)
	rec.CertRaw = redactCert(rec.CertRaw, salt)
	return rec
}

func redactIntent(raw json.RawMessage, salt []byte) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var intent models.ActionIntent
	if err := json.Unmarshal(raw, &intent); err != nil {
		payload := map[string]interface{}{
			"intent_hash":     hashBytes(raw, salt),
			"redaction_error": "invalid_json",
		}
		b, _ := json.Marshal(payload)
		return b
	}
	paramsHash := hashJSONRaw(intent.Operation.Params, salt)
	budgetHash := hashJSON(intent.DataRequirements.UncertaintyBudget, salt)
	redacted := map[string]interface{}{
		"intent_id_hash":       hashString(intent.IntentID, salt),
		"idempotency_key_hash": hashString(intent.IdempotencyKey, salt),
		"actor": map[string]interface{}{
			"id_hash": hashString(intent.Actor.ID, salt),
			"roles":   intent.Actor.Roles,
			"tenant":  intent.Actor.Tenant,
		},
		"action_type": intent.ActionType,
		"target": map[string]interface{}{
			"domain":          intent.Target.Domain,
			"object_types":    intent.Target.ObjectTypes,
			"object_ids_hash": hashStrings(intent.Target.ObjectIDs, salt),
			"scope":           intent.Target.Scope,
		},
		"operation": map[string]interface{}{
			"name":        intent.Operation.Name,
			"params_hash": paramsHash,
		},
		"time": intent.Time,
		"data_requirements": map[string]interface{}{
			"max_staleness_sec":       intent.DataRequirements.MaxStalenessSec,
			"required_sources":        intent.DataRequirements.RequiredSources,
			"uncertainty_budget_hash": budgetHash,
		},
		"safety_mode": intent.SafetyMode,
	}
	b, _ := json.Marshal(redacted)
	return b
}

func redactCert(raw json.RawMessage, salt []byte) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var cert models.ActionCert
	if err := json.Unmarshal(raw, &cert); err != nil {
		payload := map[string]interface{}{
			"cert_hash":       hashBytes(raw, salt),
			"redaction_error": "invalid_json",
		}
		b, _ := json.Marshal(payload)
		return b
	}
	redacted := map[string]interface{}{
		"cert_id_hash":     hashString(cert.CertID, salt),
		"intent_hash":      cert.IntentHash,
		"policy_set_id":    cert.PolicySetID,
		"policy_version":   cert.PolicyVersion,
		"claims_hash":      hashJSON(cert.Claims, salt),
		"assumptions_hash": hashJSON(cert.Assumptions, salt),
		"evidence_hash":    hashJSON(cert.Evidence, salt),
		"rollback_hash":    hashJSON(cert.RollbackPlan, salt),
		"expires_at":       cert.ExpiresAt,
		"nonce_hash":       hashString(cert.Nonce, salt),
		"sequence":         cert.Sequence,
		"signature": map[string]interface{}{
			"signer":   cert.Signature.Signer,
			"alg":      cert.Signature.Alg,
			"kid":      cert.Signature.Kid,
			"sig_hash": hashString(cert.Signature.Sig, salt),
		},
	}
	b, _ := json.Marshal(redacted)
	return b
}

func hashStrings(values []string, salt []byte) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, hashString(v, salt))
	}
	return out
}

func hashJSON(v interface{}, salt []byte) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	canon, err := models.CanonicalizeJSONAllowFloat(raw)
	if err != nil {
		return hashBytes(raw, salt)
	}
	return hashBytes(canon, salt)
}

func hashJSONRaw(raw json.RawMessage, salt []byte) string {
	if len(raw) == 0 {
		return ""
	}
	canon, err := models.CanonicalizeJSONAllowFloat(raw)
	if err != nil {
		return hashBytes(raw, salt)
	}
	return hashBytes(canon, salt)
}

func hashString(v string, salt []byte) string {
	return hashBytes([]byte(v), salt)
}

func hashBytes(b []byte, salt []byte) string {
	h := sha256.New()
	if len(salt) > 0 {
		_, _ = h.Write(salt)
	}
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
