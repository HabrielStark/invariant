package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"axiom/pkg/models"
)

// SignaturePayload binds cert to intent hash, policy version and expiry.
func SignaturePayload(cert models.ActionCert) ([]byte, error) {
	binding := struct {
		CertID        string             `json:"cert_id"`
		IntentHash    string             `json:"intent_hash"`
		PolicySetID   string             `json:"policy_set_id"`
		PolicyVersion string             `json:"policy_version"`
		Claims        []models.Claim     `json:"claims"`
		Assumptions   models.Assumptions `json:"assumptions"`
		Evidence      models.Evidence    `json:"evidence"`
		RollbackPlan  models.Rollback    `json:"rollback_plan"`
		ExpiresAt     string             `json:"expires_at"`
		Nonce         string             `json:"nonce"`
		Sequence      *int               `json:"sequence,omitempty"`
	}{
		CertID:        cert.CertID,
		IntentHash:    cert.IntentHash,
		PolicySetID:   cert.PolicySetID,
		PolicyVersion: cert.PolicyVersion,
		Claims:        cert.Claims,
		Assumptions:   cert.Assumptions,
		Evidence:      cert.Evidence,
		RollbackPlan:  cert.RollbackPlan,
		ExpiresAt:     cert.ExpiresAt,
		Nonce:         cert.Nonce,
		Sequence:      cert.Sequence,
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("marshal signature payload: %w", err)
	}
	canon, err := models.CanonicalizeJSONAllowFloat(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalize signature payload: %w", err)
	}
	return canon, nil
}

func VerifyEd25519(pubKey ed25519.PublicKey, cert models.ActionCert) error {
	if cert.Signature.Alg != "ed25519" {
		return errors.New("unsupported signature alg")
	}
	payload, err := SignaturePayload(cert)
	if err != nil {
		return err
	}
	sigBytes, err := base64.StdEncoding.DecodeString(cert.Signature.Sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, payload, sigBytes) {
		return errors.New("invalid signature")
	}
	return nil
}
