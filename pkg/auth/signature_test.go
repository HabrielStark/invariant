package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"axiom/pkg/models"
)

func TestSignatureBindsCriticalFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := models.ActionCert{
		CertID:        "cert-1",
		IntentHash:    "intent-hash",
		PolicySetID:   "finance",
		PolicyVersion: "v1",
		Claims:        []models.Claim{{Type: "Freshness", Statement: "bank_feed_age <= 30s"}},
		Assumptions:   models.Assumptions{AllowedTimeSkewSec: 10},
		Evidence:      models.Evidence{StateSnapshotRefs: []models.StateSnapshotRef{{Source: "bank", SnapshotID: "snap-1", AgeSec: 1}}},
		RollbackPlan:  models.Rollback{Type: "COMPENSATING_ACTION", Steps: []string{"reverse_payment"}},
		ExpiresAt:     time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
		Nonce:         "nonce-1",
		Signature:     models.Signature{Alg: "ed25519", Kid: "kid-1"},
	}
	payload, err := SignaturePayload(cert)
	if err != nil {
		t.Fatalf("signature payload: %v", err)
	}
	cert.Signature.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	if err := VerifyEd25519(pub, cert); err != nil {
		t.Fatalf("verify: %v", err)
	}
	cert.PolicySetID = "hr"
	if err := VerifyEd25519(pub, cert); err == nil {
		t.Fatal("expected signature mismatch after policy_set_id change")
	}
}
