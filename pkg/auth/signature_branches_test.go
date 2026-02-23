package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"math"
	"testing"
	"time"

	"axiom/pkg/models"
)

func TestVerifyEd25519Branches(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := models.ActionCert{
		CertID:        "cert-1",
		IntentHash:    "intent-hash",
		PolicySetID:   "finance",
		PolicyVersion: "v1",
		ExpiresAt:     time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
		Nonce:         "nonce-1",
		Signature:     models.Signature{Alg: "rsa", Sig: "bad"},
	}
	if err := VerifyEd25519(pub, cert); err == nil {
		t.Fatal("expected unsupported signature algorithm error")
	}

	cert.Signature.Alg = "ed25519"
	if err := VerifyEd25519(pub, cert); err == nil {
		t.Fatal("expected bad base64 signature decoding error")
	}

	cert.Signature.Sig = base64.StdEncoding.EncodeToString([]byte("short-signature"))
	if err := VerifyEd25519(pub, cert); err == nil {
		t.Fatal("expected invalid signature verification error")
	}
}

func TestSignaturePayloadMarshalFailure(t *testing.T) {
	cert := models.ActionCert{
		CertID:        "cert-1",
		IntentHash:    "intent-hash",
		PolicySetID:   "finance",
		PolicyVersion: "v1",
		Assumptions: models.Assumptions{
			UncertaintyBudget: map[string]interface{}{
				"bad": math.NaN(),
			},
		},
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339),
		Nonce:     "nonce-1",
		Signature: models.Signature{Alg: "ed25519"},
	}
	if _, err := SignaturePayload(cert); err == nil {
		t.Fatal("expected marshal signature payload failure")
	}
}
