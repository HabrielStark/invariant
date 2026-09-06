package auth

import (
	"axiom/pkg/models"
	"crypto/ed25519"
	"testing"
)

func TestVerifyEd25519RejectsInvalidKeyLengths(t *testing.T) {
	for _, size := range []int{0, 1, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		cert := models.ActionCert{}
		cert.Signature.Alg = "ed25519"
		if err := VerifyEd25519(make([]byte, size), cert); err == nil {
			t.Fatalf("accepted key length %d", size)
		}
	}
}
