package openclaw

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/models"
)

type Signer struct {
	KID        string
	SignerName string
	PrivateKey ed25519.PrivateKey
}

func LoadSigner(cfg Config) (Signer, error) {
	privateB64 := strings.TrimSpace(cfg.PrivateKeyB64)
	if privateB64 == "" && cfg.PrivateKeyPath != "" {
		content, err := os.ReadFile(cfg.PrivateKeyPath)
		if err != nil {
			return Signer{}, fmt.Errorf("read private key: %w", err)
		}
		privateB64 = strings.TrimSpace(string(content))
	}
	if privateB64 == "" {
		return Signer{}, fmt.Errorf("missing private key: set OPENCLAW_SIGNER_PRIVATE_KEY_B64 or OPENCLAW_SIGNER_PRIVATE_KEY_PATH")
	}
	decoded, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return Signer{}, fmt.Errorf("decode private key b64: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return Signer{}, fmt.Errorf("invalid private key length: %d", len(decoded))
	}
	return Signer{KID: cfg.SignerKid, SignerName: cfg.SignerName, PrivateKey: ed25519.PrivateKey(decoded)}, nil
}

func BuildAndSignCert(cfg Config, signer Signer, mapped MappedInvocation, req InvokeRequest, now time.Time) (models.ActionCert, json.RawMessage, error) {
	rollback := models.Rollback{Type: "NONE", Steps: nil}
	if req.RollbackPlan != nil {
		rollback = *req.RollbackPlan
	}
	if rollback.Type == "" && mapped.SideEffecting {
		if cfg.MissingRollbackForceEscrow {
			rollback = models.Rollback{Type: "NONE", Steps: nil}
		} else {
			rollback = models.Rollback{Type: "COMPENSATING_ACTION", Steps: []string{"noop"}}
		}
	}
	if rollback.Type == "" && !mapped.SideEffecting {
		rollback = models.Rollback{Type: "NONE", Steps: nil}
	}

	intentHash := models.IntentHash(mapped.IntentRawCanonical, cfg.PolicyVersion, mapped.Nonce)
	claims := make([]models.Claim, 0, 1)
	if mapped.SideEffecting && (strings.EqualFold(rollback.Type, "NONE") || len(rollback.Steps) == 0) {
		claims = append(claims, models.Claim{Type: "Approval", Statement: "approvals_required >= 1"})
	}
	cert := models.ActionCert{
		CertID:        deriveCertID(mapped.Intent.IdempotencyKey, mapped.Nonce),
		IntentHash:    intentHash,
		PolicySetID:   cfg.PolicySetID,
		PolicyVersion: cfg.PolicyVersion,
		Claims:        claims,
		Assumptions: models.Assumptions{
			AllowedTimeSkewSec: 30,
		},
		Evidence:     models.Evidence{},
		RollbackPlan: rollback,
		ExpiresAt:    mapped.ExpiresAt.UTC().Format(time.RFC3339),
		Nonce:        mapped.Nonce,
		Signature: models.Signature{
			Signer: signer.SignerName,
			Alg:    "ed25519",
			Kid:    signer.KID,
		},
	}
	if snapshotID := strings.TrimSpace(req.SnapshotID); snapshotID != "" {
		cert.Evidence.StateSnapshotRefs = []models.StateSnapshotRef{{Source: "openclaw", SnapshotID: snapshotID, AgeSec: 0}}
	}
	payload, err := auth.SignaturePayload(cert)
	if err != nil {
		return models.ActionCert{}, nil, fmt.Errorf("signature payload: %w", err)
	}
	sig := ed25519.Sign(signer.PrivateKey, payload)
	cert.Signature.Sig = base64.StdEncoding.EncodeToString(sig)
	raw, err := json.Marshal(cert)
	if err != nil {
		return models.ActionCert{}, nil, fmt.Errorf("marshal cert: %w", err)
	}
	return cert, raw, nil
}

func deriveCertID(idempotencyKey, nonce string) string {
	h := sha256.Sum256([]byte(idempotencyKey + "|" + nonce))
	return "cert-" + hex.EncodeToString(h[:10])
}
