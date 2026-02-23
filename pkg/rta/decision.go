package rta

import (
	"time"

	"axiom/pkg/models"
	"axiom/pkg/shield"
)

const (
	VerdictAllow  = "ALLOW"
	VerdictShield = "SHIELD"
	VerdictDefer  = "DEFER"
	VerdictEscrow = "ESCROW"
	VerdictDeny   = "DENY"
)

type Config struct {
	MaxVerifyTime   time.Duration
	MaxDeferTotal   time.Duration
	MaxEscrowTTL    time.Duration
	DegradedNoAllow bool
}

type Inputs struct {
	VerifierResp *models.VerifierResponse
	StateFresh   bool
	StateUnknown bool
	HasRollback  bool
	CriticalFail bool
	Degraded     bool
	DeferExpired bool
}

// Decide returns a verdict and optional shield suggestion.
func Decide(cfg Config, in Inputs) (string, *models.SuggestedShield, string) {
	if in.Degraded && cfg.DegradedNoAllow {
		return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), "DEGRADED_MODE"
	}
	if in.StateUnknown {
		return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), "STATE_UNKNOWN"
	}
	if !in.StateFresh {
		return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), "STATE_STALE"
	}
	if in.VerifierResp == nil {
		if in.DeferExpired {
			if in.HasRollback {
				return VerdictEscrow, nil, "DEFER_LIMIT_ESCROW"
			}
			return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), "DEFER_LIMIT_SHIELD"
		}
		return VerdictDefer, nil, "VERIFY_TIMEOUT"
	}
	switch in.VerifierResp.Verdict {
	case VerdictAllow:
		if !in.HasRollback {
			return VerdictEscrow, nil, "ROLLBACK_REQUIRED"
		}
		return VerdictAllow, nil, "OK"
	case VerdictShield:
		if in.VerifierResp.SuggestedShield != nil {
			return VerdictShield, in.VerifierResp.SuggestedShield, in.VerifierResp.ReasonCode
		}
		return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), in.VerifierResp.ReasonCode
	case VerdictEscrow:
		return VerdictEscrow, nil, in.VerifierResp.ReasonCode
	case VerdictDefer:
		if in.DeferExpired {
			if in.HasRollback {
				return VerdictEscrow, nil, "DEFER_LIMIT_ESCROW"
			}
			return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), "DEFER_LIMIT_SHIELD"
		}
		return VerdictDefer, nil, in.VerifierResp.ReasonCode
	default:
		if in.CriticalFail {
			return VerdictDeny, nil, in.VerifierResp.ReasonCode
		}
		// Try shield if possible
		return VerdictShield, shield.Suggested(shield.ShieldReadOnly, shield.DefaultParams(shield.ShieldReadOnly)), in.VerifierResp.ReasonCode
	}
}
