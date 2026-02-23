package rta

import (
	"testing"
	"time"

	"axiom/pkg/models"
	"axiom/pkg/shield"
)

func TestDecideDegradedNoAllow(t *testing.T) {
	cfg := Config{
		MaxVerifyTime:   200 * time.Millisecond,
		MaxDeferTotal:   30 * time.Second,
		MaxEscrowTTL:    24 * time.Hour,
		DegradedNoAllow: true,
	}
	verdict, sh, reason := Decide(cfg, Inputs{
		VerifierResp: &models.VerifierResponse{Verdict: VerdictAllow, ReasonCode: "OK"},
		StateFresh:   true,
		HasRollback:  true,
		Degraded:     true,
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if sh == nil || sh.Type == "" {
		t.Fatalf("expected shield suggestion")
	}
	if reason != "DEGRADED_MODE" {
		t.Fatalf("expected DEGRADED_MODE, got %s", reason)
	}
}

func TestDecideStateUnknown(t *testing.T) {
	cfg := Config{DegradedNoAllow: true}
	verdict, _, reason := Decide(cfg, Inputs{
		VerifierResp: &models.VerifierResponse{Verdict: VerdictAllow, ReasonCode: "OK"},
		StateUnknown: true,
		HasRollback:  true,
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if reason != "STATE_UNKNOWN" {
		t.Fatalf("expected STATE_UNKNOWN, got %s", reason)
	}
}

func TestDecideDeferOnTimeout(t *testing.T) {
	cfg := Config{DegradedNoAllow: true}
	verdict, _, reason := Decide(cfg, Inputs{
		VerifierResp: nil,
		StateFresh:   true,
		HasRollback:  true,
	})
	if verdict != VerdictDefer {
		t.Fatalf("expected DEFER, got %s", verdict)
	}
	if reason != "VERIFY_TIMEOUT" {
		t.Fatalf("expected VERIFY_TIMEOUT, got %s", reason)
	}
}

func TestDecideAllow(t *testing.T) {
	cfg := Config{DegradedNoAllow: true}
	verdict, sh, reason := Decide(cfg, Inputs{
		VerifierResp: &models.VerifierResponse{Verdict: VerdictAllow, ReasonCode: "OK"},
		StateFresh:   true,
		HasRollback:  true,
	})
	if verdict != VerdictAllow {
		t.Fatalf("expected ALLOW, got %s", verdict)
	}
	if sh != nil {
		t.Fatalf("expected nil shield for allow")
	}
	if reason != "OK" {
		t.Fatalf("expected OK, got %s", reason)
	}
}

func TestDecideRollbackRequired(t *testing.T) {
	cfg := Config{}
	verdict, _, reason := Decide(cfg, Inputs{
		VerifierResp: &models.VerifierResponse{Verdict: VerdictAllow, ReasonCode: "OK"},
		StateFresh:   true,
		HasRollback:  false,
	})
	if verdict != VerdictEscrow {
		t.Fatalf("expected ESCROW, got %s", verdict)
	}
	if reason != "ROLLBACK_REQUIRED" {
		t.Fatalf("expected ROLLBACK_REQUIRED, got %s", reason)
	}
}

func TestDecideDeferExpired(t *testing.T) {
	cfg := Config{}
	verdict, _, reason := Decide(cfg, Inputs{
		VerifierResp: nil,
		StateFresh:   true,
		HasRollback:  true,
		DeferExpired: true,
	})
	if verdict != VerdictEscrow {
		t.Fatalf("expected ESCROW, got %s", verdict)
	}
	if reason != "DEFER_LIMIT_ESCROW" {
		t.Fatalf("expected DEFER_LIMIT_ESCROW, got %s", reason)
	}
}

func TestDecideStateStale(t *testing.T) {
	verdict, sh, reason := Decide(Config{}, Inputs{
		StateFresh: false,
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if sh == nil || sh.Type != shield.ShieldReadOnly {
		t.Fatalf("expected READ_ONLY shield, got %+v", sh)
	}
	if reason != "STATE_STALE" {
		t.Fatalf("expected STATE_STALE, got %s", reason)
	}
}

func TestDecideShieldPaths(t *testing.T) {
	custom := &models.SuggestedShield{
		Type:   shield.ShieldSmallBatch,
		Params: map[string]interface{}{"max": float64(10)},
	}
	verdict, sh, reason := Decide(Config{}, Inputs{
		StateFresh: true,
		VerifierResp: &models.VerifierResponse{
			Verdict:         VerdictShield,
			ReasonCode:      "BUDGET_FAIL",
			SuggestedShield: custom,
		},
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if sh != custom {
		t.Fatalf("expected custom shield to be passed through")
	}
	if reason != "BUDGET_FAIL" {
		t.Fatalf("expected BUDGET_FAIL, got %s", reason)
	}

	verdict, sh, reason = Decide(Config{}, Inputs{
		StateFresh: true,
		VerifierResp: &models.VerifierResponse{
			Verdict:    VerdictShield,
			ReasonCode: "STATE_UNKNOWN",
		},
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if sh == nil || sh.Type != shield.ShieldReadOnly {
		t.Fatalf("expected fallback READ_ONLY shield, got %+v", sh)
	}
	if reason != "STATE_UNKNOWN" {
		t.Fatalf("expected STATE_UNKNOWN, got %s", reason)
	}
}

func TestDecideEscrowAndDeferBranches(t *testing.T) {
	verdict, sh, reason := Decide(Config{}, Inputs{
		StateFresh: true,
		VerifierResp: &models.VerifierResponse{
			Verdict:    VerdictEscrow,
			ReasonCode: "REQUIRE_APPROVAL",
		},
	})
	if verdict != VerdictEscrow {
		t.Fatalf("expected ESCROW, got %s", verdict)
	}
	if sh != nil {
		t.Fatalf("expected no shield, got %+v", sh)
	}
	if reason != "REQUIRE_APPROVAL" {
		t.Fatalf("expected REQUIRE_APPROVAL, got %s", reason)
	}

	verdict, sh, reason = Decide(Config{}, Inputs{
		StateFresh:   true,
		HasRollback:  false,
		DeferExpired: true,
		VerifierResp: &models.VerifierResponse{
			Verdict:    VerdictDefer,
			ReasonCode: "VERIFY_TIMEOUT",
		},
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if sh == nil || sh.Type != shield.ShieldReadOnly {
		t.Fatalf("expected READ_ONLY shield, got %+v", sh)
	}
	if reason != "DEFER_LIMIT_SHIELD" {
		t.Fatalf("expected DEFER_LIMIT_SHIELD, got %s", reason)
	}

	verdict, sh, reason = Decide(Config{}, Inputs{
		StateFresh: true,
		VerifierResp: &models.VerifierResponse{
			Verdict:    VerdictDefer,
			ReasonCode: "PENDING_SOURCE_SYNC",
		},
	})
	if verdict != VerdictDefer {
		t.Fatalf("expected DEFER, got %s", verdict)
	}
	if sh != nil {
		t.Fatalf("expected nil shield, got %+v", sh)
	}
	if reason != "PENDING_SOURCE_SYNC" {
		t.Fatalf("expected PENDING_SOURCE_SYNC, got %s", reason)
	}
}

func TestDecideDefaultCriticalAndNonCritical(t *testing.T) {
	verdict, sh, reason := Decide(Config{}, Inputs{
		StateFresh:   true,
		CriticalFail: true,
		VerifierResp: &models.VerifierResponse{
			Verdict:    "UNKNOWN",
			ReasonCode: "POLICY_ENGINE_FAILURE",
		},
	})
	if verdict != VerdictDeny {
		t.Fatalf("expected DENY, got %s", verdict)
	}
	if sh != nil {
		t.Fatalf("expected no shield, got %+v", sh)
	}
	if reason != "POLICY_ENGINE_FAILURE" {
		t.Fatalf("expected POLICY_ENGINE_FAILURE, got %s", reason)
	}

	verdict, sh, reason = Decide(Config{}, Inputs{
		StateFresh:   true,
		CriticalFail: false,
		VerifierResp: &models.VerifierResponse{
			Verdict:    "UNKNOWN",
			ReasonCode: "POLICY_ENGINE_FAILURE",
		},
	})
	if verdict != VerdictShield {
		t.Fatalf("expected SHIELD, got %s", verdict)
	}
	if sh == nil || sh.Type != shield.ShieldReadOnly {
		t.Fatalf("expected READ_ONLY shield, got %+v", sh)
	}
	if reason != "POLICY_ENGINE_FAILURE" {
		t.Fatalf("expected POLICY_ENGINE_FAILURE, got %s", reason)
	}
}
