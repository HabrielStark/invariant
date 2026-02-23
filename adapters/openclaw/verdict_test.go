package openclaw

import (
	"encoding/json"
	"testing"

	"axiom/pkg/models"
	"axiom/pkg/rta"
	"axiom/pkg/shield"
)

func TestAdaptGatewayResponse(t *testing.T) {
	allow := adaptGatewayResponse(models.GatewayResponse{Verdict: rta.VerdictAllow, ReasonCode: "OK", Result: json.RawMessage(`{"ok":true}`)})
	if !allow.OK || allow.Verdict != rta.VerdictAllow {
		t.Fatalf("expected allow ok response, got %#v", allow)
	}

	readOnly := adaptGatewayResponse(models.GatewayResponse{
		Verdict:    rta.VerdictShield,
		ReasonCode: "STATE_STALE",
		Shield:     shield.Suggested(shield.ShieldReadOnly, nil),
		Result:     json.RawMessage(`{"preview":true}`),
	})
	if !readOnly.OK || len(readOnly.Preview) == 0 || len(readOnly.Result) != 0 {
		t.Fatalf("expected READ_ONLY preview response, got %#v", readOnly)
	}

	escrow := adaptGatewayResponse(models.GatewayResponse{
		Verdict:    rta.VerdictEscrow,
		ReasonCode: "REQUIRE_APPROVAL",
		Escrow:     &models.EscrowRef{EscrowID: "esc-1", Status: "PENDING"},
	})
	if escrow.OK || escrow.Escrow == nil || escrow.Escrow.EscrowID != "esc-1" {
		t.Fatalf("expected escrow response, got %#v", escrow)
	}

	deferResp := adaptGatewayResponse(models.GatewayResponse{Verdict: rta.VerdictDefer, ReasonCode: "VERIFY_TIMEOUT", RetryAfterMS: 500})
	if deferResp.OK || deferResp.RetryAfterMS != 500 {
		t.Fatalf("expected defer response, got %#v", deferResp)
	}

	deny := adaptGatewayResponse(models.GatewayResponse{Verdict: rta.VerdictDeny, ReasonCode: "BAD_SIGNATURE"})
	if deny.OK || deny.Counterexample == nil {
		t.Fatalf("expected deny counterexample, got %#v", deny)
	}
}
