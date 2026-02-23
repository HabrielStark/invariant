package openclaw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"axiom/pkg/metrics"
	"axiom/pkg/models"
	"axiom/pkg/rta"
	"axiom/pkg/shield"
)

type Adapter struct {
	cfg           Config
	signer        Signer
	gateway       GatewayClient
	idempotency   *TTLStore
	replay        *TTLStore
	metrics       *metrics.Registry
	timeNow       func() time.Time
	nonceKeySalt  string
	decisionTTL   time.Duration
	replayDefault time.Duration
}

func NewAdapter(cfg Config, gateway GatewayClient, signer Signer, reg *metrics.Registry) *Adapter {
	if gateway == nil {
		gateway = NewHTTPGatewayClient(cfg)
	}
	if reg == nil {
		reg = metrics.NewRegistry()
	}
	return &Adapter{
		cfg:           cfg,
		signer:        signer,
		gateway:       gateway,
		idempotency:   NewTTLStore(),
		replay:        NewTTLStore(),
		metrics:       reg,
		timeNow:       time.Now,
		decisionTTL:   1 * time.Hour,
		replayDefault: cfg.ReplayTTL,
	}
}

func (a *Adapter) Metrics() *metrics.Registry {
	return a.metrics
}

func (a *Adapter) HandleInvocation(ctx context.Context, req InvokeRequest) (InvokeResponse, error) {
	a.metrics.IncOpenClawAdapterRequests()
	now := a.timeNow().UTC()

	mapped, err := MapInvocation(a.cfg, req, now)
	if err != nil {
		return InvokeResponse{OK: false, Error: &InvokeError{Type: "invalid_request", Message: err.Error()}}, nil
	}
	idemKey := scopedIdempotencyKey(mapped.Intent.Actor.Tenant, mapped.Intent.Actor.ID, mapped.Intent.IdempotencyKey)
	if cached, ok := a.idempotency.Get(idemKey); ok {
		return cached, nil
	}

	cert, certRaw, err := BuildAndSignCert(a.cfg, a.signer, mapped, req, now)
	if err != nil {
		return InvokeResponse{OK: false, Error: &InvokeError{Type: "cert_error", Message: err.Error()}}, nil
	}
	nonceKey := scopedNonceKey(mapped.Intent.Actor.Tenant, mapped.Intent.Actor.ID, cert.Nonce)
	replayTTL := a.replayDefault
	if !mapped.ExpiresAt.IsZero() {
		ttl := time.Until(mapped.ExpiresAt)
		if ttl > 0 {
			replayTTL = ttl
		}
	}
	if replayTTL <= 0 {
		replayTTL = 5 * time.Minute
	}
	if !a.replay.SetNX(nonceKey, InvokeResponse{OK: true}, replayTTL) {
		deny := InvokeResponse{
			OK:         false,
			Verdict:    rta.VerdictDeny,
			ReasonCode: "REPLAY_DETECTED",
			Counterexample: &models.Counterexample{
				MinimalFacts: []string{"nonce=" + cert.Nonce},
				FailedAxioms: []string{"nonce_uniqueness"},
			},
		}
		return deny, nil
	}

	gatewayReq := GatewayExecuteRequest{
		Intent:      mapped.IntentRawCanonical,
		Cert:        certRaw,
		ToolPayload: mapped.ToolPayload,
	}
	gwResp, err := a.gateway.ExecuteTool(ctx, gatewayReq)
	if err != nil {
		a.replay.Delete(nonceKey)
		deferResp := InvokeResponse{
			OK:           false,
			Verdict:      rta.VerdictDefer,
			ReasonCode:   "GATEWAY_UNAVAILABLE",
			RetryAfterMS: 1500,
			Error:        &InvokeError{Type: "gateway_error", Message: err.Error()},
		}
		return deferResp, nil
	}

	resp := adaptGatewayResponse(gwResp)
	if resp.Verdict == rta.VerdictDefer {
		a.replay.Delete(nonceKey)
	}
	if stableVerdict(resp.Verdict) {
		a.idempotency.Set(idemKey, resp, a.decisionTTL)
	}
	return resp, nil
}

func adaptGatewayResponse(gw models.GatewayResponse) InvokeResponse {
	resp := InvokeResponse{
		Verdict:        gw.Verdict,
		ReasonCode:     gw.ReasonCode,
		Result:         gw.Result,
		RetryAfterMS:   gw.RetryAfterMS,
		Shield:         gw.Shield,
		Escrow:         gw.Escrow,
		Batch:          gw.Batch,
		Counterexample: gw.Counterexample,
	}
	switch gw.Verdict {
	case rta.VerdictAllow:
		resp.OK = true
	case rta.VerdictShield:
		resp.OK = true
		if gw.Shield != nil {
			switch strings.ToUpper(strings.TrimSpace(gw.Shield.Type)) {
			case shield.ShieldReadOnly:
				resp.Preview = gw.Result
				resp.Result = nil
			case shield.ShieldDryRun:
				resp.Preview = gw.Result
				resp.Result = nil
			case shield.ShieldSmallBatch:
				resp.Result = gw.Result
			}
		}
	case rta.VerdictEscrow:
		resp.OK = false
	case rta.VerdictDefer:
		resp.OK = false
		if resp.RetryAfterMS <= 0 {
			resp.RetryAfterMS = 1500
		}
	case rta.VerdictDeny:
		resp.OK = false
		if resp.Counterexample == nil {
			resp.Counterexample = &models.Counterexample{MinimalFacts: []string{"reason_code=" + resp.ReasonCode}}
		}
	default:
		resp.OK = false
		if resp.Error == nil {
			resp.Error = &InvokeError{Type: "invalid_verdict", Message: fmt.Sprintf("unknown verdict %q", gw.Verdict)}
		}
	}
	return resp
}

func scopedIdempotencyKey(tenant, actorID, idempotency string) string {
	return strings.ToLower(strings.TrimSpace(tenant)) + ":" + strings.ToLower(strings.TrimSpace(actorID)) + ":" + strings.TrimSpace(idempotency)
}

func scopedNonceKey(tenant, actorID, nonce string) string {
	return strings.ToLower(strings.TrimSpace(tenant)) + ":" + strings.ToLower(strings.TrimSpace(actorID)) + ":" + strings.TrimSpace(nonce)
}

func EncodeInvokeResponse(resp InvokeResponse) []byte {
	encoded, _ := json.Marshal(resp)
	return encoded
}
