package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/escrowfsm"
	"axiom/pkg/httpx"
	"axiom/pkg/models"
	"axiom/pkg/policyir"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Server) approveEscrow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EscrowID string `json:"escrow_id"`
		Approver string `json:"approver"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.EscrowID == "" {
		httpx.Error(w, 400, "escrow_id required")
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	var row pgx.Row
	if scoped {
		row = s.DB.QueryRow(r.Context(), `SELECT status, expires_at, approvals_required, approvals_received, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID)
	} else {
		row = s.DB.QueryRow(r.Context(), `SELECT status, expires_at, approvals_required, approvals_received, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE escrow_id=$1`, req.EscrowID)
	}
	var status string
	var expiresAt time.Time
	var approvalsRequired int
	var approvalsReceived int
	var intentRaw, certRaw, payloadRaw []byte
	var actionType string
	if err := row.Scan(&status, &expiresAt, &approvalsRequired, &approvalsReceived, &intentRaw, &certRaw, &payloadRaw, &actionType); err != nil {
		httpx.Error(w, 404, "escrow not found")
		return
	}
	if escrowfsm.IsExpired(time.Now().UTC(), expiresAt) {
		_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, status, escrowfsm.Expired)
		httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.Expired})
		return
	}
	if status != escrowfsm.Pending {
		httpx.WriteJSON(w, 200, map[string]string{"status": status})
		return
	}
	var intent models.ActionIntent
	if err := json.Unmarshal(intentRaw, &intent); err != nil {
		httpx.Error(w, 500, "invalid stored intent")
		return
	}
	var cert models.ActionCert
	if err := json.Unmarshal(certRaw, &cert); err != nil {
		httpx.Error(w, 500, "invalid stored cert")
		return
	}
	policy, _ := s.loadPolicy(r.Context(), cert.PolicySetID, cert.PolicyVersion)
	policyApproval := s.approvalPolicy(policy, approvalsRequired)
	approverRoles := []string{}
	principal, ok := auth.PrincipalFromContext(r.Context())
	if strings.EqualFold(s.AuthMode, "off") {
		if ok {
			approverRoles = principal.Roles
			if req.Approver == "" {
				req.Approver = principal.Subject
			}
		}
		if req.Approver == "" {
			httpx.Error(w, 400, "approver required")
			return
		}
	} else {
		if !ok || strings.TrimSpace(principal.Subject) == "" {
			httpx.Error(w, 401, "unauthenticated")
			return
		}
		if req.Approver != "" && !strings.EqualFold(req.Approver, principal.Subject) {
			httpx.Error(w, 403, "approver must match principal")
			return
		}
		req.Approver = principal.Subject
		approverRoles = principal.Roles
	}
	if err := escrowfsm.ApproverAllowed(req.Approver, intent.Actor.ID, approverRoles, policyApproval); err != nil {
		switch err {
		case escrowfsm.ErrSoDViolation:
			httpx.Error(w, 403, "approver cannot be actor")
		case escrowfsm.ErrApproverRole:
			httpx.Error(w, 403, "approver role not permitted")
		default:
			httpx.Error(w, 403, "approver not permitted")
		}
		return
	}
	_, _ = s.DB.Exec(r.Context(), `INSERT INTO escrow_approvals(escrow_id, approver) VALUES ($1,$2) ON CONFLICT DO NOTHING`, req.EscrowID, req.Approver)
	row = s.DB.QueryRow(r.Context(), `SELECT COUNT(*) FROM escrow_approvals WHERE escrow_id=$1`, req.EscrowID)
	_ = row.Scan(&approvalsReceived)
	if policyApproval.Required > approvalsRequired {
		approvalsRequired = policyApproval.Required
		if scoped {
			_, _ = s.DB.Exec(r.Context(), `UPDATE escrows SET approvals_required=$3 WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID, approvalsRequired)
		} else {
			_, _ = s.DB.Exec(r.Context(), `UPDATE escrows SET approvals_required=$2 WHERE escrow_id=$1`, req.EscrowID, approvalsRequired)
		}
	}
	if escrowfsm.QuorumReached(approvalsReceived, approvalsRequired) {
		claimedRows, claimErr := s.updateEscrowStatus(r.Context(), req.EscrowID, status, escrowfsm.Approved)
		if claimErr != nil {
			httpx.Error(w, 500, "escrow update failed")
			return
		}
		if claimedRows == 0 {
			currentStatus := status
			if scoped {
				_ = s.DB.QueryRow(r.Context(), `SELECT status FROM escrows WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID).Scan(&currentStatus)
			} else {
				_ = s.DB.QueryRow(r.Context(), `SELECT status FROM escrows WHERE escrow_id=$1`, req.EscrowID).Scan(&currentStatus)
			}
			httpx.WriteJSON(w, 200, map[string]interface{}{"status": currentStatus, "approvals_received": approvalsReceived})
			return
		}
		if scoped {
			_, _ = s.DB.Exec(r.Context(), `UPDATE escrows SET approvals_received=$3 WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID, approvalsReceived)
		} else {
			_, _ = s.DB.Exec(r.Context(), `UPDATE escrows SET approvals_received=$2 WHERE escrow_id=$1`, req.EscrowID, approvalsReceived)
		}
		_, compensated, err := s.executeEscrowAction(r.Context(), actionType, payloadRaw, intent, cert)
		if err != nil {
			_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Approved, escrowfsm.Failed)
			if compensated {
				_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Failed, escrowfsm.RolledBack)
				httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.RolledBack})
				return
			}
			httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.Failed})
			return
		}
		_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Approved, escrowfsm.Executed)
		_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Executed, escrowfsm.Closed)
		httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.Closed})
		return
	}
	if scoped {
		_, _ = s.DB.Exec(r.Context(), `UPDATE escrows SET approvals_received=$3 WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID, approvalsReceived)
	} else {
		_, _ = s.DB.Exec(r.Context(), `UPDATE escrows SET approvals_received=$2 WHERE escrow_id=$1`, req.EscrowID, approvalsReceived)
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"status": escrowfsm.Pending, "approvals_received": approvalsReceived})
}

func (s *Server) executeEscrow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EscrowID string `json:"escrow_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	req.EscrowID = strings.TrimSpace(req.EscrowID)
	if req.EscrowID == "" {
		httpx.Error(w, 400, "escrow_id required")
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	var row pgx.Row
	if scoped {
		row = s.DB.QueryRow(r.Context(), `SELECT status, expires_at, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID)
	} else {
		row = s.DB.QueryRow(r.Context(), `SELECT status, expires_at, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE escrow_id=$1`, req.EscrowID)
	}
	var (
		status             string
		expiresAt          time.Time
		intentRaw, certRaw []byte
		payloadRaw         []byte
		actionType         string
	)
	if err := row.Scan(&status, &expiresAt, &intentRaw, &certRaw, &payloadRaw, &actionType); err != nil {
		httpx.Error(w, 404, "escrow not found")
		return
	}
	if escrowfsm.IsExpired(time.Now().UTC(), expiresAt) {
		_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, status, escrowfsm.Expired)
		httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.Expired})
		return
	}
	if status != escrowfsm.Approved {
		httpx.WriteJSON(w, 200, map[string]string{"status": status})
		return
	}
	var intent models.ActionIntent
	if err := json.Unmarshal(intentRaw, &intent); err != nil {
		httpx.Error(w, 500, "invalid stored intent")
		return
	}
	var cert models.ActionCert
	if err := json.Unmarshal(certRaw, &cert); err != nil {
		httpx.Error(w, 500, "invalid stored cert")
		return
	}
	_, compensated, err := s.executeEscrowAction(r.Context(), actionType, payloadRaw, intent, cert)
	if err != nil {
		_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Approved, escrowfsm.Failed)
		if compensated {
			_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Failed, escrowfsm.RolledBack)
			httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.RolledBack})
			return
		}
		httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.Failed})
		return
	}
	_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Approved, escrowfsm.Executed)
	_, _ = s.updateEscrowStatus(r.Context(), req.EscrowID, escrowfsm.Executed, escrowfsm.Closed)
	httpx.WriteJSON(w, 200, map[string]string{"status": escrowfsm.Closed})
}

func (s *Server) cancelEscrow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EscrowID string `json:"escrow_id"`
		Actor    string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.EscrowID == "" {
		httpx.Error(w, 400, "escrow_id required")
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	var row pgx.Row
	if scoped {
		row = s.DB.QueryRow(r.Context(), `SELECT status FROM escrows WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID)
	} else {
		row = s.DB.QueryRow(r.Context(), `SELECT status FROM escrows WHERE escrow_id=$1`, req.EscrowID)
	}
	var status string
	if err := row.Scan(&status); err != nil {
		httpx.Error(w, 404, "escrow not found")
		return
	}
	if status == escrowfsm.Pending {
		if _, err := s.updateEscrowStatus(r.Context(), req.EscrowID, status, escrowfsm.Cancelled); err == nil {
			status = escrowfsm.Cancelled
		}
	}
	httpx.WriteJSON(w, 200, map[string]string{"status": status})
}

func (s *Server) rollbackEscrow(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EscrowID string `json:"escrow_id"`
		Actor    string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.EscrowID == "" {
		httpx.Error(w, 400, "escrow_id required")
		return
	}
	tenant, scoped := s.tenantScope(r.Context())
	var row pgx.Row
	if scoped {
		row = s.DB.QueryRow(r.Context(), `SELECT status, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE tenant=$1 AND escrow_id=$2`, tenant, req.EscrowID)
	} else {
		row = s.DB.QueryRow(r.Context(), `SELECT status, intent_raw, cert_raw, payload_raw, action_type FROM escrows WHERE escrow_id=$1`, req.EscrowID)
	}
	var status string
	var intentRaw, certRaw, payloadRaw []byte
	var actionType string
	if err := row.Scan(&status, &intentRaw, &certRaw, &payloadRaw, &actionType); err != nil {
		httpx.Error(w, 404, "escrow not found")
		return
	}
	if status == escrowfsm.Executed || status == escrowfsm.Failed {
		var intent models.ActionIntent
		_ = json.Unmarshal(intentRaw, &intent)
		var cert models.ActionCert
		_ = json.Unmarshal(certRaw, &cert)
		if err := s.runCompensation(r.Context(), actionType, intent, cert); err == nil {
			if _, err := s.updateEscrowStatus(r.Context(), req.EscrowID, status, escrowfsm.RolledBack); err == nil {
				status = escrowfsm.RolledBack
			}
		}
	}
	httpx.WriteJSON(w, 200, map[string]string{"status": status})
}

func (s *Server) getEscrow(w http.ResponseWriter, r *http.Request) {
	escrowID := chi.URLParam(r, "escrow_id")
	tenant, scoped := s.tenantScope(r.Context())
	if scoped {
		row := s.DB.QueryRow(r.Context(), `SELECT escrow_id, status, created_at, expires_at, approvals_required, approvals_received FROM escrows WHERE tenant=$1 AND escrow_id=$2`, tenant, escrowID)
		var out models.Escrow
		if err := row.Scan(&out.EscrowID, &out.Status, &out.CreatedAt, &out.ExpiresAt, &out.ApprovalsRequired, &out.ApprovalsReceived); err != nil {
			httpx.Error(w, 404, "escrow not found")
			return
		}
		httpx.WriteJSON(w, 200, out)
		return
	}
	row := s.DB.QueryRow(r.Context(), `SELECT escrow_id, status, created_at, expires_at, approvals_required, approvals_received FROM escrows WHERE escrow_id=$1`, escrowID)
	var out models.Escrow
	if err := row.Scan(&out.EscrowID, &out.Status, &out.CreatedAt, &out.ExpiresAt, &out.ApprovalsRequired, &out.ApprovalsReceived); err != nil {
		httpx.Error(w, 404, "escrow not found")
		return
	}
	httpx.WriteJSON(w, 200, out)
}

func (s *Server) listEscrows(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	statusFilter := r.URL.Query().Get("status")
	var rows pgx.Rows
	var err error
	tenant, scoped := s.tenantScope(r.Context())
	if statusFilter == "" {
		if scoped {
			rows, err = s.DB.Query(r.Context(), `SELECT escrow_id, status, created_at, expires_at, approvals_required, approvals_received FROM escrows WHERE tenant=$1 ORDER BY created_at DESC LIMIT $2`, tenant, limit)
		} else {
			rows, err = s.DB.Query(r.Context(), `SELECT escrow_id, status, created_at, expires_at, approvals_required, approvals_received FROM escrows ORDER BY created_at DESC LIMIT $1`, limit)
		}
	} else {
		if scoped {
			rows, err = s.DB.Query(r.Context(), `SELECT escrow_id, status, created_at, expires_at, approvals_required, approvals_received FROM escrows WHERE tenant=$1 AND status=$2 ORDER BY created_at DESC LIMIT $3`, tenant, statusFilter, limit)
		} else {
			rows, err = s.DB.Query(r.Context(), `SELECT escrow_id, status, created_at, expires_at, approvals_required, approvals_received FROM escrows WHERE status=$1 ORDER BY created_at DESC LIMIT $2`, statusFilter, limit)
		}
	}
	if err != nil {
		httpx.Error(w, 500, "failed to list escrows")
		return
	}
	defer rows.Close()
	items := make([]models.Escrow, 0, limit)
	for rows.Next() {
		var item models.Escrow
		if err := rows.Scan(&item.EscrowID, &item.Status, &item.CreatedAt, &item.ExpiresAt, &item.ApprovalsRequired, &item.ApprovalsReceived); err == nil {
			items = append(items, item)
		}
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) expireEscrowsLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cmd, _ := s.DB.Exec(ctx, `
				UPDATE escrows
				SET status = $1
				WHERE status = $2 AND expires_at <= now()
			`, escrowfsm.Expired, escrowfsm.Pending)
			if cmd.RowsAffected() > 0 {
				if s.Metrics != nil {
					s.Metrics.AddEscrowState(escrowfsm.Expired, cmd.RowsAffected())
				}
				s.publishRefresh()
			}
		}
	}
}

func (s *Server) createEscrow(ctx context.Context, tenant string, intent models.ActionIntent, req executeRequest, cert models.ActionCert, policy *policyir.PolicySetIR) (string, error) {
	escrowID := uuid.New().String()
	now := time.Now().UTC()
	expires := now.Add(s.Config.MaxEscrowTTL)
	approvalsRequired := approvalsRequiredFromClaims(cert.Claims)
	if policy != nil && policy.Approvals != nil {
		if policy.Approvals.Required > approvalsRequired {
			approvalsRequired = policy.Approvals.Required
		}
		if policy.Approvals.ExpiresIn > 0 {
			exp := now.Add(policy.Approvals.ExpiresIn)
			if exp.Before(expires) {
				expires = exp
			}
		}
	}
	if approvalsRequired < 1 {
		approvalsRequired = 1
	}
	payload := req.ToolPayload
	if intent.ActionType == "ONTOLOGY_ACTION" {
		payload = req.ActionPayload
	}
	_, err := s.DB.Exec(ctx, `
		INSERT INTO escrows(escrow_id, tenant, status, expires_at, approvals_required, intent_raw, cert_raw, payload_raw, action_type)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, escrowID, tenant, escrowfsm.Pending, expires, approvalsRequired, req.Intent, req.Cert, payload, intent.ActionType)
	if err == nil {
		if s.Metrics != nil {
			s.Metrics.IncEscrowState(escrowfsm.Pending)
		}
		s.publishRefresh()
	}
	return escrowID, err
}

func approvalsRequiredFromClaims(claims []models.Claim) int {
	required := 1
	for _, c := range claims {
		if c.Type != "TwoPersonRule" && c.Type != "Approval" {
			continue
		}
		match := approvalsFromClaimRe.FindStringSubmatch(c.Statement)
		if len(match) != 3 {
			continue
		}
		n, err := strconv.Atoi(match[2])
		if err != nil || n < 1 {
			continue
		}
		if n > required {
			required = n
		}
	}
	return required
}

func (s *Server) updateEscrowStatus(ctx context.Context, escrowID, from, to string) (int64, error) {
	if !escrowfsm.CanTransition(from, to) {
		return 0, escrowfsm.ErrInvalidTransition
	}
	cmd, err := s.DB.Exec(ctx, `UPDATE escrows SET status=$2 WHERE escrow_id=$1 AND status=$3`, escrowID, to, from)
	if err != nil {
		return 0, err
	}
	if cmd.RowsAffected() > 0 {
		if s.Metrics != nil {
			s.Metrics.AddEscrowState(to, cmd.RowsAffected())
		}
		s.publishRefresh()
	}
	return cmd.RowsAffected(), nil
}

func (s *Server) executeEscrowAction(ctx context.Context, actionType string, payload json.RawMessage, intent models.ActionIntent, cert models.ActionCert) (json.RawMessage, bool, error) {
	var result json.RawMessage
	compensated := false
	exec := func(execCtx context.Context) error {
		res, err := s.executeWithTwoPhase(execCtx, actionType, payload)
		if err != nil {
			return err
		}
		result = res
		return nil
	}
	comp := func(compCtx context.Context) error {
		if err := s.runCompensation(compCtx, actionType, intent, cert); err != nil {
			return err
		}
		compensated = true
		return nil
	}
	err := escrowfsm.ExecuteWithCompensation(ctx, exec, comp)
	return result, compensated, err
}

func (s *Server) executeWithTwoPhase(ctx context.Context, actionType string, payload json.RawMessage) (json.RawMessage, error) {
	prepare, commit, rollback, ok := parseTwoPhasePayload(payload)
	if !ok {
		return s.executeUpstream(ctx, actionType, payload, payload)
	}
	var result json.RawMessage
	err := escrowfsm.ExecuteTwoPhase(ctx, escrowfsm.TwoPhase{
		Prepare: func(pctx context.Context) error {
			if len(prepare) == 0 {
				return nil
			}
			_, err := s.executeUpstream(pctx, actionType, prepare, prepare)
			return err
		},
		Commit: func(cctx context.Context) error {
			res, err := s.executeUpstream(cctx, actionType, commit, commit)
			if err != nil {
				return err
			}
			result = res
			return nil
		},
		Rollback: func(rctx context.Context) error {
			if len(rollback) == 0 {
				return nil
			}
			_, err := s.executeUpstream(rctx, actionType, rollback, rollback)
			return err
		},
	})
	return result, err
}

func parseTwoPhasePayload(raw json.RawMessage) (json.RawMessage, json.RawMessage, json.RawMessage, bool) {
	var wrapper struct {
		TwoPhase struct {
			Prepare  json.RawMessage `json:"prepare"`
			Commit   json.RawMessage `json:"commit"`
			Rollback json.RawMessage `json:"rollback"`
		} `json:"two_phase"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, nil, nil, false
	}
	if len(wrapper.TwoPhase.Commit) == 0 {
		return nil, nil, nil, false
	}
	return wrapper.TwoPhase.Prepare, wrapper.TwoPhase.Commit, wrapper.TwoPhase.Rollback, true
}

func (s *Server) runCompensation(ctx context.Context, actionType string, intent models.ActionIntent, cert models.ActionCert) error {
	planType := strings.ToUpper(strings.TrimSpace(cert.RollbackPlan.Type))
	if planType != "COMPENSATING_ACTION" {
		return errors.New("rollback plan is not compensating action")
	}
	if len(cert.RollbackPlan.Steps) == 0 {
		return errors.New("rollback plan steps empty")
	}
	for _, step := range cert.RollbackPlan.Steps {
		payload, err := buildCompensationPayload(actionType, intent, step)
		if err != nil {
			return err
		}
		if _, err := s.executeUpstream(ctx, actionType, payload, payload); err != nil {
			return err
		}
	}
	return nil
}

func buildCompensationPayload(actionType string, intent models.ActionIntent, step string) (json.RawMessage, error) {
	step = strings.TrimSpace(step)
	if step == "" {
		return nil, errors.New("empty compensation step")
	}
	if strings.HasPrefix(step, "{") {
		return json.RawMessage(step), nil
	}
	payload := map[string]interface{}{
		"action":    step,
		"intent_id": intent.IntentID,
		"domain":    intent.Target.Domain,
		"reason":    "compensating_action",
	}
	if actionType == "ONTOLOGY_ACTION" {
		payload["ontology"] = intent.Target.Domain
	}
	raw, _ := json.Marshal(payload)
	return raw, nil
}
