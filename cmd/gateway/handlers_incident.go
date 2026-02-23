package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/httpx"
	"axiom/pkg/models"
	"axiom/pkg/rta"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	statusFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	baseQuery := `SELECT incident_id, COALESCE(decision_id, ''), severity, category, reason_code, status, title, details, COALESCE(acknowledged_by, ''), COALESCE(resolved_by, ''), created_at, updated_at, resolved_at FROM incidents`
	var (
		rows pgx.Rows
		err  error
	)
	tenant, scoped := s.tenantScope(r.Context())
	if statusFilter == "" {
		if scoped {
			rows, err = s.DB.Query(r.Context(), baseQuery+` WHERE tenant=$1 ORDER BY created_at DESC LIMIT $2`, tenant, limit)
		} else {
			rows, err = s.DB.Query(r.Context(), baseQuery+` ORDER BY created_at DESC LIMIT $1`, limit)
		}
	} else {
		if scoped {
			rows, err = s.DB.Query(r.Context(), baseQuery+` WHERE tenant=$1 AND status=$2 ORDER BY created_at DESC LIMIT $3`, tenant, statusFilter, limit)
		} else {
			rows, err = s.DB.Query(r.Context(), baseQuery+` WHERE status=$1 ORDER BY created_at DESC LIMIT $2`, statusFilter, limit)
		}
	}
	if err != nil {
		httpx.Error(w, 500, "failed to list incidents")
		return
	}
	defer rows.Close()
	items := make([]models.Incident, 0, limit)
	for rows.Next() {
		var item models.Incident
		if err := rows.Scan(
			&item.IncidentID,
			&item.DecisionID,
			&item.Severity,
			&item.Category,
			&item.ReasonCode,
			&item.Status,
			&item.Title,
			&item.Details,
			&item.AcknowledgedBy,
			&item.ResolvedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
			&item.ResolvedAt,
		); err == nil {
			items = append(items, item)
		}
	}
	httpx.WriteJSON(w, 200, map[string]interface{}{"items": items})
}

func (s *Server) patchIncident(w http.ResponseWriter, r *http.Request) {
	incidentID := chi.URLParam(r, "incident_id")
	var req struct {
		Status string `json:"status"`
		Actor  string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	status := strings.ToUpper(strings.TrimSpace(req.Status))
	actor := strings.TrimSpace(req.Actor)
	tenant, scoped := s.tenantScope(r.Context())
	if strings.EqualFold(s.AuthMode, "off") {
		if actor == "" {
			httpx.Error(w, 400, "actor required")
			return
		}
	} else {
		principal, ok := auth.PrincipalFromContext(r.Context())
		if !ok || strings.TrimSpace(principal.Subject) == "" {
			httpx.Error(w, 401, "unauthenticated")
			return
		}
		if actor != "" && !strings.EqualFold(actor, principal.Subject) {
			httpx.Error(w, 403, "actor must match principal")
			return
		}
		actor = principal.Subject
	}
	switch status {
	case incidentStatusAcknowledged:
		var (
			cmd pgconn.CommandTag
			err error
		)
		if scoped {
			cmd, err = s.DB.Exec(r.Context(), `
				UPDATE incidents
				SET status=$2, acknowledged_by=$3
				WHERE incident_id=$1 AND status=$4 AND tenant=$5
			`, incidentID, incidentStatusAcknowledged, actor, incidentStatusOpen, tenant)
		} else {
			cmd, err = s.DB.Exec(r.Context(), `
				UPDATE incidents
				SET status=$2, acknowledged_by=$3
				WHERE incident_id=$1 AND status=$4
			`, incidentID, incidentStatusAcknowledged, actor, incidentStatusOpen)
		}
		if err != nil {
			httpx.Error(w, 500, "incident update failed")
			return
		}
		if cmd.RowsAffected() == 0 {
			httpx.Error(w, 409, "incident is not open")
			return
		}
		s.publishRefresh()
	case incidentStatusResolved:
		var (
			cmd pgconn.CommandTag
			err error
		)
		if scoped {
			cmd, err = s.DB.Exec(r.Context(), `
				UPDATE incidents
				SET status=$2, resolved_by=$3, resolved_at=now()
				WHERE incident_id=$1 AND status IN ($4,$5) AND tenant=$6
			`, incidentID, incidentStatusResolved, actor, incidentStatusOpen, incidentStatusAcknowledged, tenant)
		} else {
			cmd, err = s.DB.Exec(r.Context(), `
				UPDATE incidents
				SET status=$2, resolved_by=$3, resolved_at=now()
				WHERE incident_id=$1 AND status IN ($4,$5)
			`, incidentID, incidentStatusResolved, actor, incidentStatusOpen, incidentStatusAcknowledged)
		}
		if err != nil {
			httpx.Error(w, 500, "incident update failed")
			return
		}
		if cmd.RowsAffected() == 0 {
			httpx.Error(w, 409, "incident is already resolved")
			return
		}
		s.publishRefresh()
	default:
		httpx.Error(w, 400, "status must be ACKNOWLEDGED or RESOLVED")
		return
	}
	var row pgx.Row
	if scoped {
		row = s.DB.QueryRow(r.Context(), `
			SELECT incident_id, COALESCE(decision_id, ''), severity, category, reason_code, status, title, details, COALESCE(acknowledged_by, ''), COALESCE(resolved_by, ''), created_at, updated_at, resolved_at
			FROM incidents WHERE incident_id=$1 AND tenant=$2
		`, incidentID, tenant)
	} else {
		row = s.DB.QueryRow(r.Context(), `
			SELECT incident_id, COALESCE(decision_id, ''), severity, category, reason_code, status, title, details, COALESCE(acknowledged_by, ''), COALESCE(resolved_by, ''), created_at, updated_at, resolved_at
			FROM incidents WHERE incident_id=$1
		`, incidentID)
	}
	var item models.Incident
	if err := row.Scan(
		&item.IncidentID,
		&item.DecisionID,
		&item.Severity,
		&item.Category,
		&item.ReasonCode,
		&item.Status,
		&item.Title,
		&item.Details,
		&item.AcknowledgedBy,
		&item.ResolvedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&item.ResolvedAt,
	); err != nil {
		httpx.Error(w, 404, "incident not found")
		return
	}
	httpx.WriteJSON(w, 200, item)
}

func (s *Server) raiseIncident(ctx context.Context, decisionID, category, reasonCode, verdict string, intent models.ActionIntent, cert models.ActionCert, counterexample *models.Counterexample) {
	if s.DB == nil {
		return
	}
	details := map[string]interface{}{
		"verdict":        verdict,
		"policy_set_id":  cert.PolicySetID,
		"policy_version": cert.PolicyVersion,
		"actor_id_hash":  hashIdentity(intent.Actor.ID),
		"tenant":         intent.Actor.Tenant,
		"action_type":    intent.ActionType,
		"operation":      intent.Operation.Name,
		"domain":         intent.Target.Domain,
	}
	if counterexample != nil {
		details["counterexample"] = counterexample
	}
	rawDetails, _ := json.Marshal(details)
	severity := "HIGH"
	if verdict == rta.VerdictShield {
		severity = "MEDIUM"
	}
	title := "Critical runtime assurance event"
	if reasonCode != "" {
		title = "Critical runtime assurance event: " + reasonCode
	}
	cmd, _ := s.DB.Exec(ctx, `
		INSERT INTO incidents(incident_id, tenant, decision_id, severity, category, reason_code, status, title, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, uuid.New().String(), intent.Actor.Tenant, nullIfEmpty(decisionID), severity, category, reasonCode, incidentStatusOpen, title, rawDetails)
	if cmd.RowsAffected() > 0 {
		s.publishRefresh()
	}
}

func (s *Server) raiseRateLimitIncident(ctx context.Context, decisionID string, intent models.ActionIntent) {
	if s.Cache == nil {
		return
	}
	key := "incident:ratelimit:" + intent.Actor.ID + ":" + intent.Target.Domain
	ok, err := s.Cache.SetNX(ctx, key, "1", time.Minute)
	if err != nil || !ok {
		return
	}
	details := map[string]interface{}{
		"actor_hash": hashIdentity(intent.Actor.ID),
		"tenant":     intent.Actor.Tenant,
		"domain":     intent.Target.Domain,
		"action":     intent.Operation.Name,
	}
	b, _ := json.Marshal(details)
	_, _ = s.DB.Exec(ctx, `
		INSERT INTO incidents(
			incident_id,
			tenant,
			decision_id,
			severity,
			category,
			reason_code,
			status,
			title,
			details
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, uuid.New().String(), intent.Actor.Tenant, decisionID, "MEDIUM", "ANOMALY", "RATE_LIMITED", incidentStatusOpen, "Rate limit exceeded for action stream", b)
}

func (s *Server) raiseAuthIncident(ctx context.Context, reasonCode string) {
	if s.DB == nil {
		return
	}
	tenant := ""
	if principal, ok := auth.PrincipalFromContext(ctx); ok {
		tenant = principal.Tenant
	}
	rawDetails, _ := json.Marshal(map[string]string{"event": "gateway_access_denied"})
	_, _ = s.DB.Exec(ctx, `
		INSERT INTO incidents(incident_id, tenant, severity, category, reason_code, status, title, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
	`, uuid.New().String(), tenant, "HIGH", "AUTH", reasonCode, incidentStatusOpen, "Gateway authorization failure", rawDetails)
}
