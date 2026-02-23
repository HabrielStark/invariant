package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"axiom/pkg/auth"
	"axiom/pkg/httpx"
)

// handleGDPRExport handles subject access requests — exports all data for a given data subject.
// P2 fix: queries by explicit subject_id hash, not just the requesting actor.
func (s *Server) handleGDPRExport(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.resolveComplianceActor(w, r, r.URL.Query().Get("requested_by"))
	if !ok {
		return
	}

	subjectID := strings.TrimSpace(r.URL.Query().Get("subject_id"))
	if subjectID == "" {
		subjectID = actor // fall back to actor if no explicit subject
	}
	subjectHash := hashIdentity(subjectID)
	tenant, scoped := s.tenantScope(r.Context())

	// Collect audit decisions from audit_records (P0 fix: was audit_log)
	var decisionRows []map[string]interface{}
	var auditQuery string
	var queryArgs []interface{}
	if scoped {
		auditQuery = `
			SELECT decision_id, tenant, policy_version, verdict, reason_code, created_at
			FROM audit_records WHERE actor_id_hash=$1 AND tenant=$2
			ORDER BY created_at DESC LIMIT 10000
		`
		queryArgs = []interface{}{subjectHash, tenant}
	} else {
		auditQuery = `
			SELECT decision_id, tenant, policy_version, verdict, reason_code, created_at
			FROM audit_records WHERE actor_id_hash=$1
			ORDER BY created_at DESC LIMIT 10000
		`
		queryArgs = []interface{}{subjectHash}
	}
	rows, err := s.DB.Query(r.Context(), auditQuery, queryArgs...)
	if err != nil {
		log.Printf("gdpr export: audit_records query error: %v", err)
		httpx.Error(w, 500, "failed to query audit records")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var decisionID, recTenant, policyVersion, verdict, reasonCode string
		var createdAt interface{}
		if err := rows.Scan(&decisionID, &recTenant, &policyVersion, &verdict, &reasonCode, &createdAt); err != nil {
			log.Printf("gdpr export: row scan error: %v", err)
			continue
		}
		decisionRows = append(decisionRows, map[string]interface{}{
			"decision_id":    decisionID,
			"tenant":         recTenant,
			"policy_version": policyVersion,
			"verdict":        verdict,
			"reason_code":    reasonCode,
			"created_at":     createdAt,
		})
	}

	// Collect escrow records
	var escrowRows []map[string]interface{}
	if scoped && tenant != "" {
		escrowQuery := `
			SELECT escrow_id, status, created_at, expires_at
			FROM escrows WHERE tenant=$1 AND intent_raw->'actor'->>'id'=$2
			ORDER BY created_at DESC LIMIT 1000
		`
		erows, eerr := s.DB.Query(r.Context(), escrowQuery, tenant, subjectID)
		if eerr != nil {
			log.Printf("gdpr export: escrows query error: %v", eerr)
		} else {
			defer erows.Close()
			for erows.Next() {
				var escrowID, status string
				var createdAt, expiresAt interface{}
				if err := erows.Scan(&escrowID, &status, &createdAt, &expiresAt); err == nil {
					escrowRows = append(escrowRows, map[string]interface{}{
						"escrow_id":  escrowID,
						"status":     status,
						"created_at": createdAt,
						"expires_at": expiresAt,
					})
				}
			}
		}
	} else {
		escrowQuery := `
			SELECT escrow_id, status, created_at, expires_at
			FROM escrows WHERE intent_raw->'actor'->>'id'=$1
			ORDER BY created_at DESC LIMIT 1000
		`
		erows, eerr := s.DB.Query(r.Context(), escrowQuery, subjectID)
		if eerr != nil {
			log.Printf("gdpr export: escrows query error: %v", eerr)
		} else {
			defer erows.Close()
			for erows.Next() {
				var escrowID, status string
				var createdAt, expiresAt interface{}
				if err := erows.Scan(&escrowID, &status, &createdAt, &expiresAt); err == nil {
					escrowRows = append(escrowRows, map[string]interface{}{
						"escrow_id":  escrowID,
						"status":     status,
						"created_at": createdAt,
						"expires_at": expiresAt,
					})
				}
			}
		}
	}

	// Collect incident records
	var incidentRows []map[string]interface{}
	if scoped && tenant != "" {
		incidentQuery := `
			SELECT incident_id, severity, category, reason_code, status, title, created_at
			FROM incidents
			WHERE tenant=$1 AND (details->>'actor_id_hash'=$2 OR details->>'actor_id'=$3)
			ORDER BY created_at DESC LIMIT 1000
		`
		irows, ierr := s.DB.Query(r.Context(), incidentQuery, tenant, subjectHash, subjectID)
		if ierr != nil {
			log.Printf("gdpr export: incidents query error: %v", ierr)
		} else {
			defer irows.Close()
			for irows.Next() {
				var incidentID, severity, category, reasonCode, status, title string
				var createdAt interface{}
				if err := irows.Scan(&incidentID, &severity, &category, &reasonCode, &status, &title, &createdAt); err == nil {
					incidentRows = append(incidentRows, map[string]interface{}{
						"incident_id": incidentID,
						"severity":    severity,
						"category":    category,
						"reason_code": reasonCode,
						"status":      status,
						"title":       title,
						"created_at":  createdAt,
					})
				}
			}
		}
	} else {
		incidentQuery := `
			SELECT incident_id, severity, category, reason_code, status, title, created_at
			FROM incidents
			WHERE details->>'actor_id_hash'=$1 OR details->>'actor_id'=$2
			ORDER BY created_at DESC LIMIT 1000
		`
		irows, ierr := s.DB.Query(r.Context(), incidentQuery, subjectHash, subjectID)
		if ierr != nil {
			log.Printf("gdpr export: incidents query error: %v", ierr)
		} else {
			defer irows.Close()
			for irows.Next() {
				var incidentID, severity, category, reasonCode, status, title string
				var createdAt interface{}
				if err := irows.Scan(&incidentID, &severity, &category, &reasonCode, &status, &title, &createdAt); err == nil {
					incidentRows = append(incidentRows, map[string]interface{}{
						"incident_id": incidentID,
						"severity":    severity,
						"category":    category,
						"reason_code": reasonCode,
						"status":      status,
						"title":       title,
						"created_at":  createdAt,
					})
				}
			}
		}
	}

	export := map[string]interface{}{
		"subject_id":   subjectID,
		"subject_hash": subjectHash,
		"requested_by": actor,
		"data": map[string]interface{}{
			"audit_decisions": decisionRows,
			"escrows":         escrowRows,
			"incidents":       incidentRows,
		},
	}
	httpx.WriteJSON(w, 200, export)
}

// handleGDPRErasure pseudonymizes all personal data for a data subject (right to erasure).
func (s *Server) handleGDPRErasure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectID   string `json:"subject_id"`
		RequestedBy string `json:"requested_by"`
		Reason      string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.SubjectID == "" {
		httpx.Error(w, 400, "subject_id required")
		return
	}
	actor, ok := s.resolveComplianceActor(w, r, req.RequestedBy)
	if !ok {
		return
	}
	if req.Reason == "" {
		req.Reason = "GDPR erasure request"
	}

	hashedSubject := hashIdentity(req.SubjectID)
	pseudonym := "REDACTED_" + hashedSubject[:16]
	immutableTables := []string{"audit_records"}

	tenant, scoped := s.tenantScope(r.Context())
	affected := int64(0)

	// audit_records is append-only by design; only mutable tables are pseudonymized.
	if scoped {
		cmd, err := s.DB.Exec(r.Context(), `
			UPDATE subject_restrictions
			SET actor_id_hash=$1
			WHERE actor_id_hash=$2 AND tenant=$3
		`, pseudonym, hashedSubject, tenant)
		if err != nil {
			log.Printf("gdpr erasure: subject_restrictions update error: %v", err)
			httpx.Error(w, 500, "failed to pseudonymize subject restrictions")
			return
		}
		affected += cmd.RowsAffected()

		cmd, err = s.DB.Exec(r.Context(), `
			UPDATE incidents
			SET details = jsonb_set(
				jsonb_set(COALESCE(details, '{}'::jsonb), '{actor_id_hash}', to_jsonb($1::text), true),
				'{actor_id}',
				to_jsonb($1::text),
				true
			)
			WHERE tenant=$2 AND (details->>'actor_id_hash'=$3 OR details->>'actor_id'=$4)
		`, pseudonym, tenant, hashedSubject, req.SubjectID)
		if err != nil {
			log.Printf("gdpr erasure: incidents update error: %v", err)
			httpx.Error(w, 500, "failed to pseudonymize incidents")
			return
		}
		affected += cmd.RowsAffected()
	} else {
		cmd, err := s.DB.Exec(r.Context(), `
			UPDATE subject_restrictions
			SET actor_id_hash=$1
			WHERE actor_id_hash=$2
		`, pseudonym, hashedSubject)
		if err != nil {
			log.Printf("gdpr erasure: subject_restrictions update error: %v", err)
			httpx.Error(w, 500, "failed to pseudonymize subject restrictions")
			return
		}
		affected += cmd.RowsAffected()

		cmd, err = s.DB.Exec(r.Context(), `
			UPDATE incidents
			SET details = jsonb_set(
				jsonb_set(COALESCE(details, '{}'::jsonb), '{actor_id_hash}', to_jsonb($1::text), true),
				'{actor_id}',
				to_jsonb($1::text),
				true
			)
			WHERE details->>'actor_id_hash'=$2 OR details->>'actor_id'=$3
		`, pseudonym, hashedSubject, req.SubjectID)
		if err != nil {
			log.Printf("gdpr erasure: incidents update error: %v", err)
			httpx.Error(w, 500, "failed to pseudonymize incidents")
			return
		}
		affected += cmd.RowsAffected()
	}

	// Record compliance event
	_, err := s.DB.Exec(r.Context(), `
		INSERT INTO compliance_events(event_type, subject_hash, requested_by, reason, records_affected)
		VALUES ($1, $2, $3, $4, $5)
	`, "GDPR_ERASURE", pseudonym, actor, req.Reason+" | immutable=audit_records", affected)
	if err != nil {
		log.Printf("gdpr erasure: compliance_events insert error: %v", err)
		httpx.Error(w, 500, "failed to log compliance event")
		return
	}

	httpx.WriteJSON(w, 200, map[string]interface{}{
		"status":            "completed",
		"records_affected":  affected,
		"subject_pseudonym": pseudonym,
		"immutable_tables":  immutableTables,
	})
}

// handleGDPRAccessRequest creates a logged subject access request for audit trail.
func (s *Server) handleGDPRAccessRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectID   string `json:"subject_id"`
		RequestedBy string `json:"requested_by"`
		Purpose     string `json:"purpose"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "invalid json")
		return
	}
	if req.SubjectID == "" {
		httpx.Error(w, 400, "subject_id required")
		return
	}
	actor, ok := s.resolveComplianceActor(w, r, req.RequestedBy)
	if !ok {
		return
	}
	if req.Purpose == "" {
		req.Purpose = "Subject access request"
	}

	hashedSubject := hashIdentity(req.SubjectID)

	// Log the access request for compliance trail
	_, err := s.DB.Exec(r.Context(), `
		INSERT INTO compliance_events(event_type, subject_hash, requested_by, reason)
		VALUES ($1, $2, $3, $4)
	`, "SUBJECT_ACCESS_REQUEST", hashedSubject, actor, req.Purpose)
	if err != nil {
		httpx.Error(w, 500, "failed to log access request")
		return
	}

	httpx.WriteJSON(w, 200, map[string]interface{}{
		"status":       "logged",
		"subject_hash": hashedSubject,
		"requested_by": actor,
	})
}

// resolveComplianceActorGDPR validates the requesting principal for GDPR operations.
func (s *Server) resolveComplianceActorGDPR(ctx context.Context, provided string) (string, bool) {
	provided = strings.TrimSpace(provided)
	if strings.EqualFold(s.AuthMode, "off") {
		return provided, provided != ""
	}
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok || strings.TrimSpace(principal.Subject) == "" {
		return "", false
	}
	return principal.Subject, true
}
