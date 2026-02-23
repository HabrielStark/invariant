package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axiom/pkg/auth"
	"axiom/pkg/metrics"

	"github.com/jackc/pgx/v5"
)

// ----- GDPR edge cases -----

func TestHandleGDPRErasure_NoRequestedByAuthOff(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","reason":"GDPR request"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when requested_by missing in auth=off, got %d", rr.Code)
	}
}

func TestHandleGDPRAccessRequest_NoRequestedByAuthOff(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","purpose":"audit"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/access-request", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRAccessRequest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when requested_by missing in auth=off, got %d", rr.Code)
	}
}

func TestHandleGDPRErasure_DefaultReason(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","requested_by":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleGDPRAccessRequest_DefaultPurpose(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","requested_by":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/access-request", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRAccessRequest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleGDPRExport_AuthOffNoRequestedBy(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	req := httptest.NewRequest(http.MethodGet, "/v1/gdpr/export", nil)
	rr := httptest.NewRecorder()
	s.handleGDPRExport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGDPRExport_DataStructure(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	req := httptest.NewRequest(http.MethodGet, "/v1/gdpr/export?requested_by=user-1", nil)
	rr := httptest.NewRecorder()
	s.handleGDPRExport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	data := resp["data"].(map[string]interface{})
	if _, ok := data["audit_decisions"]; !ok {
		t.Fatal("expected audit_decisions key in export")
	}
	if _, ok := data["escrows"]; !ok {
		t.Fatal("expected escrows key in export")
	}
	if _, ok := data["incidents"]; !ok {
		t.Fatal("expected incidents key in export")
	}
}

func TestHandleGDPRErasure_PrincipalMismatch(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","requested_by":"impostor"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "real-admin",
		Tenant:  "tenant-a",
		Roles:   []string{"complianceofficer"},
	}))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for principal mismatch, got %d", rr.Code)
	}
}

func TestHandleGDPRErasure_Unauthenticated(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","requested_by":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated, got %d", rr.Code)
	}
}

// ----- resolveComplianceActorGDPR -----

func TestResolveComplianceActorGDPR_AuthOff(t *testing.T) {
	s := &Server{AuthMode: "off"}
	actor, ok := s.resolveComplianceActorGDPR(context.Background(), "admin")
	if !ok || actor != "admin" {
		t.Fatalf("expected admin, got %q ok=%v", actor, ok)
	}
	_, ok = s.resolveComplianceActorGDPR(context.Background(), "")
	if ok {
		t.Fatal("expected false for empty actor when auth=off")
	}
}

func TestResolveComplianceActorGDPR_AuthOn(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256"}
	ctx := auth.WithPrincipal(context.Background(), auth.Principal{Subject: "admin-1"})
	actor, ok := s.resolveComplianceActorGDPR(ctx, "")
	if !ok || actor != "admin-1" {
		t.Fatalf("expected admin-1, got %q ok=%v", actor, ok)
	}
}

// ----- Histogram in MetricsMiddleware -----

func TestMetricsMiddlewareHistograms(t *testing.T) {
	s := &Server{Metrics: metrics.NewRegistry()}
	handler := s.metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
		handler.ServeHTTP(rr, req)
	}
	snap := s.Metrics.Snapshot()
	if len(snap.Histograms) != 1 {
		t.Fatalf("expected 1 histogram, got %d", len(snap.Histograms))
	}
	if snap.Histograms[0].Count != 10 {
		t.Fatalf("expected 10 observations, got %d", snap.Histograms[0].Count)
	}
}

func TestHandleGDPRExport_SubjectScopedQueries(t *testing.T) {
	subjectID := "subject-1"
	subjectHash := hashIdentity(subjectID)
	escrowScoped := false
	incidentScoped := false
	db := &fakeGatewayDB{
		queryFn: func(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
			switch {
			case strings.Contains(sql, "FROM audit_records"):
				return &fakeGatewayRows{}, nil
			case strings.Contains(sql, "FROM escrows"):
				if len(args) != 2 || args[0] != "tenant-a" || args[1] != subjectID {
					t.Fatalf("unexpected escrows args: %#v", args)
				}
				escrowScoped = true
				return &fakeGatewayRows{}, nil
			case strings.Contains(sql, "FROM incidents"):
				if len(args) != 3 || args[0] != "tenant-a" || args[1] != subjectHash || args[2] != subjectID {
					t.Fatalf("unexpected incidents args: %#v", args)
				}
				incidentScoped = true
				return &fakeGatewayRows{}, nil
			default:
				return &fakeGatewayRows{}, nil
			}
		},
	}
	s := &Server{
		AuthMode: "oidc_rs256",
		Metrics:  metrics.NewRegistry(),
		DB:       db,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/gdpr/export?subject_id=subject-1", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "compliance-officer",
		Tenant:  "tenant-a",
		Roles:   []string{"operator"},
	}))
	rr := httptest.NewRecorder()
	s.handleGDPRExport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !escrowScoped || !incidentScoped {
		t.Fatalf("expected scoped subject filters, escrows=%v incidents=%v", escrowScoped, incidentScoped)
	}
}

func TestHandleGDPRErasure_DoesNotMutateAuditRecords(t *testing.T) {
	db := &fakeGatewayDB{}
	s := &Server{
		AuthMode: "off",
		Metrics:  metrics.NewRegistry(),
		DB:       db,
	}
	body := `{"subject_id":"user-42","requested_by":"compliance-officer","reason":"GDPR request"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	for _, sql := range db.execSQL {
		if strings.Contains(sql, "UPDATE audit_records") {
			t.Fatalf("audit_records must remain immutable, got SQL=%s", sql)
		}
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode erasure response: %v", err)
	}
	immutable, _ := resp["immutable_tables"].([]interface{})
	if len(immutable) != 1 || immutable[0] != "audit_records" {
		t.Fatalf("expected immutable_tables with audit_records, got %#v", resp["immutable_tables"])
	}
}
