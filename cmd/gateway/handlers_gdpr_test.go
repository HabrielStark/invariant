package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axiom/pkg/auth"
	"axiom/pkg/metrics"
)

// ----- handleGDPRExport -----

func TestHandleGDPRExport_NoActor(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256", Metrics: metrics.NewRegistry()}
	req := httptest.NewRequest(http.MethodGet, "/v1/gdpr/export", nil)
	rr := httptest.NewRecorder()
	s.handleGDPRExport(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusUnauthorized && rr.Code != http.StatusBadRequest {
		t.Fatalf("expected error for unauthenticated request, got %d", rr.Code)
	}
}

func TestHandleGDPRExport_AuthOff(t *testing.T) {
	s := &Server{
		AuthMode: "off",
		Metrics:  metrics.NewRegistry(),
		DB:       &fakeGatewayDB{},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/gdpr/export?requested_by=user-1", nil)
	rr := httptest.NewRecorder()
	s.handleGDPRExport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["subject_id"] != "user-1" {
		t.Fatalf("unexpected subject_id: %v", resp["subject_id"])
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		t.Fatal("expected data object in response")
	}
}

func TestHandleGDPRExport_Authenticated(t *testing.T) {
	s := &Server{
		AuthMode: "oidc_rs256",
		Metrics:  metrics.NewRegistry(),
		DB:       &fakeGatewayDB{},
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/gdpr/export", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "compliance-officer",
		Tenant:  "tenant-a",
		Roles:   []string{"complianceofficer"},
	}))
	rr := httptest.NewRecorder()
	s.handleGDPRExport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ----- handleGDPRErasure -----

func TestHandleGDPRErasure_InvalidJSON(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGDPRErasure_MissingSubjectID(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"requested_by":"admin","reason":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing subject_id, got %d", rr.Code)
	}
}

func TestHandleGDPRErasure_Success(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","requested_by":"compliance-officer","reason":"GDPR request"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "completed" {
		t.Fatalf("expected completed, got %v", resp["status"])
	}
	if resp["subject_pseudonym"] == nil || resp["subject_pseudonym"] == "" {
		t.Fatal("expected pseudonym in response")
	}
}

func TestHandleGDPRErasure_Authenticated(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","reason":"GDPR Art.17"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/erasure", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "compliance-officer",
		Tenant:  "tenant-a",
		Roles:   []string{"complianceofficer"},
	}))
	rr := httptest.NewRecorder()
	s.handleGDPRErasure(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ----- handleGDPRAccessRequest -----

func TestHandleGDPRAccessRequest_InvalidJSON(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/access-request", strings.NewReader("{bad"))
	rr := httptest.NewRecorder()
	s.handleGDPRAccessRequest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGDPRAccessRequest_MissingSubjectID(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"requested_by":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/access-request", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRAccessRequest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing subject_id, got %d", rr.Code)
	}
}

func TestHandleGDPRAccessRequest_Success(t *testing.T) {
	s := &Server{AuthMode: "off", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","requested_by":"admin","purpose":"compliance review"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/access-request", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGDPRAccessRequest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "logged" {
		t.Fatalf("expected logged, got %v", resp["status"])
	}
	if resp["subject_hash"] == nil || resp["subject_hash"] == "" {
		t.Fatal("expected subject_hash in response")
	}
}

func TestHandleGDPRAccessRequest_Authenticated(t *testing.T) {
	s := &Server{AuthMode: "oidc_rs256", Metrics: metrics.NewRegistry(), DB: &fakeGatewayDB{}}
	body := `{"subject_id":"user-42","purpose":"data audit"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/gdpr/access-request", strings.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Subject: "security-admin",
		Tenant:  "tenant-a",
		Roles:   []string{"securityadmin"},
	}))
	rr := httptest.NewRecorder()
	s.handleGDPRAccessRequest(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}
