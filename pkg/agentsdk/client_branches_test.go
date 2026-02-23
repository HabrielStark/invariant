package agentsdk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"axiom/pkg/models"
)

func TestNewClientDefaultsAndTrim(t *testing.T) {
	c := NewClient("https://api.example/", 0)
	if c.BaseURL != "https://api.example" {
		t.Fatalf("expected trimmed base url, got %q", c.BaseURL)
	}
	if c.HTTPClient == nil || c.HTTPClient.Timeout != 5*time.Second {
		t.Fatalf("expected default timeout 5s, got %#v", c.HTTPClient)
	}
}

func TestApplyAuthTrimsToken(t *testing.T) {
	c := &Client{AuthToken: "  token-1  "}
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	c.applyAuth(req)
	if got := req.Header.Get("Authorization"); got != "Bearer token-1" {
		t.Fatalf("unexpected auth header: %q", got)
	}
}

func TestVerifyAndApproveStatusErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/verify":
			http.Error(w, "verify bad", http.StatusForbidden)
		case "/v1/escrow/approve":
			http.Error(w, "approve bad", http.StatusConflict)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := NewClient(ts.URL, time.Second)
	if _, err := c.Verify(context.Background(), models.ActionIntent{}, models.ActionCert{}); err == nil || !strings.Contains(err.Error(), "status=403") {
		t.Fatalf("expected verify status error, got %v", err)
	}
	if _, err := c.ApproveEscrow(context.Background(), "e1", "approver"); err == nil || !strings.Contains(err.Error(), "status=409") {
		t.Fatalf("expected approve status error, got %v", err)
	}
}
