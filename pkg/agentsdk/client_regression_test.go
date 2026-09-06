package agentsdk

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"axiom/pkg/models"
)

var errTruncated = errors.New("truncated response")

type truncatedResponse struct {
	sent   bool
	closed bool
}

func (b *truncatedResponse) Read(p []byte) (int, error) {
	if b.sent {
		return 0, errTruncated
	}
	b.sent = true
	return copy(p, `{"verdict":"ALLOW","status":"APPROVED"}`), errTruncated
}
func (b *truncatedResponse) Close() error { b.closed = true; return nil }

type regressionTransport func(*http.Request) (*http.Response, error)

func (f regressionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientRejectsPartialResponse(t *testing.T) {
	for _, endpoint := range []string{"verify", "tool", "ontology", "approve"} {
		t.Run(endpoint, func(t *testing.T) {
			body := &truncatedResponse{}
			c := NewClient("http://example.com", time.Second)
			c.HTTPClient.Transport = regressionTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
			})
			var err error
			switch endpoint {
			case "verify":
				_, err = c.Verify(context.Background(), models.ActionIntent{}, models.ActionCert{})
			case "tool":
				_, err = c.ExecuteTool(context.Background(), ExecuteRequest{})
			case "ontology":
				_, err = c.ExecuteOntology(context.Background(), ExecuteRequest{})
			case "approve":
				_, err = c.ApproveEscrow(context.Background(), "e1", "manager")
			}
			if !errors.Is(err, errTruncated) {
				t.Fatalf("expected read failure, got %v", err)
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestBindAndSignCertInvalidKeyDoesNotMutateCert(t *testing.T) {
	cert := models.ActionCert{PolicySetID: "p", PolicyVersion: "v1", Nonce: "n"}
	if err := BindAndSignCert(models.ActionIntent{}, &cert, Signer{}, time.Minute, time.Now()); err == nil {
		t.Fatal("accepted invalid key")
	}
	if cert.IntentHash != "" || cert.ExpiresAt != "" || cert.Signature.Sig != "" {
		t.Fatal("modified certificate after invalid key")
	}
}
