package agentsdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/models"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	AuthToken  string
}

type ExecuteRequest struct {
	Intent        models.ActionIntent `json:"intent"`
	Cert          models.ActionCert   `json:"cert"`
	ToolPayload   json.RawMessage     `json:"tool_payload,omitempty"`
	ActionPayload json.RawMessage     `json:"action_payload,omitempty"`
}

type Signer struct {
	Kid        string
	SignerName string
	PrivateKey ed25519.PrivateKey
}

func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func NewSignerFromBase64(kid, signerName, privateKeyB64 string) (Signer, error) {
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privateKeyB64))
	if err != nil {
		return Signer{}, fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return Signer{}, fmt.Errorf("invalid private key length: got=%d want=%d", len(privBytes), ed25519.PrivateKeySize)
	}
	if kid == "" {
		return Signer{}, fmt.Errorf("kid is required")
	}
	if signerName == "" {
		signerName = "agent"
	}
	return Signer{Kid: kid, SignerName: signerName, PrivateKey: ed25519.PrivateKey(privBytes)}, nil
}

func ComputeIntentHash(intent models.ActionIntent, policyVersion, nonce string) (string, error) {
	raw, err := json.Marshal(intent)
	if err != nil {
		return "", fmt.Errorf("marshal intent: %w", err)
	}
	if err := models.ValidateNoJSONNumbers(raw); err != nil {
		return "", err
	}
	canon, err := models.CanonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	return models.IntentHash(canon, policyVersion, nonce), nil
}

func BindAndSignCert(intent models.ActionIntent, cert *models.ActionCert, signer Signer, ttl time.Duration, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("cert is nil")
	}
	if cert.PolicyVersion == "" {
		return fmt.Errorf("cert.policy_version is required")
	}
	if cert.PolicySetID == "" {
		return fmt.Errorf("cert.policy_set_id is required")
	}
	if cert.Nonce == "" {
		return fmt.Errorf("cert.nonce is required")
	}
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	intentHash, err := ComputeIntentHash(intent, cert.PolicyVersion, cert.Nonce)
	if err != nil {
		return err
	}
	cert.IntentHash = intentHash
	if cert.ExpiresAt == "" {
		cert.ExpiresAt = now.Add(ttl).Format(time.RFC3339)
	}
	cert.Signature.Kid = signer.Kid
	cert.Signature.Signer = signer.SignerName
	cert.Signature.Alg = "ed25519"
	payload, err := auth.SignaturePayload(*cert)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(signer.PrivateKey, payload)
	cert.Signature.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

func (c *Client) ExecuteTool(ctx context.Context, req ExecuteRequest) (models.GatewayResponse, error) {
	return c.execute(ctx, "/v1/tool/execute", req)
}

func (c *Client) ExecuteOntology(ctx context.Context, req ExecuteRequest) (models.GatewayResponse, error) {
	return c.execute(ctx, "/v1/ontology/actions/execute", req)
}

func (c *Client) Verify(ctx context.Context, intent models.ActionIntent, cert models.ActionCert) (models.VerifierResponse, error) {
	payload := map[string]interface{}{
		"intent": intent,
		"cert":   cert,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return models.VerifierResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/verify", bytes.NewReader(body))
	if err != nil {
		return models.VerifierResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyAuth(httpReq)
	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return models.VerifierResponse{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return models.VerifierResponse{}, fmt.Errorf("verify failed status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var out models.VerifierResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return models.VerifierResponse{}, err
	}
	return out, nil
}

func (c *Client) ApproveEscrow(ctx context.Context, escrowID, approver string) (map[string]interface{}, error) {
	payload := map[string]string{"escrow_id": escrowID}
	if strings.TrimSpace(c.AuthToken) == "" && strings.TrimSpace(approver) != "" {
		payload["approver"] = approver
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/escrow/approve", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyAuth(httpReq)
	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("approve failed status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var out map[string]interface{}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) execute(ctx context.Context, path string, req ExecuteRequest) (models.GatewayResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return models.GatewayResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return models.GatewayResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.applyAuth(httpReq)
	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return models.GatewayResponse{}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return models.GatewayResponse{}, fmt.Errorf("execute failed status=%d body=%s", resp.StatusCode, string(respBody))
	}
	var out models.GatewayResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return models.GatewayResponse{}, err
	}
	return out, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (c *Client) applyAuth(req *http.Request) {
	if c.AuthToken == "" {
		return
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.AuthToken))
}
