package openclaw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"axiom/pkg/models"
)

type GatewayClient interface {
	ExecuteTool(ctx context.Context, req GatewayExecuteRequest) (models.GatewayResponse, error)
	ListEscrows(ctx context.Context, limit int, status string) (json.RawMessage, error)
	ApproveEscrow(ctx context.Context, escrowID, approver string) (json.RawMessage, error)
	ExecuteEscrow(ctx context.Context, escrowID string) (json.RawMessage, error)
}

type HTTPGatewayClient struct {
	BaseURL       string
	HTTPClient    *http.Client
	AuthHeader    string
	AuthToken     string
	UpstreamRetry int
}

func NewHTTPGatewayClient(cfg Config) *HTTPGatewayClient {
	client := &http.Client{Timeout: cfg.RequestTimeout}
	return &HTTPGatewayClient{
		BaseURL:       strings.TrimRight(cfg.GatewayURL, "/"),
		HTTPClient:    client,
		AuthHeader:    strings.TrimSpace(cfg.AuthHeader),
		AuthToken:     strings.TrimSpace(cfg.AuthToken),
		UpstreamRetry: 1,
	}
}

func (c *HTTPGatewayClient) ExecuteTool(ctx context.Context, req GatewayExecuteRequest) (models.GatewayResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return models.GatewayResponse{}, fmt.Errorf("marshal execute request: %w", err)
	}
	respBody, status, err := c.doJSON(ctx, http.MethodPost, c.BaseURL+"/v1/tool/execute", body)
	if err != nil {
		return models.GatewayResponse{}, err
	}
	if status != http.StatusOK {
		return models.GatewayResponse{}, fmt.Errorf("gateway status %d: %s", status, string(respBody))
	}
	var response models.GatewayResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return models.GatewayResponse{}, fmt.Errorf("decode gateway response: %w", err)
	}
	return response, nil
}

func (c *HTTPGatewayClient) ListEscrows(ctx context.Context, limit int, status string) (json.RawMessage, error) {
	url := c.BaseURL + "/v1/escrows"
	sep := "?"
	if limit > 0 {
		url += fmt.Sprintf("%slimit=%d", sep, limit)
		sep = "&"
	}
	if strings.TrimSpace(status) != "" {
		url += fmt.Sprintf("%sstatus=%s", sep, status)
	}
	body, httpStatus, err := c.doJSON(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if httpStatus != http.StatusOK {
		return nil, fmt.Errorf("list escrows status %d: %s", httpStatus, string(body))
	}
	return body, nil
}

func (c *HTTPGatewayClient) ApproveEscrow(ctx context.Context, escrowID, approver string) (json.RawMessage, error) {
	payload := map[string]string{"escrow_id": escrowID, "approver": approver}
	body, _ := json.Marshal(payload)
	respBody, status, err := c.doJSON(ctx, http.MethodPost, c.BaseURL+"/v1/escrow/approve", body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("approve escrow status %d: %s", status, string(respBody))
	}
	return respBody, nil
}

func (c *HTTPGatewayClient) ExecuteEscrow(ctx context.Context, escrowID string) (json.RawMessage, error) {
	payload := map[string]string{"escrow_id": escrowID}
	body, _ := json.Marshal(payload)
	respBody, status, err := c.doJSON(ctx, http.MethodPost, c.BaseURL+"/v1/escrow/execute", body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("execute escrow status %d: %s", status, string(respBody))
	}
	return respBody, nil
}

func (c *HTTPGatewayClient) doJSON(ctx context.Context, method, url string, body []byte) ([]byte, int, error) {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	attempts := c.UpstreamRetry + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		var bodyReader io.Reader
		if len(body) > 0 {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		if c.AuthHeader != "" && c.AuthToken != "" {
			req.Header.Set(c.AuthHeader, c.AuthToken)
		}
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		return respBody, resp.StatusCode, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("request failed")
	}
	return nil, 0, lastErr
}
