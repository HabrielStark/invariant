package palantir

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"axiom/pkg/httpx"
)

type Executor interface {
	Execute(ctx context.Context, payload json.RawMessage) (json.RawMessage, error)
}

type HTTPExecutor struct {
	Client     *http.Client
	Endpoint   string
	Headers    map[string]string
	Retries    int
	RetryDelay time.Duration
}

func (h HTTPExecutor) Execute(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	if h.Endpoint == "" {
		return nil, errors.New("endpoint is empty")
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	status, body, err := httpx.RequestJSON(ctx, client, http.MethodPost, h.Endpoint, payload, h.Headers, h.Retries, h.RetryDelay)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, errors.New("upstream error")
	}
	return body, nil
}
