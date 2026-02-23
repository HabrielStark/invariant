package httpx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

// RequestJSON performs an HTTP request with retry for transient failures.
// Retries apply to transport errors and 5xx responses only.
func RequestJSON(ctx context.Context, client *http.Client, method, url string, body []byte, headers map[string]string, retries int, retryDelay time.Duration) (int, []byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if retries < 0 {
		retries = 0
	}
	var lastErr error
	attempts := retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < retries {
				time.Sleep(retryDelay)
				continue
			}
			return 0, nil, err
		}
		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			if attempt < retries {
				time.Sleep(retryDelay)
				continue
			}
			return 0, nil, readErr
		}
		if resp.StatusCode >= 500 && attempt < retries {
			time.Sleep(retryDelay)
			continue
		}
		return resp.StatusCode, respBody, nil
	}
	return 0, nil, lastErr
}
