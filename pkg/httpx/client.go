package httpx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// MaxResponseBytes bounds buffered JSON responses from upstream services.
const MaxResponseBytes int64 = 16 << 20

var ErrResponseTooLarge = errors.New("HTTP response exceeds 16 MiB limit")

// ReadResponseBody never returns partial data as a successful response.
func ReadResponseBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxResponseBytes {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

// WaitRetry stops promptly when the calling operation is canceled.
func WaitRetry(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// RequestJSON performs an HTTP request with retry for transient failures.
// Retries apply to transport/read errors and 5xx responses. Callers must set
// retries to zero for side effects unless the upstream enforces idempotency.
func RequestJSON(ctx context.Context, client *http.Client, method, url string, body []byte, headers map[string]string, retries int, retryDelay time.Duration) (int, []byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if retries < 0 {
		retries = 0
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		if attempt > 0 {
			if err := WaitRetry(ctx, retryDelay); err != nil {
				return 0, nil, err
			}
		}
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
			if attempt < retries {
				continue
			}
			return 0, nil, err
		}
		respBody, readErr := ReadResponseBody(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			if attempt < retries && !errors.Is(readErr, ErrResponseTooLarge) {
				continue
			}
			return 0, nil, readErr
		}
		if resp.StatusCode >= 500 && attempt < retries {
			continue
		}
		return resp.StatusCode, respBody, nil
	}
}
