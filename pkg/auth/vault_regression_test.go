package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type vaultRegressionTransport func(*http.Request) (*http.Response, error)

func (f vaultRegressionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVaultRetryPolicy(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			attempts := 0
			client := &http.Client{Transport: vaultRegressionTransport(func(*http.Request) (*http.Response, error) {
				attempts++
				code, body := status, "{}"
				if attempts > 1 {
					code = 200
					body = fmt.Sprintf(`{"data":{"latest_version":1,"keys":{"1":{"public_key":%q}}}}`, base64.StdEncoding.EncodeToString(make([]byte, 32)))
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})}
			ks := VaultTransitKeyStore{Client: client, Addr: "http://example.com", Token: "test", MaxRetries: 2, RetryDelay: 0}
			_, err := ks.GetKey(context.Background(), "key")
			if status == 429 || status >= 500 {
				if err != nil || attempts != 2 {
					t.Fatalf("retry failed attempts=%d err=%v", attempts, err)
				}
			} else if err == nil || attempts != 1 {
				t.Fatalf("retried permanent error attempts=%d err=%v", attempts, err)
			}
		})
	}
}

func TestVaultCancellationDuringRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &http.Client{Transport: vaultRegressionTransport(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, errors.New("connection reset")
	})}
	ks := VaultTransitKeyStore{Client: client, Addr: "http://example.com", Token: "test", MaxRetries: 2, RetryDelay: time.Hour}
	done := make(chan error, 1)
	go func() { _, err := ks.GetKey(ctx, "key"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled vault lookup stuck in backoff")
	}
}

func TestVaultRejectsWrongKeyLength(t *testing.T) {
	raw := []byte(`{"data":{"latest_version":1,"keys":{"1":{"public_key":"YWJj"}}}}`)
	if _, err := parseVaultTransitPublicKey(raw); err == nil {
		t.Fatal("accepted three-byte key")
	}
}
