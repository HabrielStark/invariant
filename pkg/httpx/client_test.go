package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRequestJSONRetriesOn5xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"try again"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	status, body, err := RequestJSON(context.Background(), srv.Client(), http.MethodPost, srv.URL, []byte(`{"k":"v"}`), nil, 1, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected 200 got %d", status)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", string(body))
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts got %d", attempts)
	}
}

func TestRequestJSONNoRetryOn4xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad"}`))
	}))
	defer srv.Close()

	status, _, err := RequestJSON(context.Background(), srv.Client(), http.MethodPost, srv.URL, []byte(`{"k":"v"}`), nil, 3, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 got %d", status)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt got %d", attempts)
	}
}

func TestRequestJSONSetsHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Test-Header"); got != "abc" {
			t.Fatalf("expected header abc got %q", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	_, _, err := RequestJSON(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, map[string]string{"X-Test-Header": "abc"}, 0, 0)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type failingReadCloser struct{}

func (failingReadCloser) Read(p []byte) (int, error) { return 0, errors.New("read failed") }
func (failingReadCloser) Close() error               { return nil }

func TestRequestJSONAdditionalBranches(t *testing.T) {
	t.Run("nil client and content type for body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("expected json content type, got %q", got)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()
		status, _, err := RequestJSON(context.Background(), nil, http.MethodPost, srv.URL, []byte(`{"x":1}`), nil, 0, 0)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if status != http.StatusCreated {
			t.Fatalf("expected 201, got %d", status)
		}
	})

	t.Run("invalid method request build error", func(t *testing.T) {
		_, _, err := RequestJSON(context.Background(), http.DefaultClient, "bad method", "http://example.com", nil, nil, 0, 0)
		if err == nil {
			t.Fatal("expected invalid method error")
		}
	})

	t.Run("transport error with retries exhausted", func(t *testing.T) {
		client := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("dial failed")
			}),
		}
		_, _, err := RequestJSON(context.Background(), client, http.MethodGet, "http://example.com", nil, nil, -3, 0)
		if err == nil || !strings.Contains(err.Error(), "dial failed") {
			t.Fatalf("expected transport failure, got %v", err)
		}
	})

	t.Run("transport error retried then success", func(t *testing.T) {
		attempts := 0
		client := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				attempts++
				if attempts == 1 {
					return nil, errors.New("temporary network")
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
					Header:     http.Header{},
				}, nil
			}),
		}
		status, body, err := RequestJSON(context.Background(), client, http.MethodGet, "http://example.com", nil, nil, 1, 0)
		if err != nil {
			t.Fatalf("expected retry success, got %v", err)
		}
		if attempts != 2 || status != http.StatusOK || string(body) != `{"ok":true}` {
			t.Fatalf("unexpected retry result attempts=%d status=%d body=%s", attempts, status, string(body))
		}
	})

	t.Run("read error retried then success", func(t *testing.T) {
		attempts := 0
		client := &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				attempts++
				if attempts == 1 {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       failingReadCloser{},
						Header:     http.Header{},
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
					Header:     http.Header{},
				}, nil
			}),
		}
		status, body, err := RequestJSON(context.Background(), client, http.MethodGet, "http://example.com", nil, nil, 1, 0)
		if err != nil {
			t.Fatalf("expected retry after read error, got %v", err)
		}
		if attempts != 2 || status != http.StatusOK || string(body) != `{"ok":true}` {
			t.Fatalf("unexpected retry result attempts=%d status=%d body=%s", attempts, status, string(body))
		}
	})
}
