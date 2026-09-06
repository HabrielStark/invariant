package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRequestJSONCancellationDuringRetry(t *testing.T) {
	for _, failure := range []string{"transport", "body", "status"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempts := 0
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				attempts++
				cancel()
				switch failure {
				case "transport":
					return nil, errors.New("connection reset")
				case "body":
					return &http.Response{StatusCode: 200, Body: failingReadCloser{}, Header: http.Header{}}, nil
				default:
					return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable")), Header: http.Header{}}, nil
				}
			})}
			done := make(chan error, 1)
			go func() {
				_, _, err := RequestJSON(ctx, client, "GET", "http://example.com", nil, nil, 2, time.Hour)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("retry ignored cancellation")
			}
			if attempts != 1 {
				t.Fatalf("made %d requests after cancellation", attempts)
			}
		})
	}
}

func TestWaitRetryDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := WaitRetry(ctx, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

type repeatedByteReader struct{}

func (repeatedByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestReadResponseBodyLimit(t *testing.T) {
	if _, err := ReadResponseBody(repeatedByteReader{}); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("got %v", err)
	}
	body, err := ReadResponseBody(io.LimitReader(repeatedByteReader{}, MaxResponseBytes))
	if err != nil || int64(len(body)) != MaxResponseBytes {
		t.Fatalf("exact limit rejected: %v", err)
	}
}

func TestRequestJSONOversizedResponseIsNotRetried(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(repeatedByteReader{})}, nil
	})}
	_, body, err := RequestJSON(context.Background(), client, "GET", "http://example.com", nil, nil, 2, 0)
	if !errors.Is(err, ErrResponseTooLarge) || body != nil || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}
