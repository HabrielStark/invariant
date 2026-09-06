package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"axiom/pkg/httpx"
)

// VaultTransitKeyStore resolves Ed25519 public keys from Vault Transit.
type VaultTransitKeyStore struct {
	Client     *http.Client
	Addr       string
	Token      string
	Namespace  string
	Transit    string
	KeyPrefix  string
	Timeout    time.Duration
	MaxRetries int
	RetryDelay time.Duration
}

func (s VaultTransitKeyStore) GetKey(ctx context.Context, kid string) (*KeyRecord, error) {
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, errors.New("kid required")
	}
	addr := strings.TrimRight(strings.TrimSpace(s.Addr), "/")
	if addr == "" {
		return nil, errors.New("vault addr required")
	}
	if strings.TrimSpace(s.Token) == "" {
		return nil, errors.New("vault token required")
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	if s.Transit == "" {
		s.Transit = "transit"
	}
	if s.Timeout <= 0 {
		s.Timeout = 1500 * time.Millisecond
	}
	if s.MaxRetries < 0 {
		s.MaxRetries = 0
	}
	if s.RetryDelay < 0 {
		s.RetryDelay = 0
	}
	keyName := s.KeyPrefix + kid
	keyPath := "/v1/" + strings.Trim(s.Transit, "/") + "/keys/" + url.PathEscape(keyName)
	endpoint := addr + keyPath

	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if attempt > 0 {
			if err := httpx.WaitRetry(ctx, s.RetryDelay); err != nil {
				return nil, err
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, s.Timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("X-Vault-Token", s.Token)
		if strings.TrimSpace(s.Namespace) != "" {
			req.Header.Set("X-Vault-Namespace", s.Namespace)
		}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if attempt < s.MaxRetries {
				continue
			}
			break
		}
		body, readErr := httpx.ReadResponseBody(resp.Body)
		_ = resp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = readErr
			if attempt < s.MaxRetries && !errors.Is(readErr, httpx.ErrResponseTooLarge) {
				continue
			}
			break
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("kid %q not found in vault transit", kid)
		}
		if resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("vault transit key lookup failed status=%d", resp.StatusCode)
			if attempt < s.MaxRetries && (resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests) {
				continue
			}
			break
		}
		pub, err := parseVaultTransitPublicKey(body)
		if err != nil {
			return nil, err
		}
		return &KeyRecord{
			Kid:       kid,
			Signer:    "vault-transit:" + keyName,
			PublicKey: pub,
			Status:    "active",
		}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("vault transit lookup failed")
	}
	return nil, lastErr
}

func parseVaultTransitPublicKey(body []byte) ([]byte, error) {
	var payload struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("invalid vault response: %w", err)
	}
	if len(payload.Data.Keys) == 0 {
		return nil, errors.New("vault response missing key versions")
	}
	version := payload.Data.LatestVersion
	if version <= 0 {
		for k := range payload.Data.Keys {
			if n, err := strconv.Atoi(k); err == nil && n > version {
				version = n
			}
		}
	}
	versionKey := strconv.Itoa(version)
	item, ok := payload.Data.Keys[versionKey]
	if !ok {
		return nil, errors.New("vault response missing latest public key")
	}
	pub := strings.TrimSpace(item.PublicKey)
	if pub == "" {
		return nil, errors.New("vault response has empty public key")
	}
	if parts := strings.SplitN(pub, ":", 2); len(parts) == 2 {
		pub = strings.TrimSpace(parts[1])
	}
	pk, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return nil, fmt.Errorf("vault public key decode failed: %w", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("vault public key must be 32 bytes for Ed25519")
	}
	return pk, nil
}
