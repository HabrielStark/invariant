package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Principal struct {
	Subject string
	Roles   []string
	Tenant  string
}

type contextKey string

const principalContextKey contextKey = "axiom.principal"

type MiddlewareConfig struct {
	JWKSURL  string
	Issuer   string
	Audience string
	Timeout  time.Duration
}

type MiddlewareOption func(*MiddlewareConfig)

func WithJWKS(url string) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.JWKSURL = strings.TrimSpace(url)
	}
}

func WithIssuer(issuer string) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.Issuer = strings.TrimSpace(issuer)
	}
}

func WithAudience(audience string) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.Audience = strings.TrimSpace(audience)
	}
}

func WithTimeout(timeout time.Duration) MiddlewareOption {
	return func(cfg *MiddlewareConfig) {
		cfg.Timeout = timeout
	}
}

func Middleware(mode, secret string, options ...MiddlewareOption) func(http.Handler) http.Handler {
	mode = strings.ToLower(strings.TrimSpace(mode))
	cfg := MiddlewareConfig{Timeout: 5 * time.Second}
	for _, opt := range options {
		opt(&cfg)
	}
	if mode == "" || mode == "off" {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), Principal{Subject: "anonymous", Roles: []string{"anonymous"}})))
			})
		}
	}
	var jwksCache *jwksCache
	if mode == "oidc_rs256" {
		jwksCache = newJWKSCache(cfg.JWKSURL, cfg.Timeout)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := strings.TrimSpace(r.Header.Get("Authorization"))
			if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			token := strings.TrimSpace(header[len("Bearer "):])
			var (
				claims TokenClaims
				err    error
			)
			switch mode {
			case "oidc_hs256":
				claims, err = VerifyHS256Token(token, secret, time.Now().UTC(), cfg.Issuer, cfg.Audience)
			case "oidc_rs256":
				claims, err = VerifyRS256Token(token, time.Now().UTC(), jwksCache, cfg.Issuer, cfg.Audience)
			default:
				err = errors.New("unsupported auth mode")
			}
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), Principal{
				Subject: claims.Sub,
				Roles:   claims.Roles,
				Tenant:  claims.Tenant,
			})))
		})
	}
}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalContextKey, p)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	v := ctx.Value(principalContextKey)
	if v == nil {
		return Principal{}, false
	}
	p, ok := v.(Principal)
	return p, ok
}

func HasAnyRole(p Principal, required ...string) bool {
	if len(required) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, r := range p.Roles {
		set[strings.ToLower(strings.TrimSpace(r))] = struct{}{}
	}
	for _, rr := range required {
		if _, ok := set[strings.ToLower(strings.TrimSpace(rr))]; ok {
			return true
		}
	}
	return false
}

type TokenClaims struct {
	Sub    string   `json:"sub"`
	Roles  []string `json:"roles"`
	Tenant string   `json:"tenant"`
	Iss    string   `json:"iss,omitempty"`
	Aud    any      `json:"aud,omitempty"`
	Exp    int64    `json:"exp"`
	Nbf    int64    `json:"nbf,omitempty"`
	Iat    int64    `json:"iat,omitempty"`
}

func VerifyHS256Token(token, secret string, now time.Time, issuer, audience string) (TokenClaims, error) {
	if secret == "" {
		return TokenClaims{}, errors.New("secret is required")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenClaims{}, errors.New("invalid token format")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return TokenClaims{}, err
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return TokenClaims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return TokenClaims{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return TokenClaims{}, err
	}
	if strings.ToUpper(header.Alg) != "HS256" {
		return TokenClaims{}, errors.New("unsupported alg")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return TokenClaims{}, errors.New("signature mismatch")
	}
	var claims TokenClaims
	var rawClaims map[string]json.RawMessage
	if err := json.Unmarshal(payloadRaw, &rawClaims); err != nil {
		return TokenClaims{}, err
	}
	if raw, ok := rawClaims["sub"]; ok {
		_ = json.Unmarshal(raw, &claims.Sub)
	}
	if raw, ok := rawClaims["tenant"]; ok {
		_ = json.Unmarshal(raw, &claims.Tenant)
	}
	if raw, ok := rawClaims["exp"]; ok {
		_ = json.Unmarshal(raw, &claims.Exp)
	}
	if raw, ok := rawClaims["nbf"]; ok {
		_ = json.Unmarshal(raw, &claims.Nbf)
	}
	if raw, ok := rawClaims["iat"]; ok {
		_ = json.Unmarshal(raw, &claims.Iat)
	}
	if raw, ok := rawClaims["roles"]; ok {
		if err := json.Unmarshal(raw, &claims.Roles); err != nil {
			var single string
			if err2 := json.Unmarshal(raw, &single); err2 == nil && single != "" {
				claims.Roles = []string{single}
			}
		}
	}
	if raw, ok := rawClaims["iss"]; ok {
		_ = json.Unmarshal(raw, &claims.Iss)
	}
	if raw, ok := rawClaims["aud"]; ok {
		var audAny any
		_ = json.Unmarshal(raw, &audAny)
		claims.Aud = audAny
	}
	if claims.Exp == 0 || now.Unix() >= claims.Exp {
		return TokenClaims{}, errors.New("token expired")
	}
	if claims.Nbf != 0 && now.Unix() < claims.Nbf {
		return TokenClaims{}, errors.New("token not active")
	}
	if claims.Sub == "" {
		return TokenClaims{}, errors.New("subject required")
	}
	if issuer != "" && claims.Iss != issuer {
		return TokenClaims{}, errors.New("issuer mismatch")
	}
	if audience != "" && !audContains(claims.Aud, audience) {
		return TokenClaims{}, errors.New("audience mismatch")
	}
	return claims, nil
}

type jwksCache struct {
	url       string
	timeout   time.Duration
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
	client    *http.Client
}

func newJWKSCache(jwksURL string, timeout time.Duration) *jwksCache {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &jwksCache{
		url:     jwksURL,
		timeout: timeout,
		keys:    map[string]*rsa.PublicKey{},
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *jwksCache) key(ctx context.Context, kid string, now time.Time) (*rsa.PublicKey, error) {
	if c == nil {
		return nil, errors.New("jwks cache is nil")
	}
	if c.url == "" {
		return nil, errors.New("jwks url is required")
	}
	c.mu.RLock()
	if key, ok := c.keys[kid]; ok && now.Before(c.expiresAt) {
		c.mu.RUnlock()
		return key, nil
	}
	c.mu.RUnlock()
	if err := c.refresh(ctx, now); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, errors.New("kid not found in jwks")
	}
	return key, nil
}

func (c *jwksCache) refresh(ctx context.Context, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Before(c.expiresAt) {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("jwks fetch failed")
	}
	var payload struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	next := map[string]*rsa.PublicKey{}
	for _, k := range payload.Keys {
		if strings.ToUpper(k.Kty) != "RSA" || strings.TrimSpace(k.Kid) == "" {
			continue
		}
		pub, err := rsaFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return errors.New("jwks has no valid rsa keys")
	}
	c.keys = next
	c.expiresAt = now.Add(5 * time.Minute)
	return nil
}

func rsaFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	if len(eb) == 0 {
		return nil, errors.New("invalid exponent")
	}
	e := 0
	for _, b := range eb {
		e = e<<8 + int(b)
	}
	if e <= 1 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

func VerifyRS256Token(token string, now time.Time, cache *jwksCache, issuer, audience string) (TokenClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenClaims{}, errors.New("invalid token format")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return TokenClaims{}, err
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return TokenClaims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return TokenClaims{}, err
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return TokenClaims{}, err
	}
	if strings.ToUpper(header.Alg) != "RS256" {
		return TokenClaims{}, errors.New("unsupported alg")
	}
	if strings.TrimSpace(header.Kid) == "" {
		return TokenClaims{}, errors.New("kid required")
	}
	pub, err := cache.key(context.Background(), header.Kid, now)
	if err != nil {
		return TokenClaims{}, err
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return TokenClaims{}, err
	}
	var claims TokenClaims
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payloadRaw, &raw); err != nil {
		return TokenClaims{}, err
	}
	if v, ok := raw["sub"]; ok {
		_ = json.Unmarshal(v, &claims.Sub)
	}
	if v, ok := raw["tenant"]; ok {
		_ = json.Unmarshal(v, &claims.Tenant)
	}
	if v, ok := raw["roles"]; ok {
		if err := json.Unmarshal(v, &claims.Roles); err != nil {
			var single string
			if err2 := json.Unmarshal(v, &single); err2 == nil && single != "" {
				claims.Roles = []string{single}
			}
		}
	}
	if v, ok := raw["exp"]; ok {
		_ = json.Unmarshal(v, &claims.Exp)
	}
	if v, ok := raw["nbf"]; ok {
		_ = json.Unmarshal(v, &claims.Nbf)
	}
	if v, ok := raw["iat"]; ok {
		_ = json.Unmarshal(v, &claims.Iat)
	}
	if v, ok := raw["iss"]; ok {
		_ = json.Unmarshal(v, &claims.Iss)
	}
	if v, ok := raw["aud"]; ok {
		var audAny any
		_ = json.Unmarshal(v, &audAny)
		claims.Aud = audAny
	}
	if claims.Sub == "" {
		return TokenClaims{}, errors.New("subject required")
	}
	if claims.Exp == 0 || now.Unix() >= claims.Exp {
		return TokenClaims{}, errors.New("token expired")
	}
	if claims.Nbf != 0 && now.Unix() < claims.Nbf {
		return TokenClaims{}, errors.New("token not active")
	}
	if issuer != "" && claims.Iss != issuer {
		return TokenClaims{}, errors.New("issuer mismatch")
	}
	if audience != "" && !audContains(claims.Aud, audience) {
		return TokenClaims{}, errors.New("audience mismatch")
	}
	return claims, nil
}

func audContains(aud any, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case nil:
		return false
	}
	return false
}

func IsValidURL(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}
