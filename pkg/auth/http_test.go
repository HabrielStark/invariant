package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func signHS256(t *testing.T, claims map[string]interface{}, secret string) string {
	t.Helper()
	headerRaw, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payloadRaw, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(headerRaw)
	p := base64.RawURLEncoding.EncodeToString(payloadRaw)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(h + "." + p))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return h + "." + p + "." + sig
}

func TestVerifyHS256Token(t *testing.T) {
	secret := "test-secret"
	tok := signHS256(t, map[string]interface{}{
		"sub":    "user-1",
		"roles":  []string{"Operator", "ComplianceOfficer"},
		"tenant": "acme",
		"iss":    "issuer-hs",
		"aud":    "axiomos",
		"exp":    time.Now().UTC().Add(time.Minute).Unix(),
	}, secret)
	claims, err := VerifyHS256Token(tok, secret, time.Now().UTC(), "issuer-hs", "axiomos")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if claims.Sub != "user-1" || claims.Tenant != "acme" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if len(claims.Roles) != 2 {
		t.Fatalf("unexpected roles: %+v", claims.Roles)
	}
}

func TestVerifyHS256TokenIssuerMismatch(t *testing.T) {
	secret := "test-secret"
	tok := signHS256(t, map[string]interface{}{
		"sub": "user-1",
		"iss": "issuer-1",
		"exp": time.Now().UTC().Add(time.Minute).Unix(),
	}, secret)
	if _, err := VerifyHS256Token(tok, secret, time.Now().UTC(), "issuer-2", ""); err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestVerifyHS256TokenAudienceMismatch(t *testing.T) {
	secret := "test-secret"
	tok := signHS256(t, map[string]interface{}{
		"sub": "user-1",
		"aud": []string{"a", "b"},
		"exp": time.Now().UTC().Add(time.Minute).Unix(),
	}, secret)
	if _, err := VerifyHS256Token(tok, secret, time.Now().UTC(), "", "c"); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestMiddlewareRejectsInvalidToken(t *testing.T) {
	mw := Middleware("oidc_hs256", "secret")
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad.token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareInjectsPrincipal(t *testing.T) {
	secret := "secret"
	tok := signHS256(t, map[string]interface{}{
		"sub":   "user-2",
		"roles": []string{"Operator"},
		"exp":   time.Now().UTC().Add(time.Minute).Unix(),
	}, secret)
	mw := Middleware("oidc_hs256", secret)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			t.Fatalf("principal missing")
		}
		if p.Subject != "user-2" {
			t.Fatalf("unexpected subject %s", p.Subject)
		}
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestHasAnyRole(t *testing.T) {
	p := Principal{Roles: []string{"Operator", "SecurityAdmin"}}
	if !HasAnyRole(p, "securityadmin") {
		t.Fatal("expected role match")
	}
	if HasAnyRole(p, "ComplianceOfficer") {
		t.Fatal("unexpected role match")
	}
}

func signRS256(t *testing.T, claims map[string]interface{}, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	headerRaw, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payloadRaw, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(headerRaw)
	p := base64.RawURLEncoding.EncodeToString(payloadRaw)
	sum := sha256.Sum256([]byte(h + "." + p))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyRS256Token(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": "kid-1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e},
			},
		})
	}))
	defer jwks.Close()

	cache := newJWKSCache(jwks.URL, 2*time.Second)
	now := time.Now().UTC()
	token := signRS256(t, map[string]any{
		"sub":    "user-rs",
		"roles":  []string{"Operator"},
		"tenant": "acme",
		"iss":    "https://issuer.test",
		"aud":    "axiomos",
		"exp":    now.Add(time.Minute).Unix(),
	}, key, "kid-1")

	claims, err := VerifyRS256Token(token, now, cache, "https://issuer.test", "axiomos")
	if err != nil {
		t.Fatalf("verify rs256 failed: %v", err)
	}
	if claims.Sub != "user-rs" {
		t.Fatalf("unexpected sub: %s", claims.Sub)
	}
}

func TestMiddlewareRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": "kid-2", "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e},
			},
		})
	}))
	defer jwks.Close()

	now := time.Now().UTC()
	token := signRS256(t, map[string]any{
		"sub":   "rs-user",
		"roles": []string{"Operator"},
		"iss":   "issuer-rs",
		"aud":   []string{"axiomos", "other"},
		"exp":   now.Add(2 * time.Minute).Unix(),
	}, key, "kid-2")

	mw := Middleware("oidc_rs256", "", WithJWKS(jwks.URL), WithIssuer("issuer-rs"), WithAudience("axiomos"), WithTimeout(2*time.Second))
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.Subject != "rs-user" {
			t.Fatalf("principal missing: %+v", p)
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", rr.Code, strings.TrimSpace(rr.Body.String()))
	}
}

func TestJWKSCacheMissingKid(t *testing.T) {
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{},
		})
	}))
	defer jwks.Close()
	cache := newJWKSCache(jwks.URL, time.Second)
	_, err := cache.key(context.Background(), "missing", time.Now().UTC())
	if err == nil {
		t.Fatal("expected error for missing kid")
	}
}

func TestIsValidURL(t *testing.T) {
	if IsValidURL("") {
		t.Fatal("empty url must be invalid")
	}
	if IsValidURL("   ") {
		t.Fatal("blank url must be invalid")
	}
	if IsValidURL("://broken") {
		t.Fatal("malformed url must be invalid")
	}
	if IsValidURL("http:///missing-host") {
		t.Fatal("url without host must be invalid")
	}
	if !IsValidURL("https://example.com/path") {
		t.Fatal("https url with host must be valid")
	}
	if !IsValidURL("http://localhost:8080/healthz") {
		t.Fatal("localhost url must be valid")
	}
}
