package auth

import (
	"context"
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

func signHS256WithHeader(t *testing.T, header map[string]string, claims map[string]interface{}, secret string) string {
	t.Helper()
	headerRaw, _ := json.Marshal(header)
	payloadRaw, _ := json.Marshal(claims)
	h := base64.RawURLEncoding.EncodeToString(headerRaw)
	p := base64.RawURLEncoding.EncodeToString(payloadRaw)
	sig := hmacSHA256(h+"."+p, secret)
	return h + "." + p + "." + sig
}

func hmacSHA256(msg, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func jwksServerForKey(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e},
			},
		})
	}))
}

func TestMiddlewareModeBranches(t *testing.T) {
	t.Run("off_mode_injects_anonymous", func(t *testing.T) {
		mw := Middleware("off", "")
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFromContext(r.Context())
			if !ok || p.Subject != "anonymous" || len(p.Roles) != 1 || p.Roles[0] != "anonymous" {
				t.Fatalf("expected anonymous principal injection, got %+v ok=%v", p, ok)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("expected 204 from wrapped handler, got %d", rr.Code)
		}
	})

	t.Run("unsupported_mode_denied", func(t *testing.T) {
		mw := Middleware("unknown_mode", "")
		h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer abc.def.ghi")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected unsupported mode to deny, got %d", rr.Code)
		}
	})
}

func TestVerifyHS256AdditionalBranches(t *testing.T) {
	now := time.Now().UTC()

	if _, err := VerifyHS256Token("a.b.c", "", now, "", ""); err == nil {
		t.Fatal("expected secret required error")
	}
	if _, err := VerifyHS256Token("abc", "secret", now, "", ""); err == nil {
		t.Fatal("expected invalid token format error")
	}

	badAlg := signHS256WithHeader(t, map[string]string{"alg": "HS512", "typ": "JWT"}, map[string]interface{}{
		"sub": "u1",
		"exp": now.Add(time.Minute).Unix(),
	}, "secret")
	if _, err := VerifyHS256Token(badAlg, "secret", now, "", ""); err == nil {
		t.Fatal("expected unsupported alg error")
	}

	badSig := signHS256WithHeader(t, map[string]string{"alg": "HS256", "typ": "JWT"}, map[string]interface{}{
		"sub": "u1",
		"exp": now.Add(time.Minute).Unix(),
	}, "secret-a")
	if _, err := VerifyHS256Token(badSig, "secret-b", now, "", ""); err == nil {
		t.Fatal("expected signature mismatch")
	}

	notActive := signHS256(t, map[string]interface{}{
		"sub": "u1",
		"exp": now.Add(2 * time.Minute).Unix(),
		"nbf": now.Add(time.Minute).Unix(),
	}, "secret")
	if _, err := VerifyHS256Token(notActive, "secret", now, "", ""); err == nil {
		t.Fatal("expected token not active error")
	}

	noSub := signHS256(t, map[string]interface{}{
		"exp": now.Add(time.Minute).Unix(),
	}, "secret")
	if _, err := VerifyHS256Token(noSub, "secret", now, "", ""); err == nil {
		t.Fatal("expected subject required error")
	}

	rolesAsString := signHS256(t, map[string]interface{}{
		"sub":   "u2",
		"roles": "Operator",
		"exp":   now.Add(time.Minute).Unix(),
	}, "secret")
	claims, err := VerifyHS256Token(rolesAsString, "secret", now, "", "")
	if err != nil {
		t.Fatalf("expected roles single-string fallback to pass, got %v", err)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "Operator" {
		t.Fatalf("expected single role fallback, got %+v", claims.Roles)
	}
}

func TestJWKSCacheAndRSAHelpersBranches(t *testing.T) {
	now := time.Now().UTC()

	c := newJWKSCache("https://example.com/jwks", 0)
	if c.timeout != 5*time.Second {
		t.Fatalf("expected default timeout 5s, got %v", c.timeout)
	}

	var nilCache *jwksCache
	if _, err := nilCache.key(context.Background(), "kid", now); err == nil {
		t.Fatal("expected nil cache error")
	}

	c = newJWKSCache("", time.Second)
	if _, err := c.key(context.Background(), "kid", now); err == nil {
		t.Fatal("expected jwks url required error")
	}

	cacheHit := newJWKSCache("https://example.com/jwks", time.Second)
	cacheHit.keys["k1"] = &rsa.PublicKey{N: big.NewInt(3), E: 3}
	cacheHit.expiresAt = now.Add(time.Minute)
	if _, err := cacheHit.key(context.Background(), "k1", now); err != nil {
		t.Fatalf("expected cache hit path, got %v", err)
	}

	cacheNoRefresh := newJWKSCache("https://example.com/jwks", time.Second)
	cacheNoRefresh.expiresAt = now.Add(time.Minute)
	if err := cacheNoRefresh.refresh(context.Background(), now); err != nil {
		t.Fatalf("expected refresh fast-path skip to succeed, got %v", err)
	}

	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv404.Close()
	cache404 := newJWKSCache(srv404.URL, time.Second)
	if err := cache404.refresh(context.Background(), now); err == nil {
		t.Fatal("expected refresh non-200 error")
	}

	srvBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{bad`))
	}))
	defer srvBadJSON.Close()
	cacheBadJSON := newJWKSCache(srvBadJSON.URL, time.Second)
	if err := cacheBadJSON.refresh(context.Background(), now); err == nil {
		t.Fatal("expected refresh decode error")
	}

	srvNoRSA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kid": "k1", "kty": "EC", "alg": "ES256", "n": "x", "e": "AQAB"},
			},
		})
	}))
	defer srvNoRSA.Close()
	cacheNoRSA := newJWKSCache(srvNoRSA.URL, time.Second)
	if err := cacheNoRSA.refresh(context.Background(), now); err == nil {
		t.Fatal("expected refresh no-valid-rsa-keys error")
	}

	if _, err := rsaFromJWK("bad%%%", "AQAB"); err == nil {
		t.Fatal("expected modulus decode error")
	}
	if _, err := rsaFromJWK("AQAB", "bad%%%"); err == nil {
		t.Fatal("expected exponent decode error")
	}
	if _, err := rsaFromJWK("AQAB", ""); err == nil {
		t.Fatal("expected empty exponent error")
	}
	if _, err := rsaFromJWK("AQAB", "AQ"); err == nil {
		t.Fatal("expected exponent<=1 error")
	}
}

func TestVerifyRS256AdditionalBranches(t *testing.T) {
	now := time.Now().UTC()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	jwks := jwksServerForKey(t, key, "kid-rs")
	defer jwks.Close()
	cache := newJWKSCache(jwks.URL, 2*time.Second)

	if _, err := VerifyRS256Token("bad", now, cache, "", ""); err == nil {
		t.Fatal("expected invalid token format error")
	}

	badAlgHeader := map[string]string{"alg": "HS256", "typ": "JWT", "kid": "kid-rs"}
	badAlgToken := signHS256WithHeader(t, badAlgHeader, map[string]interface{}{
		"sub": "u1",
		"exp": now.Add(time.Minute).Unix(),
	}, "secret")
	if _, err := VerifyRS256Token(badAlgToken, now, cache, "", ""); err == nil {
		t.Fatal("expected unsupported alg error")
	}

	noKidHeaderRaw, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payloadRaw, _ := json.Marshal(map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix()})
	noKid := base64.RawURLEncoding.EncodeToString(noKidHeaderRaw) + "." + base64.RawURLEncoding.EncodeToString(payloadRaw) + ".sig"
	if _, err := VerifyRS256Token(noKid, now, cache, "", ""); err == nil {
		t.Fatal("expected kid required error")
	}

	noSub := signRS256(t, map[string]any{"exp": now.Add(time.Minute).Unix()}, key, "kid-rs")
	if _, err := VerifyRS256Token(noSub, now, cache, "", ""); err == nil {
		t.Fatal("expected subject required error")
	}

	expired := signRS256(t, map[string]any{"sub": "u1", "exp": now.Add(-time.Minute).Unix()}, key, "kid-rs")
	if _, err := VerifyRS256Token(expired, now, cache, "", ""); err == nil {
		t.Fatal("expected token expired error")
	}

	notActive := signRS256(t, map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix(), "nbf": now.Add(30 * time.Second).Unix()}, key, "kid-rs")
	if _, err := VerifyRS256Token(notActive, now, cache, "", ""); err == nil {
		t.Fatal("expected token not active error")
	}

	issuerMismatch := signRS256(t, map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix(), "iss": "issuer-a"}, key, "kid-rs")
	if _, err := VerifyRS256Token(issuerMismatch, now, cache, "issuer-b", ""); err == nil {
		t.Fatal("expected issuer mismatch")
	}

	audienceMismatch := signRS256(t, map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix(), "aud": []string{"a", "b"}}, key, "kid-rs")
	if _, err := VerifyRS256Token(audienceMismatch, now, cache, "", "c"); err == nil {
		t.Fatal("expected audience mismatch")
	}

	wrongKid := signRS256(t, map[string]any{"sub": "u1", "exp": now.Add(time.Minute).Unix()}, key, "missing-kid")
	if _, err := VerifyRS256Token(wrongKid, now, cache, "", ""); err == nil || !strings.Contains(err.Error(), "kid not found") {
		t.Fatalf("expected kid-not-found path, got %v", err)
	}
}
