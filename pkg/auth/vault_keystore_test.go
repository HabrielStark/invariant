package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVaultTransitKeyStoreGetKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/v1/transit/keys/") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"latest_version": 2,
				"keys": map[string]any{
					"1": map[string]any{"public_key": "ed25519:" + pubB64},
					"2": map[string]any{"public_key": pubB64},
				},
			},
		})
	}))
	defer srv.Close()

	ks := VaultTransitKeyStore{
		Client:  srv.Client(),
		Addr:    srv.URL,
		Token:   "vault-token",
		Transit: "transit",
		Timeout: time.Second,
	}
	rec, err := ks.GetKey(context.Background(), "kid-1")
	if err != nil {
		t.Fatalf("GetKey error: %v", err)
	}
	if rec.Kid != "kid-1" || rec.Status != "active" {
		t.Fatalf("unexpected key record: %+v", rec)
	}
	if string(rec.PublicKey) != string(pub) {
		t.Fatal("public key mismatch")
	}
}

func TestVaultTransitKeyStoreGetKeyNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	ks := VaultTransitKeyStore{
		Client:  srv.Client(),
		Addr:    srv.URL,
		Token:   "vault-token",
		Transit: "transit",
		Timeout: time.Second,
	}
	if _, err := ks.GetKey(context.Background(), "kid-404"); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestVaultTransitKeyStoreGetKeyBadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"latest_version":1,"keys":{"1":{"public_key":"%%%"}}}}`))
	}))
	defer srv.Close()
	ks := VaultTransitKeyStore{
		Client:  srv.Client(),
		Addr:    srv.URL,
		Token:   "vault-token",
		Transit: "transit",
		Timeout: time.Second,
	}
	if _, err := ks.GetKey(context.Background(), "kid-1"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestParseVaultTransitPublicKeyErrors(t *testing.T) {
	if _, err := parseVaultTransitPublicKey([]byte(`{bad`)); err == nil {
		t.Fatal("expected unmarshal error")
	}
	if _, err := parseVaultTransitPublicKey([]byte(`{"data":{"keys":{}}}`)); err == nil {
		t.Fatal("expected missing keys error")
	}
	if _, err := parseVaultTransitPublicKey([]byte(`{"data":{"latest_version":2,"keys":{"1":{"public_key":"abc"}}}}`)); err == nil {
		t.Fatal("expected missing latest key error")
	}
}
