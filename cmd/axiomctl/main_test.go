package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axiom/pkg/models"
)

func TestRunCommandRouting(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := run(nil, &out); err == nil {
		t.Fatal("expected error when command is missing")
	}
	if !strings.Contains(out.String(), "axiomctl commands") {
		t.Fatalf("expected usage output, got %q", out.String())
	}

	out.Reset()
	if err := run([]string{"unknown"}, &out); err == nil {
		t.Fatal("expected error for unknown command")
	}
	if !strings.Contains(out.String(), "axiomctl commands") {
		t.Fatalf("expected usage output for unknown command, got %q", out.String())
	}
}

func TestRunKnownCommandSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, "run-private.key")
	publicPath := filepath.Join(dir, "run-public.key")
	var out bytes.Buffer
	err := run([]string{"gen-key", "--out-private", privatePath, "--out-public", publicPath}, &out)
	if err != nil {
		t.Fatalf("run gen-key failed: %v", err)
	}
	if _, err := os.Stat(privatePath); err != nil {
		t.Fatalf("expected private key file, got error: %v", err)
	}
	if _, err := os.Stat(publicPath); err != nil {
		t.Fatalf("expected public key file, got error: %v", err)
	}
}

func TestRunDispatchHashIntentAndSignCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	if err := os.WriteFile(intentPath, []byte(`{"intent_id":"i1","value":"10.00"}`), 0o600); err != nil {
		t.Fatalf("write intent: %v", err)
	}
	var out bytes.Buffer
	if err := run([]string{"hash-intent", "--intent", intentPath, "--policy-version", "v17", "--nonce", "n1"}, &out); err != nil {
		t.Fatalf("run hash-intent failed: %v", err)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Fatal("expected hash-intent output")
	}

	out.Reset()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	privatePath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	certPath := filepath.Join(dir, "cert.json")
	if err := os.WriteFile(certPath, []byte(`{"cert_id":"c1","intent_hash":"h","policy_set_id":"p","policy_version":"v17","nonce":"n1"}`), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	outPath := filepath.Join(dir, "signed.json")
	if err := run([]string{"sign-cert", "--cert", certPath, "--private", privatePath, "--out", outPath}, &out); err != nil {
		t.Fatalf("run sign-cert failed: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected signed cert output, got error: %v", err)
	}
}

func TestGenKeyWritesFilesAndOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")

	var out bytes.Buffer
	if err := genKey([]string{"--out-private", privatePath, "--out-public", publicPath}, &out); err != nil {
		t.Fatalf("genKey failed: %v", err)
	}
	privateRaw, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}
	publicRaw, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateRaw)))
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicRaw)))
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(privateBytes) != ed25519.PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(privateBytes))
	}
	if len(publicBytes) != ed25519.PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", ed25519.PublicKeySize, len(publicBytes))
	}
	if !strings.Contains(out.String(), "wrote") {
		t.Fatalf("expected output to contain write confirmation, got %q", out.String())
	}
}

func TestGenKeyParseError(t *testing.T) {
	t.Parallel()

	if err := genKey([]string{"--bad-flag"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected parse error for unknown flag")
	}

	var out bytes.Buffer
	err := genKey([]string{"--out-private", filepath.Join(t.TempDir(), "missing", "private.key"), "--out-public", filepath.Join(t.TempDir(), "public.key")}, &out)
	if err == nil {
		t.Fatal("expected write error for missing output directory")
	}
}

func TestHashIntentSuccessAndValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	intent := []byte(`{"intent_id":"i1","value":"123.45"}`)
	if err := os.WriteFile(intentPath, intent, 0o600); err != nil {
		t.Fatalf("write intent: %v", err)
	}

	var out bytes.Buffer
	if err := hashIntent([]string{"--intent", intentPath, "--policy-version", "v17", "--nonce", "n1"}, &out); err != nil {
		t.Fatalf("hashIntent failed: %v", err)
	}
	hash := strings.TrimSpace(out.String())
	if hash == "" {
		t.Fatal("expected non-empty hash output")
	}

	if err := hashIntent([]string{"--intent", intentPath, "--policy-version", "v17"}, &out); err == nil {
		t.Fatal("expected error when nonce is missing")
	}
}

func TestHashIntentErrorPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	var out bytes.Buffer

	if err := hashIntent([]string{"--intent", filepath.Join(dir, "missing.json"), "--policy-version", "v17", "--nonce", "n1"}, &out); err == nil {
		t.Fatal("expected read error for missing intent")
	}

	intWithNumber := filepath.Join(dir, "intent-number.json")
	if err := os.WriteFile(intWithNumber, []byte(`{"value":123.45}`), 0o600); err != nil {
		t.Fatalf("write numeric intent: %v", err)
	}
	if err := hashIntent([]string{"--intent", intWithNumber, "--policy-version", "v17", "--nonce", "n1"}, &out); err == nil {
		t.Fatal("expected validation error for JSON number")
	}

	invalidJSON := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalidJSON, []byte(`{"value":`), 0o600); err != nil {
		t.Fatalf("write invalid json intent: %v", err)
	}
	if err := hashIntent([]string{"--intent", invalidJSON, "--policy-version", "v17", "--nonce", "n1"}, &out); err == nil {
		t.Fatal("expected canonicalization error for invalid intent JSON")
	}
}

func TestSignCertSuccessAndErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	privatePath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	cert := models.ActionCert{
		CertID:        "cert-1",
		IntentHash:    "intent-hash",
		PolicySetID:   "finance",
		PolicyVersion: "v17",
		Nonce:         "nonce-1",
	}
	certPath := filepath.Join(dir, "cert.json")
	encoded, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal cert: %v", err)
	}
	if err := os.WriteFile(certPath, encoded, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	outPath := filepath.Join(dir, "cert.signed.json")
	var out bytes.Buffer
	if err := signCert([]string{"--cert", certPath, "--private", privatePath, "--out", outPath}, &out); err != nil {
		t.Fatalf("signCert failed: %v", err)
	}
	signedRaw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read signed cert: %v", err)
	}
	var signed models.ActionCert
	if err := json.Unmarshal(signedRaw, &signed); err != nil {
		t.Fatalf("decode signed cert: %v", err)
	}
	if signed.ExpiresAt == "" {
		t.Fatal("expected signCert to set ExpiresAt when missing")
	}
	if signed.Signature.Alg != "ed25519" {
		t.Fatalf("expected ed25519 alg, got %q", signed.Signature.Alg)
	}
	if signed.Signature.Sig == "" {
		t.Fatal("expected non-empty signature")
	}

	shortKeyPath := filepath.Join(dir, "short.key")
	if err := os.WriteFile(shortKeyPath, []byte(base64.StdEncoding.EncodeToString([]byte("short"))), 0o600); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	if err := signCert([]string{"--cert", certPath, "--private", shortKeyPath, "--out", filepath.Join(dir, "bad.json")}, &out); err == nil {
		t.Fatal("expected error for invalid private key size")
	}
}

func TestSignCertErrorPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	var out bytes.Buffer

	if err := signCert([]string{}, &out); err == nil {
		t.Fatal("expected error when cert/private flags are missing")
	}

	certPath := filepath.Join(dir, "cert-invalid.json")
	if err := os.WriteFile(certPath, []byte(`{"cert_id":`), 0o600); err != nil {
		t.Fatalf("write invalid cert: %v", err)
	}
	privatePath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(privatePath, []byte("not-base64"), 0o600); err != nil {
		t.Fatalf("write invalid private key: %v", err)
	}
	if err := signCert([]string{"--cert", certPath, "--private", privatePath, "--out", filepath.Join(dir, "out.json")}, &out); err == nil {
		t.Fatal("expected decode cert error")
	}

	validCertPath := filepath.Join(dir, "cert.json")
	if err := os.WriteFile(validCertPath, []byte(`{"cert_id":"c1"}`), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := signCert([]string{"--cert", validCertPath, "--private", privatePath, "--out", filepath.Join(dir, "out2.json")}, &out); err == nil {
		t.Fatal("expected base64 decode private key error")
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	validPrivatePath := filepath.Join(dir, "valid-private.key")
	if err := os.WriteFile(validPrivatePath, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := signCert([]string{"--cert", validCertPath, "--private", validPrivatePath, "--out", filepath.Join(dir, "missing", "out.json")}, &out); err == nil {
		t.Fatal("expected write signed cert error for missing output directory")
	}
}
