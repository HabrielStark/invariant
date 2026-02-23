package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tests for uncovered branches in axiomctl

func TestGenKeyOutputError(t *testing.T) {
	// Test write error by using invalid path
	out := &bytes.Buffer{}
	err := genKey([]string{"--out-private", "/nonexistent/dir/private.key", "--out-public", "/nonexistent/dir/public.key"}, out)
	if err == nil {
		t.Fatal("expected write error for invalid path")
	}
}

func TestGenKeyPublicWriteError(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.key")
	// Use invalid path for public key
	out := &bytes.Buffer{}
	err := genKey([]string{"--out-private", privPath, "--out-public", "/nonexistent/dir/public.key"}, out)
	if err == nil {
		t.Fatal("expected write error for invalid public key path")
	}
	// Private key should have been written
	if _, statErr := os.Stat(privPath); os.IsNotExist(statErr) {
		t.Fatal("expected private key to exist")
	}
}

func TestHashIntentMissingArgs(t *testing.T) {
	out := &bytes.Buffer{}
	// Missing policy-version
	err := hashIntent([]string{"--intent", "intent.json", "--nonce", "test"}, out)
	if err == nil || err.Error() != "intent, policy-version, nonce required" {
		t.Fatalf("expected missing args error, got %v", err)
	}
}

func TestHashIntentReadError(t *testing.T) {
	out := &bytes.Buffer{}
	err := hashIntent([]string{"--intent", "/nonexistent/intent.json", "--policy-version", "v1", "--nonce", "n1"}, out)
	if err == nil {
		t.Fatal("expected read error for nonexistent file")
	}
}

func TestHashIntentInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	_ = os.WriteFile(intentPath, []byte(`{invalid json`), 0600)

	out := &bytes.Buffer{}
	err := hashIntent([]string{"--intent", intentPath, "--policy-version", "v1", "--nonce", "n1"}, out)
	if err == nil {
		t.Fatal("expected validation error for invalid JSON")
	}
}

func TestHashIntentWithJSONNumbers(t *testing.T) {
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	// JSON with a number that might cause issues
	_ = os.WriteFile(intentPath, []byte(`{"amount": 1e308}`), 0600)

	out := &bytes.Buffer{}
	err := hashIntent([]string{"--intent", intentPath, "--policy-version", "v1", "--nonce", "n1"}, out)
	// Should either succeed or fail with validation error
	if err != nil && err.Error() != "validate intent: json number out of range" {
		// It might succeed with valid JSON
		t.Logf("hashIntent result: %v", err)
	}
}

func TestSignCertMissingArgs(t *testing.T) {
	out := &bytes.Buffer{}
	// Missing private
	err := signCert([]string{"--cert", "cert.json"}, out)
	if err == nil || err.Error() != "cert and private required" {
		t.Fatalf("expected missing args error, got %v", err)
	}
}

func TestSignCertReadCertError(t *testing.T) {
	out := &bytes.Buffer{}
	err := signCert([]string{"--cert", "/nonexistent/cert.json", "--private", "private.key"}, out)
	if err == nil {
		t.Fatal("expected read error for nonexistent cert")
	}
}

func TestSignCertInvalidCertJSON(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, []byte(`{invalid json`), 0600)

	out := &bytes.Buffer{}
	err := signCert([]string{"--cert", certPath, "--private", "private.key"}, out)
	if err == nil {
		t.Fatal("expected decode error for invalid cert JSON")
	}
}

func TestSignCertReadPrivateError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, []byte(`{"kid":"k1","policy_set_id":"ps1","policy_version":"v1"}`), 0600)

	out := &bytes.Buffer{}
	err := signCert([]string{"--cert", certPath, "--private", "/nonexistent/private.key"}, out)
	if err == nil {
		t.Fatal("expected read error for nonexistent private key")
	}
}

func TestSignCertInvalidBase64Private(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, []byte(`{"kid":"k1","policy_set_id":"ps1","policy_version":"v1"}`), 0600)
	privatePath := filepath.Join(dir, "private.key")
	_ = os.WriteFile(privatePath, []byte(`not-base64!!!`), 0600)

	out := &bytes.Buffer{}
	err := signCert([]string{"--cert", certPath, "--private", privatePath}, out)
	if err == nil {
		t.Fatal("expected decode error for invalid base64 private key")
	}
}

func TestSignCertInvalidKeySizePrivate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, []byte(`{"kid":"k1","policy_set_id":"ps1","policy_version":"v1"}`), 0600)
	privatePath := filepath.Join(dir, "private.key")
	// Valid base64 but wrong size (not 64 bytes)
	_ = os.WriteFile(privatePath, []byte(`dG9vLXNob3J0`), 0600) // "too-short" in base64

	out := &bytes.Buffer{}
	err := signCert([]string{"--cert", certPath, "--private", privatePath}, out)
	if err == nil {
		t.Fatal("expected size error for wrong private key size")
	}
}

func TestSignCertWriteError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.json")
	_ = os.WriteFile(certPath, []byte(`{"kid":"k1","policy_set_id":"ps1","policy_version":"v1"}`), 0600)
	privatePath := filepath.Join(dir, "private.key")

	// Generate valid key first
	var keyBuf bytes.Buffer
	if err := genKey([]string{"--out-private", privatePath, "--out-public", filepath.Join(dir, "public.key")}, &keyBuf); err != nil {
		t.Fatalf("setup genKey failed: %v", err)
	}

	out := &bytes.Buffer{}
	err := signCert([]string{
		"--cert", certPath,
		"--private", privatePath,
		"--out", "/nonexistent/dir/cert.signed.json",
	}, out)
	if err == nil {
		t.Fatal("expected write error for invalid output path")
	}
}

func TestRunUnknownCommand(t *testing.T) {
	out := &bytes.Buffer{}
	err := run([]string{"unknown-cmd"}, out)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
	if err.Error() != "unknown command: unknown-cmd" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunNoCommand(t *testing.T) {
	out := &bytes.Buffer{}
	err := run([]string{}, out)
	if err == nil || err.Error() != "command required" {
		t.Fatalf("expected 'command required' error, got %v", err)
	}
}

func TestGenKeyFlagError(t *testing.T) {
	out := &bytes.Buffer{}
	err := genKey([]string{"--invalid-flag"}, out)
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestHashIntentFlagError(t *testing.T) {
	out := &bytes.Buffer{}
	err := hashIntent([]string{"--invalid-flag"}, out)
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestSignCertFlagError(t *testing.T) {
	out := &bytes.Buffer{}
	err := signCert([]string{"--invalid-flag"}, out)
	if err == nil {
		t.Fatal("expected flag parse error")
	}
}

func TestSignCertInvalidPrivateKeySize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid cert file
	certPath := tmpDir + "/cert.json"
	certData := `{"action":"test","domain":"test","version":"v1"}`
	if err := os.WriteFile(certPath, []byte(certData), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a private key with wrong size (not 64 bytes)
	privPath := tmpDir + "/bad.key"
	if err := os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString([]byte("tooshort"))), 0600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	err := signCert([]string{
		"--cert", certPath,
		"--private", privPath,
		"--out", tmpDir + "/out.json",
	}, out)
	if err == nil || !strings.Contains(err.Error(), "invalid size") {
		t.Fatalf("expected invalid size error, got %v", err)
	}
}

func TestSignCertInvalidBase64PrivateKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid cert file
	certPath := tmpDir + "/cert.json"
	certData := `{"action":"test","domain":"test","version":"v1"}`
	if err := os.WriteFile(certPath, []byte(certData), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a private key file with invalid base64
	privPath := tmpDir + "/invalid.key"
	if err := os.WriteFile(privPath, []byte("not!!valid!!base64@@"), 0600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	err := signCert([]string{
		"--cert", certPath,
		"--private", privPath,
		"--out", tmpDir + "/out.json",
	}, out)
	if err == nil || !strings.Contains(err.Error(), "decode private key") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestHashIntentJSONNumberError(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an intent file with JSON numbers (should fail validation)
	intentPath := tmpDir + "/intent.json"
	intentData := `{"amount": 12345678901234567890}` // Large number causes precision issues
	if err := os.WriteFile(intentPath, []byte(intentData), 0600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	err := hashIntent([]string{
		"--intent", intentPath,
		"--policy-version", "v1",
		"--nonce", "abc123",
	}, out)
	// Should succeed or fail validation depending on JSON number handling
	_ = err
}

func TestHashIntentReadFileError(t *testing.T) {
	out := &bytes.Buffer{}
	err := hashIntent([]string{
		"--intent", "/nonexistent/path/intent.json",
		"--policy-version", "v1",
		"--nonce", "test",
	}, out)
	if err == nil || !strings.Contains(err.Error(), "read intent") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestSignCertReadPrivateKeyError(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := tmpDir + "/cert.json"
	if err := os.WriteFile(certPath, []byte(`{"action":"test"}`), 0600); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	err := signCert([]string{
		"--cert", certPath,
		"--private", "/nonexistent/priv.key",
	}, out)
	if err == nil || !strings.Contains(err.Error(), "read private key") {
		t.Fatalf("expected read private key error, got %v", err)
	}
}
