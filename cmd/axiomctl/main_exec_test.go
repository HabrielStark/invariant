package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestMainEntryPoint tests the full main() code path by calling run() with os-like args
func TestMainEntryPoint(t *testing.T) {
	t.Parallel()

	t.Run("no args exits with error", func(t *testing.T) {
		var out bytes.Buffer
		err := run([]string{}, &out)
		if err == nil {
			t.Fatal("expected error for no args")
		}
		if err.Error() != "command required" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("full gen-key workflow", func(t *testing.T) {
		dir := t.TempDir()
		privPath := filepath.Join(dir, "priv.key")
		pubPath := filepath.Join(dir, "pub.key")

		var out bytes.Buffer
		err := run([]string{"gen-key", "--out-private", privPath, "--out-public", pubPath}, &out)
		if err != nil {
			t.Fatalf("gen-key failed: %v", err)
		}

		priv, _ := os.ReadFile(privPath)
		pub, _ := os.ReadFile(pubPath)
		if len(priv) < 50 || len(pub) < 30 {
			t.Fatalf("keys too short: priv=%d pub=%d", len(priv), len(pub))
		}
	})

	t.Run("full hash-intent workflow", func(t *testing.T) {
		dir := t.TempDir()
		intentPath := filepath.Join(dir, "intent.json")
		_ = os.WriteFile(intentPath, []byte(`{"action":"deploy","target":"prod"}`), 0600)

		var out bytes.Buffer
		err := run([]string{"hash-intent", "--intent", intentPath, "--policy-version", "v1", "--nonce", "abc"}, &out)
		if err != nil {
			t.Fatalf("hash-intent failed: %v", err)
		}
		if len(out.String()) < 10 {
			t.Fatalf("expected hash output, got: %s", out.String())
		}
	})

	t.Run("full sign-cert workflow", func(t *testing.T) {
		dir := t.TempDir()
		privPath := filepath.Join(dir, "priv.key")
		pubPath := filepath.Join(dir, "pub.key")
		certPath := filepath.Join(dir, "cert.json")
		signedPath := filepath.Join(dir, "cert.signed.json")

		var genOut bytes.Buffer
		if err := run([]string{"gen-key", "--out-private", privPath, "--out-public", pubPath}, &genOut); err != nil {
			t.Fatalf("gen-key failed: %v", err)
		}

		_ = os.WriteFile(certPath, []byte(`{"kid":"k1","policy_set_id":"ps1","policy_version":"v1"}`), 0600)

		var signOut bytes.Buffer
		err := run([]string{"sign-cert", "--cert", certPath, "--private", privPath, "--out", signedPath}, &signOut)
		if err != nil {
			t.Fatalf("sign-cert failed: %v", err)
		}

		signed, err := os.ReadFile(signedPath)
		if err != nil || len(signed) < 50 {
			t.Fatalf("signed cert invalid: %v len=%d", err, len(signed))
		}
	})
}

// TestMainDirect tests the actual main() function by overriding osExit
func TestMainDirect(t *testing.T) {
	origExit := osExit
	origArgs := os.Args
	defer func() {
		osExit = origExit
		os.Args = origArgs
	}()

	t.Run("main success path", func(t *testing.T) {
		dir := t.TempDir()
		privPath := filepath.Join(dir, "priv.key")
		pubPath := filepath.Join(dir, "pub.key")

		exitCalled := false
		osExit = func(code int) { exitCalled = true }
		os.Args = []string{"axiomctl", "gen-key", "--out-private", privPath, "--out-public", pubPath}

		main()

		if exitCalled {
			t.Fatal("osExit should not be called on success")
		}
	})

	t.Run("main error path calls osExit", func(t *testing.T) {
		exitCalled := false
		exitCode := 0
		osExit = func(code int) {
			exitCalled = true
			exitCode = code
		}
		os.Args = []string{"axiomctl"} // no command

		// Capture log output
		main()

		if !exitCalled {
			t.Fatal("osExit should be called on error")
		}
		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}
	})
}

// TestUsage tests the usage function
func TestUsage(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	if out.Len() == 0 {
		t.Fatal("expected usage output")
	}
}

// TestRunErrors tests run() with various error conditions
func TestRunErrors(t *testing.T) {
	var out bytes.Buffer

	t.Run("unknown command", func(t *testing.T) {
		err := run([]string{"unknown-cmd"}, &out)
		if err == nil || err.Error() != "unknown command: unknown-cmd" {
			t.Fatalf("expected unknown command error, got %v", err)
		}
	})

	t.Run("no command", func(t *testing.T) {
		err := run([]string{}, &out)
		if err == nil || err.Error() != "command required" {
			t.Fatalf("expected command required error, got %v", err)
		}
	})
}

// Ensure errors import is used
var _ = errors.New
