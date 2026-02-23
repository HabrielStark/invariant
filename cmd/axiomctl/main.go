package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"axiom/pkg/auth"
	"axiom/pkg/models"
)

// Testable variables for main()
var osExit = os.Exit

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Print(err)
		osExit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		usage(out)
		return errors.New("command required")
	}
	switch args[0] {
	case "gen-key":
		return genKey(args[1:], out)
	case "hash-intent":
		return hashIntent(args[1:], out)
	case "sign-cert":
		return signCert(args[1:], out)
	default:
		usage(out)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "axiomctl commands:")
	fmt.Fprintln(out, "  gen-key --out-private private.key --out-public public.key")
	fmt.Fprintln(out, "  hash-intent --intent intent.json --policy-version v17 --nonce <uuid>")
	fmt.Fprintln(out, "  sign-cert --cert cert.json --private private.key --out cert.signed.json")
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func genKey(args []string, out io.Writer) error {
	fs := newFlagSet("gen-key")
	outPriv := fs.String("out-private", "private.key", "private key output")
	outPub := fs.String("out-public", "public.key", "public key output")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	if err := os.WriteFile(*outPriv, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(*outPub, []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	fmt.Fprintf(out, "wrote %s and %s\n", *outPriv, *outPub)
	return nil
}

func hashIntent(args []string, out io.Writer) error {
	fs := newFlagSet("hash-intent")
	intentPath := fs.String("intent", "", "intent file")
	policyVersion := fs.String("policy-version", "", "policy version")
	nonce := fs.String("nonce", "", "nonce")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *intentPath == "" || *policyVersion == "" || *nonce == "" {
		return errors.New("intent, policy-version, nonce required")
	}
	raw, err := os.ReadFile(*intentPath)
	if err != nil {
		return fmt.Errorf("read intent: %w", err)
	}
	if err := models.ValidateNoJSONNumbers(raw); err != nil {
		return fmt.Errorf("validate intent: %w", err)
	}
	canon, err := models.CanonicalizeJSON(raw)
	if err != nil {
		return fmt.Errorf("canonicalize intent: %w", err)
	}
	fmt.Fprintln(out, models.IntentHash(canon, *policyVersion, *nonce))
	return nil
}

func signCert(args []string, out io.Writer) error {
	fs := newFlagSet("sign-cert")
	certPath := fs.String("cert", "", "cert json path")
	privatePath := fs.String("private", "", "base64 private key path")
	outPath := fs.String("out", "cert.signed.json", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" || *privatePath == "" {
		return errors.New("cert and private required")
	}
	certRaw, err := os.ReadFile(*certPath)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}
	var cert models.ActionCert
	if err := json.Unmarshal(certRaw, &cert); err != nil {
		return fmt.Errorf("decode cert: %w", err)
	}
	if cert.ExpiresAt == "" {
		cert.ExpiresAt = time.Now().UTC().Add(120 * time.Second).Format(time.RFC3339)
	}
	pkRaw, err := os.ReadFile(*privatePath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(string(pkRaw))
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("decode private key: invalid size %d", len(privBytes))
	}
	payload, err := auth.SignaturePayload(cert)
	if err != nil {
		return fmt.Errorf("signature payload: %w", err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), payload)
	cert.Signature.Alg = "ed25519"
	cert.Signature.Sig = base64.StdEncoding.EncodeToString(sig)

	encoded, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed cert: %w", err)
	}
	if err := os.WriteFile(*outPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write signed cert: %w", err)
	}
	fmt.Fprintf(out, "wrote %s\n", *outPath)
	return nil
}
