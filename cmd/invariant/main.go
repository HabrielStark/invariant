package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		usage(out)
		return errors.New("command required")
	}
	switch args[0] {
	case "openclaw":
		return runOpenClaw(args[1:], out)
	case "escrow":
		return runEscrow(args[1:], out)
	default:
		usage(out)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "invariant commands:")
	fmt.Fprintln(out, "  invariant openclaw keys init [--dir .invariant/openclaw/dev_keys] [--kid openclaw-dev-kid]")
	fmt.Fprintln(out, "  invariant escrow list [--base http://localhost:8080] [--status PENDING] [--limit 50]")
	fmt.Fprintln(out, "  invariant escrow approve <id> [--approver manager-1] [--base http://localhost:8080]")
	fmt.Fprintln(out, "  invariant escrow execute <id> [--base http://localhost:8080]")
}

func runOpenClaw(args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New("openclaw subcommand required")
	}
	if args[0] != "keys" {
		return fmt.Errorf("unknown openclaw subcommand: %s", args[0])
	}
	if len(args) < 2 || args[1] != "init" {
		return errors.New("usage: invariant openclaw keys init [--dir ...] [--kid ...]")
	}
	fs := flag.NewFlagSet("openclaw keys init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", ".invariant/openclaw/dev_keys", "output directory")
	kid := fs.String("kid", "openclaw-dev-kid", "signer kid")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	return writeKeypair(*dir, *kid, out)
}

func writeKeypair(dir, kid string, out io.Writer) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("dir required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateB64 := base64.StdEncoding.EncodeToString(priv)
	publicB64 := base64.StdEncoding.EncodeToString(pub)
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	kidPath := filepath.Join(dir, "kid.txt")
	if err := os.WriteFile(privatePath, []byte(privateB64+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(publicPath, []byte(publicB64+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(kidPath, []byte(strings.TrimSpace(kid)+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s\n", privatePath)
	fmt.Fprintf(out, "wrote %s\n", publicPath)
	fmt.Fprintf(out, "wrote %s\n", kidPath)
	fmt.Fprintf(out, "export OPENCLAW_SIGNER_PRIVATE_KEY_B64=%s\n", privateB64)
	fmt.Fprintf(out, "export OPENCLAW_SIGNER_KID=%s\n", strings.TrimSpace(kid))
	return nil
}

func runEscrow(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("escrow subcommand required")
	}
	switch args[0] {
	case "list":
		return escrowList(args[1:], out)
	case "approve":
		return escrowApprove(args[1:], out)
	case "execute":
		return escrowExecute(args[1:], out)
	default:
		return fmt.Errorf("unknown escrow subcommand: %s", args[0])
	}
}

func escrowList(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("escrow list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	base := fs.String("base", env("INVARIANT_BASE_URL", "http://localhost:8080"), "gateway base url")
	status := fs.String("status", "", "status filter")
	limit := fs.Int("limit", 50, "page size")
	if err := fs.Parse(args); err != nil {
		return err
	}
	url := strings.TrimRight(*base, "/") + "/v1/escrows?limit=" + fmt.Sprintf("%d", *limit)
	if strings.TrimSpace(*status) != "" {
		url += "&status=" + strings.TrimSpace(*status)
	}
	body, err := requestJSON(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	pretty, _ := prettyJSON(body)
	_, _ = out.Write(pretty)
	_, _ = out.Write([]byte("\n"))
	return nil
}

func escrowApprove(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: invariant escrow approve <id> [--approver x] [--base y]")
	}
	escrowID := strings.TrimSpace(args[0])
	fs := flag.NewFlagSet("escrow approve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	approver := fs.String("approver", env("INVARIANT_ESCROW_APPROVER", "manager-1"), "approver id")
	base := fs.String("base", env("INVARIANT_BASE_URL", "http://localhost:8080"), "gateway base url")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	payload := map[string]string{"escrow_id": escrowID, "approver": *approver}
	body, _ := json.Marshal(payload)
	resp, err := requestJSON(http.MethodPost, strings.TrimRight(*base, "/")+"/v1/escrow/approve", body)
	if err != nil {
		return err
	}
	pretty, _ := prettyJSON(resp)
	_, _ = out.Write(pretty)
	_, _ = out.Write([]byte("\n"))
	return nil
}

func escrowExecute(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: invariant escrow execute <id> [--base y]")
	}
	escrowID := strings.TrimSpace(args[0])
	fs := flag.NewFlagSet("escrow execute", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	base := fs.String("base", env("INVARIANT_BASE_URL", "http://localhost:8080"), "gateway base url")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	payload := map[string]string{"escrow_id": escrowID}
	body, _ := json.Marshal(payload)
	resp, err := requestJSON(http.MethodPost, strings.TrimRight(*base, "/")+"/v1/escrow/execute", body)
	if err != nil {
		return err
	}
	pretty, _ := prettyJSON(resp)
	_, _ = out.Write(pretty)
	_, _ = out.Write([]byte("\n"))
	return nil
}

func requestJSON(method, url string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	authToken := strings.TrimSpace(os.Getenv("INVARIANT_AUTH_TOKEN"))
	authHeader := strings.TrimSpace(env("INVARIANT_AUTH_HEADER", "Authorization"))
	if authToken != "" {
		if strings.EqualFold(authHeader, "authorization") && !strings.HasPrefix(strings.ToLower(authToken), "bearer ") {
			req.Header.Set(authHeader, "Bearer "+authToken)
		} else {
			req.Header.Set(authHeader, authToken)
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func prettyJSON(raw []byte) ([]byte, error) {
	var obj interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw, nil
	}
	return json.MarshalIndent(obj, "", "  ")
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
