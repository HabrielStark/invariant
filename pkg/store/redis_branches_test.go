package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRedisTLSConfigInvalidCAPEM(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(ca, []byte("not-a-certificate"), 0o600); err != nil {
		t.Fatalf("write bad ca: %v", err)
	}
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_CERT_FILE", ca)
	t.Setenv("REDIS_TLS_CERT_FILE", "")
	t.Setenv("REDIS_TLS_KEY_FILE", "")

	if _, err := loadRedisTLSConfigFromEnv(); err == nil {
		t.Fatal("expected invalid ca pem error")
	}
}

func TestLoadRedisTLSConfigBadKeyPair(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte("bad-cert"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	if err := os.WriteFile(key, []byte("bad-key"), 0o600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_CERT_FILE", "")
	t.Setenv("REDIS_TLS_CERT_FILE", cert)
	t.Setenv("REDIS_TLS_KEY_FILE", key)

	if _, err := loadRedisTLSConfigFromEnv(); err == nil {
		t.Fatal("expected invalid mTLS keypair error")
	}
}

func TestNewRedisPingFailure(t *testing.T) {
	t.Setenv("REDIS_ADDR", "127.0.0.1:1")
	t.Setenv("REDIS_DB", "1")
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_TLS", "false")
	t.Setenv("REDIS_REQUIRE_TLS", "false")

	client, err := NewRedis(context.Background())
	if err == nil {
		if client != nil {
			_ = client.Close()
		}
		t.Fatal("expected ping failure for closed port")
	}
}
