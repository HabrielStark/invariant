package store

import (
	"context"
	"strings"
	"testing"
)

func TestLoadRedisTLSConfigFromEnv(t *testing.T) {
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_INSECURE", "true")
	t.Setenv("REDIS_ALLOW_INSECURE_TLS", "true")
	t.Setenv("REDIS_TLS_SERVER_NAME", "redis.internal")
	t.Setenv("REDIS_TLS_CA_CERT_FILE", "")
	t.Setenv("REDIS_TLS_CERT_FILE", "")
	t.Setenv("REDIS_TLS_KEY_FILE", "")

	cfg, err := loadRedisTLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected tls config error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected tls config")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected insecure skip verify to be set")
	}
	if cfg.ServerName != "redis.internal" {
		t.Fatalf("expected server name redis.internal, got %q", cfg.ServerName)
	}
}

func TestLoadRedisTLSConfigFromEnvInsecureGuard(t *testing.T) {
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_INSECURE", "true")
	t.Setenv("REDIS_ALLOW_INSECURE_TLS", "false")
	if _, err := loadRedisTLSConfigFromEnv(); err == nil {
		t.Fatal("expected insecure tls guard error")
	}
}

func TestLoadRedisTLSConfigFromEnvErrors(t *testing.T) {
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CERT_FILE", "/tmp/non-existent-cert.pem")
	t.Setenv("REDIS_TLS_KEY_FILE", "")
	if _, err := loadRedisTLSConfigFromEnv(); err == nil {
		t.Fatal("expected cert/key mismatch error")
	}

	t.Setenv("REDIS_TLS_CERT_FILE", "")
	t.Setenv("REDIS_TLS_KEY_FILE", "")
	t.Setenv("REDIS_TLS_CA_CERT_FILE", "/tmp/non-existent-ca.pem")
	if _, err := loadRedisTLSConfigFromEnv(); err == nil {
		t.Fatal("expected missing CA file error")
	}
}

func TestNewRedisRejectsInsecureWhenRequired(t *testing.T) {
	t.Setenv("REDIS_ADDR", "127.0.0.1:1")
	t.Setenv("REDIS_DB", "not-int")
	t.Setenv("REDIS_REQUIRE_TLS", "true")
	t.Setenv("REDIS_TLS", "false")
	client, err := NewRedis(context.Background())
	if err == nil {
		if client != nil {
			client.Close()
		}
		t.Fatal("expected tls requirement error")
	}
	if !strings.Contains(err.Error(), "REDIS_REQUIRE_TLS") {
		t.Fatalf("expected REDIS_REQUIRE_TLS error, got %v", err)
	}
}
