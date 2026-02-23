package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadRedisTLSConfigFromEnvDisabled(t *testing.T) {
	t.Setenv("REDIS_TLS", "false")
	cfg, err := loadRedisTLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil TLS config when REDIS_TLS is false")
	}
}

func TestLoadRedisTLSConfigFromEnvServerName(t *testing.T) {
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_SERVER_NAME", "redis.internal")
	cfg, err := loadRedisTLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.ServerName != "redis.internal" {
		t.Fatalf("expected server name redis.internal, got %q", cfg.ServerName)
	}
}

func TestLoadRedisTLSConfigFromEnvCAAndMTLS(t *testing.T) {
	tmp := t.TempDir()
	certPEM, keyPEM := mustCreateSelfSignedPEM(t)
	caPath := filepath.Join(tmp, "ca.pem")
	certPath := filepath.Join(tmp, "client.pem")
	keyPath := filepath.Join(tmp, "client-key.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CA_CERT_FILE", caPath)
	t.Setenv("REDIS_TLS_CERT_FILE", certPath)
	t.Setenv("REDIS_TLS_KEY_FILE", keyPath)
	cfg, err := loadRedisTLSConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected TLS config")
	}
	if cfg.RootCAs == nil {
		t.Fatal("expected RootCAs to be populated")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(cfg.Certificates))
	}
}

func TestLoadRedisTLSConfigFromEnvIncompleteMTLS(t *testing.T) {
	t.Setenv("REDIS_TLS", "true")
	t.Setenv("REDIS_TLS_CERT_FILE", "/tmp/client.pem")
	_, err := loadRedisTLSConfigFromEnv()
	if err == nil {
		t.Fatal("expected error for incomplete mTLS configuration")
	}
}

func mustCreateSelfSignedPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "redis-test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return cert, priv
}
