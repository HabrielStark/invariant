package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

func NewRedis(ctx context.Context) (*redis.Client, error) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	password := os.Getenv("REDIS_PASSWORD")
	db := 0
	if raw := os.Getenv("REDIS_DB"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			db = parsed
		}
	}
	tlsConfig, err := loadRedisTLSConfigFromEnv()
	if err != nil {
		return nil, err
	}
	if requiresSecureTransport("REDIS_REQUIRE_TLS") && tlsConfig == nil {
		return nil, fmt.Errorf("REDIS_REQUIRE_TLS=true but REDIS_TLS is not enabled")
	}
	client := redis.NewClient(&redis.Options{
		Addr:      addr,
		Password:  password,
		DB:        db,
		TLSConfig: tlsConfig,
	})
	ctxPing, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	if err := client.Ping(ctxPing).Err(); err != nil {
		return nil, err
	}
	return client, nil
}

func loadRedisTLSConfigFromEnv() (*tls.Config, error) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("REDIS_TLS")), "true") {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("REDIS_TLS_INSECURE")), "true") {
		if !strings.EqualFold(strings.TrimSpace(os.Getenv("REDIS_ALLOW_INSECURE_TLS")), "true") {
			return nil, fmt.Errorf("REDIS_TLS_INSECURE=true requires REDIS_ALLOW_INSECURE_TLS=true")
		}
		cfg.InsecureSkipVerify = true
	}
	if serverName := strings.TrimSpace(os.Getenv("REDIS_TLS_SERVER_NAME")); serverName != "" {
		cfg.ServerName = serverName
	}
	if caFile := strings.TrimSpace(os.Getenv("REDIS_TLS_CA_CERT_FILE")); caFile != "" {
		caBytes, err := os.ReadFile(filepath.Clean(caFile))
		if err != nil {
			return nil, fmt.Errorf("read REDIS_TLS_CA_CERT_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("parse REDIS_TLS_CA_CERT_FILE: no valid certificates")
		}
		cfg.RootCAs = pool
	}
	certFile := strings.TrimSpace(os.Getenv("REDIS_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("REDIS_TLS_KEY_FILE"))
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("both REDIS_TLS_CERT_FILE and REDIS_TLS_KEY_FILE must be set")
		}
		cert, err := tls.LoadX509KeyPair(filepath.Clean(certFile), filepath.Clean(keyFile))
		if err != nil {
			return nil, fmt.Errorf("load redis mTLS keypair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
