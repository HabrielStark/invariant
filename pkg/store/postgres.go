package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	pgxPoolNewWithConfig   = pgxpool.NewWithConfig
	postgresConnectRetries = 30
	postgresRetryDelay     = 2 * time.Second
	postgresPingTimeout    = 2 * time.Second
	postgresSleep          = time.Sleep
)

func NewPostgresPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dsn == "" {
		dsn = defaultPostgresURL()
	}
	if requiresSecureTransport("DATABASE_REQUIRE_TLS") {
		if err := validatePostgresTLS(dsn); err != nil {
			return nil, err
		}
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if v := strings.TrimSpace(os.Getenv("DB_TENANT_SCOPE")); v != "" {
		cfg.ConnConfig.RuntimeParams["app.current_tenant_scope"] = v
	}
	if v := strings.TrimSpace(os.Getenv("DB_TENANT_STATIC")); v != "" {
		cfg.ConnConfig.RuntimeParams["app.current_tenant"] = v
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = time.Minute * 5
	var lastErr error
	for i := 0; i < postgresConnectRetries; i++ {
		pool, err := pgxPoolNewWithConfig(ctx, cfg)
		if err != nil {
			lastErr = err
			postgresSleep(postgresRetryDelay)
			continue
		}
		ctxPing, cancel := context.WithTimeout(ctx, postgresPingTimeout)
		err = pool.Ping(ctxPing)
		cancel()
		if err == nil {
			return pool, nil
		}
		lastErr = err
		pool.Close()
		postgresSleep(postgresRetryDelay)
	}
	return nil, fmt.Errorf("db ping retries exhausted: %w", lastErr)
}

func defaultPostgresURL() string {
	user := strings.TrimSpace(os.Getenv("DATABASE_USER"))
	if user == "" {
		user = "axiom"
	}
	password := os.Getenv("POSTGRES_PASSWORD")
	host := strings.TrimSpace(os.Getenv("DATABASE_HOST"))
	if host == "" {
		host = "localhost"
	}
	port := strings.TrimSpace(os.Getenv("DATABASE_PORT"))
	if port == "" {
		port = "5432"
	}
	if _, err := strconv.Atoi(port); err != nil {
		port = "5432"
	}
	dbName := strings.TrimSpace(os.Getenv("DATABASE_NAME"))
	if dbName == "" {
		dbName = "axiom"
	}
	sslmode := strings.TrimSpace(os.Getenv("DATABASE_SSLMODE"))
	if sslmode == "" {
		sslmode = "disable"
	}
	uri := &url.URL{
		Scheme: "postgres",
		Host:   host + ":" + port,
		Path:   "/" + dbName,
	}
	if password != "" {
		uri.User = url.UserPassword(user, password)
	} else {
		uri.User = url.User(user)
	}
	q := uri.Query()
	q.Set("sslmode", sslmode)
	uri.RawQuery = q.Encode()
	return uri.String()
}

func validatePostgresTLS(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid DATABASE_URL: %w", err)
	}
	sslmode := strings.ToLower(strings.TrimSpace(parsed.Query().Get("sslmode")))
	switch sslmode {
	case "verify-full", "verify-ca", "require":
		return nil
	case "allow", "disable", "prefer":
		return fmt.Errorf("DATABASE_REQUIRE_TLS=true but DATABASE_URL sslmode=%q is insecure", sslmode)
	default:
		return fmt.Errorf("DATABASE_REQUIRE_TLS=true requires explicit sslmode=require|verify-ca|verify-full")
	}
}

func requiresSecureTransport(envKey string) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(envKey)))
	return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
}
