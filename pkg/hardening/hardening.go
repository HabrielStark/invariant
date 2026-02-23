package hardening

import (
	"fmt"
	"strings"
)

type EnvRequirement struct {
	Name  string
	Value string
}

type Options struct {
	Service                string
	Environment            string
	StrictProdSecurity     string
	DatabaseRequireTLS     string
	RedisAddr              string
	RedisRequireTLS        string
	RedisTLSInsecure       string
	RedisAllowInsecureTLS  string
	CORSAllowedOrigins     string
	RequiredServiceSecrets []EnvRequirement
}

func ValidateProduction(o Options) error {
	if !isProductionLikeEnv(o.Environment) {
		return nil
	}
	if !isTrue(o.StrictProdSecurity, true) {
		return nil
	}
	service := strings.TrimSpace(o.Service)
	if service == "" {
		service = "service"
	}
	if !isTrue(o.DatabaseRequireTLS, false) {
		return fmt.Errorf("%s: strict production hardening requires DATABASE_REQUIRE_TLS=true", service)
	}
	if strings.TrimSpace(o.RedisAddr) != "" {
		if !isTrue(o.RedisRequireTLS, false) {
			return fmt.Errorf("%s: strict production hardening requires REDIS_REQUIRE_TLS=true", service)
		}
		if isTrue(o.RedisTLSInsecure, false) || isTrue(o.RedisAllowInsecureTLS, false) {
			return fmt.Errorf("%s: strict production hardening forbids REDIS_TLS_INSECURE/REDIS_ALLOW_INSECURE_TLS", service)
		}
	}
	if err := validateCORSOrigins(o.CORSAllowedOrigins, service); err != nil {
		return err
	}
	for _, req := range o.RequiredServiceSecrets {
		if strings.TrimSpace(req.Name) == "" {
			continue
		}
		if strings.TrimSpace(req.Value) == "" {
			return fmt.Errorf("%s: strict production hardening requires %s", service, req.Name)
		}
	}
	return nil
}

func validateCORSOrigins(raw, service string) error {
	origins := strings.Split(raw, ",")
	if len(origins) == 0 {
		return fmt.Errorf("%s: strict production hardening requires explicit CORS_ALLOWED_ORIGINS", service)
	}
	validCount := 0
	for _, origin := range origins {
		o := strings.TrimSpace(origin)
		if o == "" {
			continue
		}
		validCount++
		lower := strings.ToLower(o)
		if lower == "*" {
			return fmt.Errorf("%s: strict production hardening forbids CORS wildcard origin", service)
		}
		if strings.HasPrefix(lower, "http://localhost") || strings.HasPrefix(lower, "https://localhost") || strings.HasPrefix(lower, "http://127.0.0.1") || strings.HasPrefix(lower, "https://127.0.0.1") {
			return fmt.Errorf("%s: strict production hardening forbids localhost CORS origin %q", service, o)
		}
		if !strings.HasPrefix(lower, "https://") {
			return fmt.Errorf("%s: strict production hardening requires HTTPS CORS origin, got %q", service, o)
		}
	}
	if validCount == 0 {
		return fmt.Errorf("%s: strict production hardening requires explicit CORS_ALLOWED_ORIGINS", service)
	}
	return nil
}

func isTrue(raw string, def bool) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return def
	}
	return strings.EqualFold(trimmed, "true")
}

func isProductionLikeEnv(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "prod", "production", "staging", "stage":
		return true
	default:
		return false
	}
}
