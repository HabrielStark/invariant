package hardening

import "testing"

func TestValidateProduction(t *testing.T) {
	base := Options{
		Service:                "gateway",
		Environment:            "production",
		StrictProdSecurity:     "true",
		DatabaseRequireTLS:     "true",
		RedisAddr:              "redis:6379",
		RedisRequireTLS:        "true",
		CORSAllowedOrigins:     "https://console.example.com",
		RequiredServiceSecrets: []EnvRequirement{{Name: "VERIFIER_AUTH_TOKEN", Value: "secret"}},
	}

	t.Run("pass", func(t *testing.T) {
		if err := ValidateProduction(base); err != nil {
			t.Fatalf("expected pass, got %v", err)
		}
	})

	t.Run("non_prod_skip", func(t *testing.T) {
		o := base
		o.Environment = "development"
		o.DatabaseRequireTLS = "false"
		o.CORSAllowedOrigins = "*"
		if err := ValidateProduction(o); err != nil {
			t.Fatalf("expected skip in non-production, got %v", err)
		}
	})

	t.Run("db_tls_required", func(t *testing.T) {
		o := base
		o.DatabaseRequireTLS = "false"
		if err := ValidateProduction(o); err == nil {
			t.Fatal("expected DATABASE_REQUIRE_TLS enforcement error")
		}
	})

	t.Run("redis_tls_required", func(t *testing.T) {
		o := base
		o.RedisRequireTLS = "false"
		if err := ValidateProduction(o); err == nil {
			t.Fatal("expected REDIS_REQUIRE_TLS enforcement error")
		}
	})

	t.Run("redis_insecure_forbidden", func(t *testing.T) {
		o := base
		o.RedisTLSInsecure = "true"
		o.RedisAllowInsecureTLS = "true"
		if err := ValidateProduction(o); err == nil {
			t.Fatal("expected insecure redis flags error")
		}
	})

	t.Run("cors_wildcard_forbidden", func(t *testing.T) {
		o := base
		o.CORSAllowedOrigins = "*"
		if err := ValidateProduction(o); err == nil {
			t.Fatal("expected wildcard CORS error")
		}
	})

	t.Run("cors_https_required", func(t *testing.T) {
		o := base
		o.CORSAllowedOrigins = "http://console.example.com"
		if err := ValidateProduction(o); err == nil {
			t.Fatal("expected https CORS error")
		}
	})

	t.Run("required_secret", func(t *testing.T) {
		o := base
		o.RequiredServiceSecrets = []EnvRequirement{
			{Name: "VERIFIER_AUTH_TOKEN", Value: ""},
		}
		if err := ValidateProduction(o); err == nil {
			t.Fatal("expected required secret error")
		}
	})

	t.Run("strict_can_be_disabled", func(t *testing.T) {
		o := base
		o.StrictProdSecurity = "false"
		o.DatabaseRequireTLS = "false"
		o.CORSAllowedOrigins = "*"
		if err := ValidateProduction(o); err != nil {
			t.Fatalf("expected strict disable skip, got %v", err)
		}
	})
}
