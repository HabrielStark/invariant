package openclaw

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	GatewayURL                 string
	PolicySetID                string
	PolicyVersion              string
	SignerKid                  string
	SignerName                 string
	PrivateKeyPath             string
	PrivateKeyB64              string
	DefaultActorID             string
	DefaultTenant              string
	DefaultRoles               []string
	DefaultWorkspace           string
	DefaultSafetyMode          string
	DefaultActionType          string
	DefaultMaxStalenessSec     int
	MaxStalenessByOperation    map[string]int
	CertTTL                    time.Duration
	ReplayTTL                  time.Duration
	MissingRollbackForceEscrow bool
	SideEffectFreeOps          map[string]struct{}
	EscrowOnOps                map[string]struct{}
	AuthHeader                 string
	AuthToken                  string
	RequestTimeout             time.Duration
}

func LoadConfigFromEnv() Config {
	defaultStale := envInt("OPENCLAW_MAX_STALENESS_DEFAULT_SEC", 30)
	if defaultStale <= 0 {
		defaultStale = 30
	}
	cfg := Config{
		GatewayURL:                 env("INVARIANT_GATEWAY_URL", "http://localhost:8080"),
		PolicySetID:                env("OPENCLAW_POLICY_SET_ID", "finance"),
		PolicyVersion:              env("OPENCLAW_POLICY_VERSION", "v1"),
		SignerKid:                  env("OPENCLAW_SIGNER_KID", "openclaw-dev-kid"),
		SignerName:                 env("OPENCLAW_SIGNER_NAME", "openclaw-adapter"),
		PrivateKeyPath:             env("OPENCLAW_SIGNER_PRIVATE_KEY_PATH", ".invariant/openclaw/dev_keys/private.key"),
		PrivateKeyB64:              strings.TrimSpace(os.Getenv("OPENCLAW_SIGNER_PRIVATE_KEY_B64")),
		DefaultActorID:             env("OPENCLAW_DEFAULT_ACTOR_ID", "openclaw-agent"),
		DefaultTenant:              env("OPENCLAW_DEFAULT_TENANT", "acme"),
		DefaultRoles:               csvList(env("OPENCLAW_DEFAULT_ROLES", "FinanceOperator")),
		DefaultWorkspace:           env("OPENCLAW_DEFAULT_WORKSPACE", "finance"),
		DefaultSafetyMode:          normalizeSafetyMode(env("OPENCLAW_DEFAULT_SAFETY_MODE", "NORMAL")),
		DefaultActionType:          normalizeActionType(env("OPENCLAW_DEFAULT_ACTION_TYPE", "TOOL_CALL")),
		DefaultMaxStalenessSec:     defaultStale,
		MaxStalenessByOperation:    parseKeyIntMap(env("OPENCLAW_MAX_STALENESS_BY_OPERATION", "")),
		CertTTL:                    time.Second * time.Duration(envInt("OPENCLAW_CERT_TTL_SEC", 120)),
		ReplayTTL:                  time.Second * time.Duration(envInt("OPENCLAW_REPLAY_TTL_SEC", 300)),
		MissingRollbackForceEscrow: envBool("OPENCLAW_MISSING_ROLLBACK_FORCE_ESCROW", true),
		SideEffectFreeOps:          csvSet(env("OPENCLAW_SIDE_EFFECT_FREE_OPS", "health,read,list,status")),
		EscrowOnOps:                csvSet(env("OPENCLAW_FORCE_ESCROW_OPS", "")),
		AuthHeader:                 env("INVARIANT_GATEWAY_AUTH_HEADER", ""),
		AuthToken:                  env("INVARIANT_GATEWAY_AUTH_TOKEN", ""),
		RequestTimeout:             time.Millisecond * time.Duration(envInt("OPENCLAW_REQUEST_TIMEOUT_MS", 5000)),
	}
	if cfg.CertTTL <= 0 {
		cfg.CertTTL = 120 * time.Second
	}
	if cfg.ReplayTTL <= 0 {
		cfg.ReplayTTL = 5 * time.Minute
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 5 * time.Second
	}
	return cfg
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func envBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func csvList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func csvSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, v := range csvList(raw) {
		out[strings.ToLower(v)] = struct{}{}
	}
	return out
}

func parseKeyIntMap(raw string) map[string]int {
	out := map[string]int{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(parts[0]))
		vRaw := strings.TrimSpace(parts[1])
		if k == "" || vRaw == "" {
			continue
		}
		v, err := strconv.Atoi(vRaw)
		if err != nil || v < 0 {
			continue
		}
		out[k] = v
	}
	return out
}

func normalizeSafetyMode(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch s {
	case "STRICT", "NORMAL", "DEGRADED":
		return s
	default:
		return "NORMAL"
	}
}

func normalizeActionType(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	switch s {
	case "TOOL_CALL", "ONTOLOGY_ACTION":
		return s
	default:
		return "TOOL_CALL"
	}
}
