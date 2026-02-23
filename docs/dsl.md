# Policy DSL

Extended syntax:

```
policyset finance v17:
  domain finance
  rate limit 240 per minute scope tenant
  approvals required 2
  approvals roles ["complianceofficer","securityadmin"]
  approvals sod true
  approvals expires_in 1h
  invariant action.scope == "single"
  abac allow when principal.role contains "complianceofficer"
  abac deny when actor.role contains "intern"
axiom Fresh_bank_feed:
  when action.name in ["pay_invoice", "refund"]
  require source("bank").age_sec <= 30
axiom Role_guard:
  when action.name == "pay_invoice"
  require actor.role contains "FinanceOperator"
  else shield("READ_ONLY")
```

Supported operators:
- `==`, `!=`, `<=`, `>=`, `<`, `>`
- `in ["a","b"]`
- `contains`
- `and` in `when` predicates

Resolvable fields:
- `action.name`, `action.scope`
- `actor.id`, `actor.tenant`, `actor.role`
- `principal.id`, `principal.tenant`, `principal.role`
- `principal.attr.<key>`, `attr.<key>` (dynamic attributes)
- `target.domain`
- `source("<name>").age_sec`, `source("<name>").health_score`, `source("<name>").lag_sec`
- `batch.size`
- `budget.remaining("<CODE>")`
- `action.params.<key>` (params values must be strings or numbers)

Notes:
- `rate limit` sets per-policy limits; gateway defaults are used if not present.
- `approvals` config defines escrow quorum and SoD enforcement.
- `abac` rules are evaluated in the gateway before verification.

## DSL Language Server (LSP)

Run the LSP server over stdio:

```bash
go run ./cmd/axiomdsl-lsp
```

Capabilities:
- diagnostics from `axiomdsl` parser
- keyword completion
- hover help for DSL keywords
