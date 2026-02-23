# Agent SDK

## Go SDK (`pkg/agentsdk`)

Capabilities:
- canonical hash computation (`ComputeIntentHash`)
- cert binding + ed25519 signing (`BindAndSignCert`)
- gateway calls (`ExecuteTool`, `ExecuteOntology`, `Verify`, `ApproveEscrow`)

Example:

```go
package main

import (
  "context"
  "encoding/json"
  "os"
  "time"

  "axiom/pkg/agentsdk"
  "axiom/pkg/models"
)

func main() {
  c := agentsdk.NewClient("http://localhost:8080", 5*time.Second)

  signer, err := agentsdk.NewSignerFromBase64("kid-1", "agent-key-1", os.Getenv("AGENT_PRIVATE_KEY_B64"))
  if err != nil {
    panic(err)
  }

  intent := models.ActionIntent{
    IntentID:       "intent-1",
    IdempotencyKey: "idem-1",
    Actor:          models.Actor{ID: "agent-1", Roles: []string{"FinanceOperator"}, Tenant: "acme"},
    ActionType:     "TOOL_CALL",
    Target:         models.Target{Domain: "finance", ObjectTypes: []string{"Invoice"}, ObjectIDs: []string{"inv-1"}, Scope: "single"},
    Operation:      models.Operation{Name: "pay_invoice", Params: json.RawMessage(`{"amount":"123.45","currency":"EUR"}`)},
    Time:           models.TimeSpec{EventTime: "2026-02-03T11:00:00Z", RequestTime: "2026-02-03T11:00:02Z"},
    DataRequirements: models.DataRequirements{
      MaxStalenessSec: 30,
      RequiredSources: []string{"bank"},
      UncertaintyBudget: map[string]interface{}{
        "amount_abs": "1.00",
      },
    },
    SafetyMode: "NORMAL",
  }

  cert := models.ActionCert{
    CertID:        "cert-1",
    PolicySetID:   "finance",
    PolicyVersion: "v17",
    Nonce:         "nonce-1",
    Claims:        []models.Claim{{Type: "Freshness", Statement: "bank_feed_age <= 30s"}},
    RollbackPlan:  models.Rollback{Type: "COMPENSATING_ACTION", Steps: []string{"reverse_payment"}},
  }

  if err := agentsdk.BindAndSignCert(intent, &cert, signer, 120*time.Second, time.Now().UTC()); err != nil {
    panic(err)
  }

  resp, err := c.ExecuteTool(context.Background(), agentsdk.ExecuteRequest{
    Intent:      intent,
    Cert:        cert,
    ToolPayload: json.RawMessage(`{"op":"simulate","input":{"invoice":"inv-1"}}`),
  })
  if err != nil {
    panic(err)
  }
  _ = resp
}
```

## TypeScript SDK (`sdk/ts`)

Capabilities:
- gateway APIs (`executeTool`, `executeOntology`, `verify`, `approveEscrow`)
- replay/verdict listing helpers
- canonical JSON + `computeIntentHash`

Build:

```bash
cd sdk/ts
../../ui/console/node_modules/.bin/tsc -p tsconfig.json
```

Example:

```ts
import { AxiomClient, computeIntentHash, type ActionIntent } from './src/index.js'

const client = new AxiomClient('http://localhost:8080')

const intent: ActionIntent = {
  intent_id: 'intent-1',
  idempotency_key: 'idem-1',
  actor: { id: 'agent-1', roles: ['FinanceOperator'], tenant: 'acme' },
  action_type: 'TOOL_CALL',
  target: { domain: 'finance', object_types: ['Invoice'], object_ids: ['inv-1'], scope: 'single' },
  operation: { name: 'pay_invoice', params: { amount: '123.45', currency: 'EUR' } },
  time: { event_time: '2026-02-03T11:00:00Z', request_time: '2026-02-03T11:00:02Z' },
  data_requirements: { max_staleness_sec: 30, required_sources: ['bank'], uncertainty_budget: { amount_abs: '1.00' } },
  safety_mode: 'NORMAL'
}

const intentHash = await computeIntentHash(intent, 'v17', 'nonce-1')

const response = await client.executeTool({
  intent,
  cert: {
    cert_id: 'cert-1',
    intent_hash: intentHash,
    policy_set_id: 'finance',
    policy_version: 'v17',
    claims: [{ type: 'Freshness', statement: 'bank_feed_age <= 30s' }],
    assumptions: { open_system_terms: [], uncertainty_budget: { amount_abs: '1.00' }, allowed_time_skew_sec: 10 },
    evidence: { state_snapshot_refs: [], attestations: [] },
    rollback_plan: { type: 'COMPENSATING_ACTION', steps: ['reverse_payment'] },
    expires_at: '2026-02-03T11:02:00Z',
    nonce: 'nonce-1',
    signature: { signer: 'agent-key-1', alg: 'ed25519', sig: '<base64-signature>', kid: 'kid-1' }
  },
  tool_payload: { op: 'simulate', input: { invoice: 'inv-1' } }
})

console.log(response.verdict)
```
