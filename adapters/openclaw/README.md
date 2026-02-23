# OpenClaw Adapter for Invariant

This package adds first-class OpenClaw integration to Invariant with two deterministic integration modes:

1. HTTP Proxy Mode (recommended)
2. WS Node Mode (`role=node`)

The adapter routes side-effecting OpenClaw calls through Invariant Gateway (`/v1/tool/execute`) and enforces:

- deterministic canonical intent mapping
- ed25519 ActionCert signing
- nonce + TTL replay protection
- idempotency dedupe
- strict verdict handling (`ALLOW | SHIELD | DEFER | ESCROW | DENY`)

## OpenClaw Hook Points (source discovery)

The integration points in OpenClaw are:

- HTTP tool execution path:
  - repo: `openclaw/openclaw`
  - file: `src/gateway/tools-invoke-http.ts`
  - function: `handleToolsInvokeHttpRequest(...)`
  - endpoint: `POST /tools/invoke`
- Side-effecting command handlers:
  - file: `src/gateway/server-methods/send.ts`
  - object fn: `sendHandlers.send(...)`
  - requires `idempotencyKey`
  - file: `src/gateway/server-methods/agent.ts`
  - object fn: `agentHandlers.agent(...)`
  - requires `idempotencyKey`
- Node command dispatch path:
  - file: `src/gateway/server-methods/nodes.ts`
  - object fn: `nodeHandlers["node.invoke"](...)`
  - forwards invoke to node registry with `idempotencyKey`
- Node invoke transport:
  - file: `src/gateway/node-registry.ts`
  - function: `invoke(...)`
  - emits event `node.invoke.request`
- WS connect challenge and node role auth:
  - file: `src/gateway/server/ws-connection.ts`
  - event: `connect.challenge`
  - file: `src/gateway/server/ws-connection/message-handler.ts`
  - validates `connect` payload, role, device signature
  - role `node` requires device identity unless explicitly bypassed for control-ui scenarios

## Integration Modes

## 1) HTTP Proxy Mode

Path: `adapters/openclaw/http-proxy`

Runs an HTTP server that accepts OpenClaw-style invoke payloads (`/tools/invoke`) and forwards to Invariant.

Input example:

```json
{
  "tool": "openclaw.send",
  "args": { "to": "+15555550123", "message": "hi" },
  "payload": { "op": "simulate", "input": { "invoice": "inv-42" } },
  "idempotency_key": "idem-001",
  "actor_id": "agent-main",
  "roles": ["Viewer"],
  "tenant": "acme",
  "workspace": "finance",
  "safety_mode": "STRICT"
}
```

## 2) WS Node Mode

Path: `adapters/openclaw/ws-node`

Connects to OpenClaw Gateway over WebSocket as `role=node`, handles `node.invoke.request`, and returns `node.invoke.result`. Internally it calls the same adapter pipeline used by HTTP mode.

Default allowed commands:

- `invariant.tool.execute`
- `invariant.agent.send`

Override with:

- `OPENCLAW_WS_NODE_COMMANDS="cmd.a,cmd.b"`

## Deterministic Mapping Contract

`OpenClaw invocation -> ActionIntent`

- `actor.id`: from request `actor_id` or header fallback
- `actor.roles`: from request `roles`
- `actor.tenant`: from request `tenant`
- `action_type`: `TOOL_CALL` by default (`ONTOLOGY_ACTION` supported)
- `operation.name`: request `command` or `tool`
- `operation.params`: sanitized canonical JSON
- `time.request_time`: request value or `now`
- `time.event_time`: request value or request time
- `data_requirements.max_staleness_sec`: per-op override (`OPENCLAW_MAX_STALENESS_BY_OPERATION`) or default
- `safety_mode`: `STRICT | NORMAL | DEGRADED`

Determinism guarantees:

- params are canonicalized with sorted object keys
- floating JSON number tokens are converted to strings to avoid non-deterministic parser differences
- intent is emitted as canonical JSON before hashing/signing
- nonce is deterministic when not explicitly supplied:
  - `sha256(idempotency_key|policy_version|canonical_intent)`

## Certificate Rules

ActionCert construction (`adapters/openclaw/signer.go`):

- `alg`: `ed25519`
- `intent_hash`: `sha256(canonical_intent|policy_version|nonce)`
- includes `expires_at` and `nonce`
- rollback behavior:
  - if `rollback_plan` provided, it is embedded
  - if missing on side-effecting calls and `OPENCLAW_MISSING_ROLLBACK_FORCE_ESCROW=true`, cert rollback is `NONE`, which forces non-ALLOW path in Invariant runtime (`ROLLBACK_REQUIRED -> ESCROW`)

Dev key management command:

```bash
go run ./cmd/invariant openclaw keys init --dir .invariant/openclaw/dev_keys --kid openclaw-dev-kid
```

Outputs:

- `.invariant/openclaw/dev_keys/private.key` (base64 ed25519 private key)
- `.invariant/openclaw/dev_keys/public.key` (base64 ed25519 public key)
- `.invariant/openclaw/dev_keys/kid.txt`

## Anti-Replay + Idempotency

In adapter core (`adapters/openclaw/adapter.go`):

- idempotency dedupe key:
  - `tenant:actor:idempotency_key`
  - stable verdicts are cached
- replay key:
  - `tenant:actor:nonce`
  - `SetNX` semantics with TTL
- DEFER responses release replay nonce key to permit safe retry

Gateway still enforces nonce replay + idempotency as second line of defense.

## Verdict Handling

- `ALLOW`: execute result returned
- `SHIELD`:
  - `READ_ONLY`: preview only
  - `SMALL_BATCH`: safe subset result returned
  - `DRY_RUN`: validation report returned as preview
  - `REQUIRE_APPROVAL`: converted upstream to `ESCROW`
- `DEFER`: return `retry_after_ms`, no execution
- `ESCROW`: return escrow reference and stop
- `DENY`: return minimal counterexample

## CLI Escrow Operations

```bash
# list
invariant escrow list --base http://localhost:8080 --status PENDING --limit 50

# approve
invariant escrow approve <escrow_id> --approver manager-1 --base http://localhost:8080

# execute approved escrow explicitly
invariant escrow execute <escrow_id> --base http://localhost:8080
```

## Local Run (without Docker)

```bash
# HTTP proxy mode
ADDR=:8090 \
INVARIANT_GATEWAY_URL=http://localhost:8080 \
OPENCLAW_SIGNER_PRIVATE_KEY_PATH=.invariant/openclaw/dev_keys/private.key \
go run ./adapters/openclaw/http-proxy

# WS node mode
OPENCLAW_WS_URL=ws://localhost:18789 \
OPENCLAW_GATEWAY_TOKEN=change-me \
INVARIANT_GATEWAY_URL=http://localhost:8080 \
OPENCLAW_SIGNER_PRIVATE_KEY_PATH=.invariant/openclaw/dev_keys/private.key \
go run ./adapters/openclaw/ws-node
```
