export type ActionIntent = {
  intent_id: string
  idempotency_key: string
  actor: { id: string; roles: string[]; tenant: string }
  action_type: 'TOOL_CALL' | 'ONTOLOGY_ACTION'
  target: {
    domain: string
    object_types: string[]
    object_ids: string[]
    scope: 'single' | 'batch'
  }
  operation: {
    name: string
    params: Record<string, string | number | boolean | null | Record<string, unknown> | unknown[]>
  }
  time: { event_time: string; request_time: string }
  data_requirements: {
    max_staleness_sec: number
    required_sources: string[]
    uncertainty_budget: Record<string, unknown>
  }
  safety_mode: 'STRICT' | 'NORMAL' | 'DEGRADED'
}

export type ActionCert = {
  cert_id: string
  intent_hash: string
  policy_set_id: string
  policy_version: string
  claims: Array<{ type: string; statement: string }>
  assumptions: Record<string, unknown>
  evidence: Record<string, unknown>
  rollback_plan: Record<string, unknown>
  expires_at: string
  nonce: string
  sequence?: number
  signature: {
    signer: string
    alg: 'ed25519'
    sig: string
    kid: string
  }
}

export type GatewayResponse = {
  verdict: 'ALLOW' | 'SHIELD' | 'DEFER' | 'ESCROW' | 'DENY'
  reason_code: string
  retry_after_ms?: number
  result?: unknown
  shield?: { type: string; params: Record<string, unknown> }
  escrow?: { escrow_id: string; status: string; ttl: string }
  counterexample?: { minimal_facts: string[]; failed_axioms: string[] }
}

export type ExecuteRequest = {
  intent: ActionIntent
  cert: ActionCert
  tool_payload?: Record<string, unknown>
  action_payload?: Record<string, unknown>
}

export class AxiomClient {
  private readonly baseURL: string
  private readonly defaultHeaders: Record<string, string>

  constructor(baseURL: string, defaultHeaders: Record<string, string> = {}) {
    this.baseURL = baseURL.replace(/\/$/, '')
    this.defaultHeaders = { ...defaultHeaders }
  }

  async executeTool(req: ExecuteRequest): Promise<GatewayResponse> {
    return this.postJSON<GatewayResponse>('/v1/tool/execute', req)
  }

  async executeOntology(req: ExecuteRequest): Promise<GatewayResponse> {
    return this.postJSON<GatewayResponse>('/v1/ontology/actions/execute', req)
  }

  async verify(intent: ActionIntent, cert: ActionCert): Promise<{
    verdict: string
    reason_code: string
    retry_after_ms?: number
    counterexample?: { minimal_facts: string[]; failed_axioms: string[] }
    suggested_shield?: { type: string; params: Record<string, unknown> }
  }> {
    return this.postJSON('/v1/verify', { intent, cert })
  }

  async approveEscrow(escrowID: string, approver: string): Promise<{ status: string; approvals_received?: number }> {
    return this.postJSON('/v1/escrow/approve', { escrow_id: escrowID, approver })
  }

  async replay(decisionID: string): Promise<{
    original: { verdict: string; reason_code: string }
    replay: { verdict: string; reason_code: string }
    drift: boolean
  }> {
    return this.postJSON(`/v1/audit/${encodeURIComponent(decisionID)}/replay`, {})
  }

  async listVerdicts(limit = 50): Promise<{ items: Array<{ decision_id: string; verdict: string; reason_code: string; created_at: string }> }> {
    return this.getJSON(`/v1/verdicts?limit=${limit}`)
  }

  async listEscrows(limit = 50): Promise<{ items: Array<{ escrow_id: string; status: string; approvals_required: number; approvals_received: number }> }> {
    return this.getJSON(`/v1/escrows?limit=${limit}`)
  }

  private async getJSON<T>(path: string): Promise<T> {
    const res = await fetch(this.baseURL + path, {
      method: 'GET',
      headers: {
        ...this.defaultHeaders
      }
    })
    if (!res.ok) {
      throw new Error(`request failed (${res.status}): ${await res.text()}`)
    }
    return (await res.json()) as T
  }

  private async postJSON<T>(path: string, payload: unknown): Promise<T> {
    const res = await fetch(this.baseURL + path, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...this.defaultHeaders
      },
      body: JSON.stringify(payload)
    })
    if (!res.ok) {
      throw new Error(`request failed (${res.status}): ${await res.text()}`)
    }
    return (await res.json()) as T
  }
}

export function canonicalizeJSON(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new Error('floating-point JSON tokens are not allowed; use decimal strings')
    }
    return String(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map(v => canonicalizeJSON(v)).join(',')}]`
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort()
    const parts = keys.map(k => `${JSON.stringify(k)}:${canonicalizeJSON(obj[k])}`)
    return `{${parts.join(',')}}`
  }
  throw new Error('unsupported json type')
}

export async function computeIntentHash(intent: ActionIntent, policyVersion: string, nonce: string): Promise<string> {
  const canonical = canonicalizeJSON(intent)
  const payload = `${canonical}|${policyVersion}|${nonce}`
  const encoded = new TextEncoder().encode(payload)
  const digest = await crypto.subtle.digest('SHA-256', encoded)
  const bytes = new Uint8Array(digest)
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}
