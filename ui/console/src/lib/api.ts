export type DecisionSummary = {
  decision_id: string
  idempotency_key: string
  verdict: string
  reason_code: string
  created_at: string
}

export type Escrow = {
  escrow_id: string
  status: string
  created_at: string
  expires_at: string
  approvals_required: number
  approvals_received: number
}

export type SourceState = {
  source: string
  age_sec: number
  health_score: number
  lag_sec: number
  jitter_sec: number
}

export type ReplayResult = {
  original: { verdict: string; reason_code: string }
  replay: { verdict: string; reason_code: string }
  drift: boolean
}

export type PolicyVersion = {
  policy_set_id: string
  version: string
  status: string
  approvals_required: number
  approvals_received: number
  created_by: string
  approved_by?: string
  created_at: string
}

export type PolicyDiff = {
  from: string
  to: string
  added: string[]
  removed: string[]
}

export type PolicyApproval = {
  approver: string
  created_at: string
}

export type PolicyEvaluation = {
  policy_set_id: string
  version: string
  verdict: string
  reason_code: string
  counterexample?: {
    minimal_facts: string[]
    failed_axioms: string[]
  }
  suggested_shield?: {
    type: string
    params: Record<string, unknown>
  }
}

export type KeySummary = {
  kid: string
  signer: string
  status: string
  created_at: string
}

export type Incident = {
  incident_id: string
  decision_id?: string
  severity: string
  category: string
  reason_code: string
  status: string
  title: string
  details?: Record<string, unknown>
  acknowledged_by?: string
  resolved_by?: string
  created_at: string
  updated_at: string
  resolved_at?: string
}

export type SubjectRestriction = {
  tenant?: string
  actor_id_hash: string
  reason: string
  created_by: string
  created_at: string
  lifted_by?: string
  lifted_at?: string
}

async function parseJSON<T>(res: Response): Promise<T> {
  if (!res.ok) {
    throw new Error(await res.text())
  }
  return (await res.json()) as T
}

const tokenStorageKey = 'axiom.auth.token'

export function getAuthToken(): string {
  try {
    return localStorage.getItem(tokenStorageKey) ?? ''
  } catch {
    return ''
  }
}

export function setAuthToken(token: string): void {
  try {
    const trimmed = token.trim()
    if (trimmed === '') {
      localStorage.removeItem(tokenStorageKey)
    } else {
      localStorage.setItem(tokenStorageKey, trimmed)
    }
  } catch {
    // ignore
  }
}

function withAuth(headers: Record<string, string> = {}): Record<string, string> {
  const token = getAuthToken()
  if (token === '') return headers
  return { ...headers, Authorization: `Bearer ${token}` }
}

export async function createPolicySet(id: string, domain = 'finance'): Promise<void> {
  await fetch('/v1/policysets', {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ id, name: id, domain })
  })
}

export async function createPolicyVersion(policyId: string, version: string, dsl: string, createdBy: string, approvalsRequired: number): Promise<void> {
  const body: Record<string, unknown> = { version, dsl, approvals_required: approvalsRequired }
  if (getAuthToken() === '') {
    body.created_by = createdBy
  }
  const res = await fetch(`/v1/policysets/${policyId}/versions`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function submitPolicyVersion(policyId: string, version: string, submitter: string): Promise<void> {
  const body: Record<string, unknown> = {}
  if (getAuthToken() === '') {
    body.submitter = submitter
  }
  const res = await fetch(`/v1/policysets/${policyId}/versions/${version}/submit`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function approvePolicyVersion(policyId: string, version: string, approver: string): Promise<void> {
  const body: Record<string, unknown> = {}
  if (getAuthToken() === '') {
    body.approver = approver
  }
  const res = await fetch(`/v1/policysets/${policyId}/versions/${version}/approvals`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function listPolicyVersions(policyId: string): Promise<PolicyVersion[]> {
  const res = await fetch(`/v1/policysets/${policyId}/versions`, { headers: withAuth() })
  const payload = await parseJSON<{ items: PolicyVersion[] }>(res)
  return payload.items ?? []
}

export async function listPolicyApprovals(policyId: string, version: string): Promise<PolicyApproval[]> {
  const res = await fetch(`/v1/policysets/${policyId}/versions/${encodeURIComponent(version)}/approvals`, { headers: withAuth() })
  const payload = await parseJSON<{ items: PolicyApproval[] }>(res)
  return payload.items ?? []
}

export async function diffPolicyVersions(policyId: string, fromVersion: string, toVersion: string): Promise<PolicyDiff> {
  const res = await fetch(`/v1/policysets/${policyId}/versions:diff?from=${encodeURIComponent(fromVersion)}&to=${encodeURIComponent(toVersion)}`, { headers: withAuth() })
  return parseJSON<PolicyDiff>(res)
}

export async function evaluatePolicy(policyId: string, version: string, intent: unknown, beliefStateSnapshot: unknown): Promise<PolicyEvaluation> {
  const res = await fetch(`/v1/policysets/${policyId}/versions/${encodeURIComponent(version)}/evaluate`, {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ intent, belief_state_snapshot: beliefStateSnapshot })
  })
  return parseJSON<PolicyEvaluation>(res)
}

export async function listVerdicts(limit = 20): Promise<DecisionSummary[]> {
  const res = await fetch(`/v1/verdicts?limit=${limit}`, { headers: withAuth() })
  const payload = await parseJSON<{ items: DecisionSummary[] }>(res)
  return payload.items ?? []
}

export async function listEscrows(limit = 20): Promise<Escrow[]> {
  const res = await fetch(`/v1/escrows?limit=${limit}`, { headers: withAuth() })
  const payload = await parseJSON<{ items: Escrow[] }>(res)
  return payload.items ?? []
}

export async function getBeliefState(domain: string): Promise<SourceState[]> {
  const res = await fetch(`/v1/beliefstate?domain=${encodeURIComponent(domain)}`, { headers: withAuth() })
  const payload = await parseJSON<{ sources: SourceState[] }>(res)
  return payload.sources ?? []
}

export async function replayDecision(decisionId: string): Promise<ReplayResult> {
  const res = await fetch(`/v1/audit/${decisionId}/replay`, { method: 'POST', headers: withAuth() })
  return parseJSON<ReplayResult>(res)
}

export async function approveEscrow(escrowId: string, approver: string): Promise<void> {
  const body: Record<string, unknown> = { escrow_id: escrowId }
  if (getAuthToken() === '') {
    body.approver = approver
  }
  const res = await fetch('/v1/escrow/approve', {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function listKeys(limit = 50): Promise<KeySummary[]> {
  const res = await fetch(`/v1/keys?limit=${limit}`, { headers: withAuth() })
  const payload = await parseJSON<{ items: KeySummary[] }>(res)
  return payload.items ?? []
}

export async function registerKey(kid: string, signer: string, publicKey: string): Promise<void> {
  const body: Record<string, string> = { signer, public_key: publicKey }
  if (kid.trim() !== '') body.kid = kid.trim()
  const res = await fetch('/v1/keys', {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function updateKeyStatus(kid: string, status: 'active' | 'revoked'): Promise<void> {
  const res = await fetch(`/v1/keys/${encodeURIComponent(kid)}`, {
    method: 'PATCH',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ status })
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function listIncidents(limit = 50, status = ''): Promise<Incident[]> {
  const query = status ? `?limit=${limit}&status=${encodeURIComponent(status)}` : `?limit=${limit}`
  const res = await fetch(`/v1/incidents${query}`, { headers: withAuth() })
  const payload = await parseJSON<{ items: Incident[] }>(res)
  return payload.items ?? []
}

export async function updateIncidentStatus(incidentId: string, status: 'ACKNOWLEDGED' | 'RESOLVED', actor: string): Promise<void> {
  const res = await fetch(`/v1/incidents/${encodeURIComponent(incidentId)}`, {
    method: 'PATCH',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ status, actor })
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function listSubjectRestrictions(actorId = '', limit = 100): Promise<SubjectRestriction[]> {
  const params = new URLSearchParams()
  params.set('limit', String(limit))
  if (actorId.trim() !== '') params.set('actor_id', actorId.trim())
  const res = await fetch(`/v1/compliance/subjects/restrictions?${params.toString()}`, { headers: withAuth() })
  const payload = await parseJSON<{ items: SubjectRestriction[] }>(res)
  return payload.items ?? []
}

export async function createSubjectRestriction(actorId: string, reason: string, requestedBy: string, tenant = ''): Promise<void> {
  const body: Record<string, string> = {
    actor_id: actorId,
    reason,
    tenant
  }
  if (getAuthToken() === '') {
    body.requested_by = requestedBy
  }
  const res = await fetch('/v1/compliance/subjects/restrict', {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}

export async function removeSubjectRestriction(actorId: string, requestedBy: string, tenant = ''): Promise<void> {
  const body: Record<string, string> = {
    actor_id: actorId,
    tenant
  }
  if (getAuthToken() === '') {
    body.requested_by = requestedBy
  }
  const res = await fetch('/v1/compliance/subjects/unrestrict', {
    method: 'POST',
    headers: withAuth({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body)
  })
  if (!res.ok) {
    throw new Error(await res.text())
  }
}
