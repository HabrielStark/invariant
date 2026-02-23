import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react'
import {
  type DecisionSummary,
  type Escrow,
  type Incident,
  type KeySummary,
  type PolicyApproval,
  type PolicyDiff,
  type PolicyEvaluation,
  type PolicyVersion,
  type ReplayResult,
  type SourceState,
  type SubjectRestriction,
  approveEscrow,
  approvePolicyVersion,
  createSubjectRestriction,
  createPolicySet,
  createPolicyVersion,
  diffPolicyVersions,
  evaluatePolicy,
  getAuthToken,
  getBeliefState,
  listIncidents,
  listKeys,
  listEscrows,
  listPolicyApprovals,
  listPolicyVersions,
  listSubjectRestrictions,
  listVerdicts,
  removeSubjectRestriction,
  replayDecision,
  registerKey,
  setAuthToken,
  submitPolicyVersion,
  updateIncidentStatus,
  updateKeyStatus
} from './lib/api'
const DslEditor = lazy(() => import('./components/DslEditor'))

const defaultIntent = `{
  "intent_id": "demo-intent",
  "idempotency_key": "demo-idempotency",
  "actor": { "id": "operator-1", "roles": ["FinanceOperator"], "tenant": "tenant-a" },
  "action_type": "TOOL_CALL",
  "target": { "domain": "finance", "object_types": ["Invoice"], "object_ids": ["inv-1"], "scope": "single" },
  "operation": { "name": "pay_invoice", "params": { "amount": "123.45", "currency": "EUR" } },
  "time": { "event_time": "2026-02-03T11:00:00Z", "request_time": "2026-02-03T11:00:02Z" },
  "data_requirements": { "max_staleness_sec": 30, "required_sources": ["bank"], "uncertainty_budget": { "amount_abs": "1.00" } },
  "safety_mode": "NORMAL"
}`

const defaultBelief = `{
  "domain": "finance",
  "sources": [
    { "source": "bank", "age_sec": 5, "health_score": 0.99, "lag_sec": 1, "jitter_sec": 1 }
  ]
}`

type RoleView = 'operator' | 'compliance'

type AxiomBlock = {
  id: string
  when: string
  requires: string[]
  elseShield: string
}

const splitDsl = (dsl: string) => {
  const lines = dsl.split(/\r?\n/)
  const prefixLines: string[] = []
  const blocks: AxiomBlock[] = []
  let current: AxiomBlock | null = null
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith('axiom ')) {
      if (current) blocks.push(current)
      const name = trimmed.replace(/^axiom\s+/, '').replace(/:$/, '')
      current = { id: name || 'Axiom', when: '', requires: [], elseShield: '' }
      continue
    }
    if (!current) {
      prefixLines.push(line)
      continue
    }
    if (trimmed.startsWith('when ')) {
      current.when = trimmed.replace(/^when\s+/, '')
      continue
    }
    if (trimmed.startsWith('require ')) {
      current.requires.push(trimmed.replace(/^require\s+/, ''))
      continue
    }
    if (trimmed.startsWith('else ')) {
      current.elseShield = trimmed.replace(/^else\s+/, '')
      continue
    }
    if (trimmed !== '') {
      current.requires.push(trimmed)
    }
  }
  if (current) blocks.push(current)
  return { prefixLines, blocks }
}

const buildDsl = (prefixLines: string[], blocks: AxiomBlock[], fallbackHeader: string) => {
  const cleanedPrefix = prefixLines.length ? [...prefixLines] : [fallbackHeader]
  if (!cleanedPrefix.some(line => line.trim().startsWith('policyset '))) {
    cleanedPrefix.unshift(fallbackHeader)
  }
  const lines: string[] = [...cleanedPrefix.filter(line => line.trim() !== '' || line.includes(':'))]
  if (lines.length > 0 && lines[lines.length - 1].trim() !== '') {
    lines.push('')
  }
  blocks.forEach(block => {
    lines.push(`axiom ${block.id || 'Axiom'}:`)
    if (block.when.trim() !== '') {
      lines.push(`  when ${block.when}`)
    }
    block.requires.forEach(req => {
      if (req.trim() !== '') {
        lines.push(`  require ${req}`)
      }
    })
    if (block.elseShield.trim() !== '') {
      const shieldLine = block.elseShield.startsWith('shield(') ? block.elseShield : `shield(${block.elseShield})`
      lines.push(`  else ${shieldLine}`)
    }
    lines.push('')
  })
  return lines.join('\n').trim() + '\n'
}

const formatTime = (iso: string) => {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

const CounterexampleExplorer = ({ result }: { result: PolicyEvaluation | null }) => {
  if (!result?.counterexample) {
    return <div className="placeholder">No counterexample to inspect.</div>
  }
  return (
    <div className="counterexample">
      <div>
        <div className="muted">Failed axioms</div>
        <div className="chip-row">
          {result.counterexample.failed_axioms.map(ax => (
            <span key={ax} className="chip warn">{ax}</span>
          ))}
        </div>
      </div>
      <div>
        <div className="muted">Minimal facts</div>
        <ul className="fact-list">
          {result.counterexample.minimal_facts.map(fact => (
            <li key={fact}>{fact}</li>
          ))}
        </ul>
      </div>
    </div>
  )
}

const PolicyStepper = ({ status }: { status: string }) => {
  const steps = ['DRAFT', 'PENDING_APPROVAL', 'PUBLISHED']
  return (
    <div className="stepper">
      {steps.map(step => {
        const active = step === status
        const complete = steps.indexOf(step) < steps.indexOf(status)
        return (
          <div key={step} className={`step ${active ? 'active' : ''} ${complete ? 'done' : ''}`}>
            <div className="step-dot" />
            <span>{step.replace('_', ' ')}</span>
          </div>
        )
      })}
    </div>
  )
}

const AuditTimeline = ({ decisions }: { decisions: DecisionSummary[] }) => (
  <div className="timeline">
    {decisions.map(item => (
      <div key={item.decision_id} className="timeline-item">
        <div className={`timeline-dot ${item.verdict.toLowerCase()}`} />
        <div>
          <div className="list-title">{item.verdict} · {item.reason_code}</div>
          <div className="muted">{formatTime(item.created_at)}</div>
        </div>
      </div>
    ))}
    {decisions.length === 0 && <div className="placeholder">No audit events.</div>}
  </div>
)

const AxiomBuilder = ({ blocks, onChange }: { blocks: AxiomBlock[]; onChange: (next: AxiomBlock[]) => void }) => {
  const [dragIndex, setDragIndex] = useState<number | null>(null)

  const updateBlock = (index: number, patch: Partial<AxiomBlock>) => {
    const next = blocks.map((b, i) => (i === index ? { ...b, ...patch } : b))
    onChange(next)
  }

  const moveBlock = (from: number, to: number) => {
    if (from === to) return
    const next = [...blocks]
    const [item] = next.splice(from, 1)
    next.splice(to, 0, item)
    onChange(next)
  }

  return (
    <div className="builder">
      <div className="builder-actions">
        <button
          className="btn ghost"
          onClick={() => onChange([...blocks, { id: `Axiom_${blocks.length + 1}`, when: '', requires: [], elseShield: '' }])}
        >
          Add axiom
        </button>
      </div>
      {blocks.map((block, index) => (
        <div
          key={`${block.id}-${index}`}
          className="builder-card"
          draggable
          onDragStart={() => setDragIndex(index)}
          onDragOver={e => e.preventDefault()}
          onDrop={() => dragIndex !== null && moveBlock(dragIndex, index)}
        >
          <div className="builder-header">
            <input
              value={block.id}
              onChange={e => updateBlock(index, { id: e.target.value })}
              placeholder="Axiom ID"
            />
            <button className="btn ghost" onClick={() => onChange(blocks.filter((_, i) => i !== index))}>Remove</button>
          </div>
          <label>When</label>
          <input
            value={block.when}
            onChange={e => updateBlock(index, { when: e.target.value })}
            placeholder="when action.name == ..."
          />
          <label>Require</label>
          <textarea
            rows={3}
            value={block.requires.join('\n')}
            onChange={e => updateBlock(index, { requires: e.target.value.split('\n').filter(Boolean) })}
            placeholder='require source("bank").age_sec <= 30'
          />
          <label>Else shield</label>
          <input
            value={block.elseShield}
            onChange={e => updateBlock(index, { elseShield: e.target.value })}
            placeholder='shield("READ_ONLY")'
          />
        </div>
      ))}
      {blocks.length === 0 && <div className="placeholder">No axioms yet. Add one to begin.</div>}
    </div>
  )
}

export default function App() {
  const [policyDsl, setPolicyDsl] = useState(`policyset finance v17:\n  domain finance\n  rate limit 240 per minute scope tenant\n  approvals required 2\n  approvals roles [\"complianceofficer\",\"securityadmin\"]\n  approvals sod true\n  approvals expires_in 1h\n  invariant action.scope == \"single\"\n  abac allow when principal.role contains \"complianceofficer\"\naxiom Fresh_bank_feed:\n  when action.name in [\"pay_invoice\", \"refund\"]\n  require source(\"bank\").age_sec <= 30\naxiom Role_guard:\n  when action.name == \"pay_invoice\"\n  require actor.role contains \"FinanceOperator\"\n  else shield(\"READ_ONLY\")\n`)
  const [policyId, setPolicyId] = useState('finance')
  const [policyVersion, setPolicyVersion] = useState('v17')
  const [status, setStatus] = useState('')
  const [decisions, setDecisions] = useState<DecisionSummary[]>([])
  const [escrows, setEscrows] = useState<Escrow[]>([])
  const [sources, setSources] = useState<SourceState[]>([])
  const [replay, setReplay] = useState<Record<string, ReplayResult>>({})
  const [approver, setApprover] = useState('finance-manager-1')
  const [versions, setVersions] = useState<PolicyVersion[]>([])
  const [diff, setDiff] = useState<PolicyDiff | null>(null)
  const [selectedVersion, setSelectedVersion] = useState('')
  const [versionApprovals, setVersionApprovals] = useState<PolicyApproval[]>([])
  const [evalIntent, setEvalIntent] = useState(defaultIntent)
  const [evalBelief, setEvalBelief] = useState(defaultBelief)
  const [evalResult, setEvalResult] = useState<PolicyEvaluation | null>(null)
  const [keys, setKeys] = useState<KeySummary[]>([])
  const [keyKid, setKeyKid] = useState('')
  const [keySigner, setKeySigner] = useState('agent-key-1')
  const [keyPublic, setKeyPublic] = useState('')
  const [keyStatus, setKeyStatus] = useState('')
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [subjectRestrictions, setSubjectRestrictions] = useState<SubjectRestriction[]>([])
  const [subjectActorID, setSubjectActorID] = useState('actor-1')
  const [subjectReason, setSubjectReason] = useState('gdpr request')
  const [subjectTenant, setSubjectTenant] = useState('')
  const [subjectRequestedBy, setSubjectRequestedBy] = useState('compliance-officer-1')
  const [subjectStatus, setSubjectStatus] = useState('')
  const [incidentActor, setIncidentActor] = useState('security-admin-1')
  const [policyAuthor, setPolicyAuthor] = useState('policy-author')
  const [policyApprover, setPolicyApprover] = useState('compliance-officer-1')
  const [roleView, setRoleView] = useState<RoleView>('operator')
  const [streamStatus, setStreamStatus] = useState('connecting')
  const [authToken, setAuthTokenState] = useState(getAuthToken())

  const refresh = useCallback(async () => {
    try {
      const [v, e, b, p, k, i, sr] = await Promise.all([
        listVerdicts(40),
        listEscrows(40),
        getBeliefState('finance').catch(() => []),
        listPolicyVersions(policyId).catch(() => []),
        listKeys(50).catch(() => []),
        listIncidents(50).catch(() => []),
        listSubjectRestrictions('', 100).catch(() => [])
      ])
      setDecisions(v)
      setEscrows(e)
      setSources(b)
      setVersions(p)
      setKeys(k)
      setIncidents(i)
      setSubjectRestrictions(sr)

      const nextSelected = selectedVersion || (p[0]?.version ?? '')
      if (nextSelected) {
        setSelectedVersion(nextSelected)
        const approvals = await listPolicyApprovals(policyId, nextSelected).catch(() => [])
        setVersionApprovals(approvals)
      } else {
        setVersionApprovals([])
      }

      if (p.length >= 2) {
        const latest = p[0].version
        const previous = p[1].version
        const d = await diffPolicyVersions(policyId, previous, latest).catch(() => null)
        setDiff(d)
      } else {
        setDiff(null)
      }
    } catch {
      // keep last known state
    }
  }, [policyId, selectedVersion])

  const publishPolicy = useCallback(async () => {
    try {
      setStatus('Publishing...')
      await createPolicySet(policyId)
      await createPolicyVersion(policyId, policyVersion, policyDsl, policyAuthor, 1)
      await submitPolicyVersion(policyId, policyVersion, policyAuthor)
      await approvePolicyVersion(policyId, policyVersion, policyApprover)
      setStatus('Published')
      await refresh()
    } catch (err) {
      setStatus(`Failed: ${String(err)}`)
    }
  }, [policyAuthor, policyApprover, policyDsl, policyId, policyVersion, refresh])

  const loadApprovals = async (version: string) => {
    setSelectedVersion(version)
    const approvals = await listPolicyApprovals(policyId, version).catch(() => [])
    setVersionApprovals(approvals)
  }

  const replayDecisionByID = async (decisionId: string) => {
    const data = await replayDecision(decisionId).catch(() => null)
    if (!data) return
    setReplay(prev => ({ ...prev, [decisionId]: data }))
  }

  const approveEscrowByID = async (escrowId: string) => {
    const ok = await approveEscrow(escrowId, approver).then(() => true).catch(() => false)
    if (ok) await refresh()
  }

  const createKey = async () => {
    try {
      setKeyStatus('Registering key...')
      await registerKey(keyKid, keySigner, keyPublic)
      setKeyPublic('')
      setKeyStatus('Key registered')
      await refresh()
    } catch (err) {
      setKeyStatus(`Failed: ${String(err)}`)
    }
  }

  const toggleKey = async (kid: string, currentStatus: string) => {
    const nextStatus = currentStatus.toLowerCase() === 'active' ? 'revoked' : 'active'
    await updateKeyStatus(kid, nextStatus as 'active' | 'revoked').then(() => refresh())
  }

  const setIncident = async (incidentId: string, status: 'ACKNOWLEDGED' | 'RESOLVED') => {
    await updateIncidentStatus(incidentId, status, incidentActor).then(() => refresh())
  }

  const applySubjectRestriction = async () => {
    try {
      setSubjectStatus('Applying restriction...')
      await createSubjectRestriction(subjectActorID, subjectReason, subjectRequestedBy, subjectTenant)
      setSubjectStatus('Restriction applied')
      await refresh()
    } catch (err) {
      setSubjectStatus(`Failed: ${String(err)}`)
    }
  }

  const liftSubjectRestriction = async () => {
    try {
      setSubjectStatus('Lifting restriction...')
      await removeSubjectRestriction(subjectActorID, subjectRequestedBy, subjectTenant)
      setSubjectStatus('Restriction lifted')
      await refresh()
    } catch (err) {
      setSubjectStatus(`Failed: ${String(err)}`)
    }
  }

  const updateAuthToken = (value: string) => {
    setAuthTokenState(value)
    setAuthToken(value)
  }

  const evaluateCurrentPolicy = async () => {
    try {
      const intent = JSON.parse(evalIntent)
      const beliefStateSnapshot = JSON.parse(evalBelief)
      const result = await evaluatePolicy(policyId, selectedVersion || policyVersion, intent, beliefStateSnapshot)
      setEvalResult(result)
    } catch (err) {
      setEvalResult({ policy_set_id: policyId, version: selectedVersion || policyVersion, verdict: 'DENY', reason_code: `EVAL_INPUT_ERROR: ${String(err)}` })
    }
  }

  const submitSelectedPolicy = async () => {
    const version = selectedVersion || policyVersion
    if (!version) return
    await submitPolicyVersion(policyId, version, policyAuthor).then(() => refresh())
  }

  const approveSelectedPolicy = async () => {
    const version = selectedVersion || policyVersion
    if (!version) return
    await approvePolicyVersion(policyId, version, policyApprover).then(() => refresh())
  }

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    let ws: WebSocket | null = null
    let attempts = 0
    let closed = false
    const connect = () => {
      if (closed) return
      attempts += 1
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${window.location.host}/v1/stream`)
      setStreamStatus('connecting')
      ws.onopen = () => {
        attempts = 0
        setStreamStatus('live')
      }
      ws.onmessage = evt => {
        try {
          const msg = JSON.parse(evt.data)
          if (msg.type === 'refresh' || msg.type === 'ready') {
            void refresh()
          }
        } catch {
          // ignore
        }
      }
      ws.onclose = () => {
        if (closed) return
        setStreamStatus('disconnected')
        const wait = Math.min(10000, 1000 * Math.max(1, attempts))
        setTimeout(connect, wait)
      }
      ws.onerror = () => {
        setStreamStatus('error')
      }
    }
    connect()
    return () => {
      closed = true
      ws?.close()
    }
  }, [refresh])

  const { prefixLines, blocks } = useMemo(() => splitDsl(policyDsl), [policyDsl])

  const onBlocksChange = (next: AxiomBlock[]) => {
    const header = `policyset ${policyId} ${policyVersion}:`
    setPolicyDsl(buildDsl(prefixLines, next, header))
  }

  const summary = useMemo(() => {
    const verdictCounts = decisions.reduce<Record<string, number>>((acc, d) => {
      acc[d.verdict] = (acc[d.verdict] || 0) + 1
      return acc
    }, {})
    const pendingEscrows = escrows.filter(e => e.status === 'PENDING').length
    const openIncidents = incidents.filter(i => i.status !== 'RESOLVED').length
    const published = versions.find(v => v.status === 'PUBLISHED')
    return {
      verdictCounts,
      pendingEscrows,
      openIncidents,
      latestPolicy: published?.version ?? versions[0]?.version ?? policyVersion
    }
  }, [decisions, escrows, incidents, versions, policyVersion])

  const selectedVersionLabel = useMemo(() => selectedVersion || policyVersion, [selectedVersion, policyVersion])

  const isCompliance = roleView === 'compliance'

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" />
          <div>
            <div className="brand-title">AxiomOS</div>
            <div className="brand-sub">Runtime Assurance</div>
          </div>
        </div>
        <nav className="nav">
          <span className="nav-title">Workspace</span>
          <button className="nav-item">Overview</button>
          <button className="nav-item">Policies</button>
          <button className="nav-item">Escrow</button>
          <button className="nav-item">Verdicts</button>
          <button className="nav-item">Data Freshness</button>
          <button className="nav-item">Audit</button>
          <button className="nav-item">Keys & Trust</button>
          <button className="nav-item">Incidents</button>
        </nav>
        <div className="sidebar-footer">
          <div className="badge">{streamStatus}</div>
          <div className="muted">Live updates</div>
          <div className="role-toggle">
            <label>View</label>
            <select value={roleView} onChange={e => setRoleView(e.target.value as RoleView)}>
              <option value="operator">Operator</option>
              <option value="compliance">Compliance Officer</option>
            </select>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h1>Runtime Assurance Console</h1>
            <p>Policies, decisions, escrow, data freshness, and incident response.</p>
          </div>
          <div className="topbar-actions">
            <div className="auth-token">
              <label htmlFor="authToken">Auth token</label>
              <input
                id="authToken"
                type="password"
                placeholder="Bearer token"
                value={authToken}
                onChange={e => updateAuthToken(e.target.value)}
              />
            </div>
            <button className="btn ghost" onClick={refresh}>Refresh</button>
            {isCompliance && <button className="btn primary" onClick={publishPolicy}>Publish policy</button>}
          </div>
        </header>

        <section className="section">
          <div className="section-header">
            <h2>Overview</h2>
            <span className="muted">Latest policy: {summary.latestPolicy}</span>
          </div>
          <div className="stat-grid">
            <div className="stat-card">
              <div className="stat-title">Total verdicts</div>
              <div className="stat-value">{decisions.length}</div>
              <div className="stat-meta">ALLOW {summary.verdictCounts.ALLOW ?? 0} · SHIELD {summary.verdictCounts.SHIELD ?? 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-title">Pending escrow</div>
              <div className="stat-value">{summary.pendingEscrows}</div>
              <div className="stat-meta">Approvals queue</div>
            </div>
            <div className="stat-card">
              <div className="stat-title">Open incidents</div>
              <div className="stat-value">{summary.openIncidents}</div>
              <div className="stat-meta">Security + compliance</div>
            </div>
            <div className="stat-card">
              <div className="stat-title">Sources monitored</div>
              <div className="stat-value">{sources.length}</div>
              <div className="stat-meta">Finance domain</div>
            </div>
          </div>
        </section>

        <div className="main-grid">
          {isCompliance && (
            <section className="section card span-2">
              <div className="section-header">
                <h2>Policy Studio</h2>
                <span className="muted">Draft → approvals → publish</span>
              </div>
              <div className="form-grid">
                <div>
                  <label>Policy ID</label>
                  <input value={policyId} onChange={e => setPolicyId(e.target.value)} />
                </div>
                <div>
                  <label>Version</label>
                  <input value={policyVersion} onChange={e => setPolicyVersion(e.target.value)} />
                </div>
                <div>
                  <label>Author</label>
                  <input value={policyAuthor} onChange={e => setPolicyAuthor(e.target.value)} />
                </div>
                <div>
                  <label>Approver</label>
                  <input value={policyApprover} onChange={e => setPolicyApprover(e.target.value)} />
                </div>
              </div>
              <div className="dsl-grid">
                <div>
                  <label>DSL</label>
                  <Suspense fallback={<div className="dsl-editor loading">Loading editor...</div>}>
                    <DslEditor value={policyDsl} onChange={setPolicyDsl} />
                  </Suspense>
                  <div className="inline">
                    <div className="muted">Status: {status || 'idle'}</div>
                  </div>
                </div>
                <div>
                  <label>Axiom Builder</label>
                  <AxiomBuilder blocks={blocks} onChange={onBlocksChange} />
                </div>
              </div>
            </section>
          )}

          {isCompliance && (
            <section className="section card">
              <div className="section-header">
                <h2>Policy Versions</h2>
                <span className="muted">Select to inspect approvals</span>
              </div>
              <div className="list">
                {versions.map(item => (
                  <div key={item.version} className="list-row">
                    <div>
                      <div className="list-title">{item.version}</div>
                      <div className="muted">{item.status} · {item.approvals_received}/{item.approvals_required}</div>
                    </div>
                    <button className="btn ghost" onClick={() => loadApprovals(item.version)}>Approvals</button>
                  </div>
                ))}
                {versions.length === 0 && <div className="placeholder">No policy versions.</div>}
              </div>
            </section>
          )}

          {isCompliance && (
            <section className="section card">
              <div className="section-header">
                <h2>Approval Workflow</h2>
                <span className="muted">Version: {selectedVersionLabel}</span>
              </div>
              <PolicyStepper status={versions.find(v => v.version === selectedVersionLabel)?.status ?? 'DRAFT'} />
              <div className="inline">
                <button className="btn ghost" onClick={submitSelectedPolicy}>Submit</button>
                <button className="btn primary" onClick={approveSelectedPolicy}>Approve</button>
              </div>
              <div className="list">
                {versionApprovals.map(item => (
                  <div key={item.approver} className="list-row">
                    <div className="list-title">{item.approver}</div>
                    <div className="muted">{formatTime(item.created_at)}</div>
                  </div>
                ))}
                {versionApprovals.length === 0 && <div className="placeholder">No approvals recorded.</div>}
              </div>
            </section>
          )}

          {isCompliance && (
            <section className="section card">
              <div className="section-header">
                <h2>Policy Diff</h2>
                <span className="muted">Latest changes</span>
              </div>
              {diff ? (
                <div className="diff">
                  <div className="diff-row">
                    <div className="muted">From</div>
                    <div>{diff.from}</div>
                  </div>
                  <div className="diff-row">
                    <div className="muted">To</div>
                    <div>{diff.to}</div>
                  </div>
                  <div className="diff-summary">+{diff.added.length} / -{diff.removed.length}</div>
                </div>
              ) : (
                <div className="placeholder">Diff requires at least two versions.</div>
              )}
            </section>
          )}

          <section className="section card">
            <div className="section-header">
              <h2>Escrow Queue</h2>
              <span className="muted">Approver: {approver}</span>
            </div>
            <label>Approver</label>
            <input value={approver} onChange={e => setApprover(e.target.value)} />
            <div className="list">
              {escrows.map(item => (
                <div key={item.escrow_id} className="list-row">
                  <div>
                    <div className="list-title">{item.status}</div>
                    <div className="muted">{item.escrow_id.slice(0, 8)} · {formatTime(item.created_at)}</div>
                    <div className="muted">{item.approvals_received}/{item.approvals_required} approvals</div>
                  </div>
                  <button className="btn primary" onClick={() => approveEscrowByID(item.escrow_id)}>Approve</button>
                </div>
              ))}
              {escrows.length === 0 && <div className="placeholder">No escrows pending.</div>}
            </div>
          </section>

          <section className="section card">
            <div className="section-header">
              <h2>Latest Verdicts</h2>
              <span className="muted">Auto-refresh feed</span>
            </div>
            <div className="list">
              {decisions.map(item => (
                <div key={item.decision_id} className="list-row">
                  <div>
                    <div className="list-title">{item.verdict}</div>
                    <div className="muted">{item.reason_code} · {formatTime(item.created_at)}</div>
                  </div>
                  <button className="btn ghost" onClick={() => replayDecisionByID(item.decision_id)}>Replay</button>
                </div>
              ))}
              {decisions.length === 0 && <div className="placeholder">No verdicts yet.</div>}
            </div>
          </section>

          <section className="section card">
            <div className="section-header">
              <h2>Audit Timeline</h2>
              <span className="muted">Decision trail</span>
            </div>
            <AuditTimeline decisions={decisions.slice(0, 12)} />
          </section>

          <section className="section card">
            <div className="section-header">
              <h2>Audit Replay</h2>
              <span className="muted">Drift detection</span>
            </div>
            <div className="list">
              {decisions.slice(0, 6).map(item => (
                <div key={item.decision_id} className="list-row">
                  <div className="list-title">{item.decision_id.slice(0, 8)}</div>
                  <div className={replay[item.decision_id]?.drift ? 'chip warn' : 'chip ok'}>
                    {replay[item.decision_id]?.drift ? 'Drift' : 'Stable'}
                  </div>
                </div>
              ))}
              {decisions.length === 0 && <div className="placeholder">Replay results appear here.</div>}
            </div>
          </section>

          <section className="section card">
            <div className="section-header">
              <h2>Data Freshness</h2>
              <span className="muted">Source health and lag</span>
            </div>
            <div className="list">
              {sources.map(item => (
                <div key={item.source} className="list-row">
                  <div>
                    <div className="list-title">{item.source}</div>
                    <div className="muted">age {item.age_sec}s · lag {item.lag_sec}s · jitter {item.jitter_sec}s</div>
                  </div>
                  <div className="chip">{(item.health_score * 100).toFixed(0)}%</div>
                </div>
              ))}
              {sources.length === 0 && <div className="placeholder">No sources.</div>}
            </div>
          </section>

          <section className="section card">
            <div className="section-header">
              <h2>Evaluate Policy</h2>
              <span className="muted">Sandbox checks</span>
            </div>
            <label>Intent</label>
            <textarea rows={6} value={evalIntent} onChange={e => setEvalIntent(e.target.value)} />
            <label>Belief snapshot</label>
            <textarea rows={4} value={evalBelief} onChange={e => setEvalBelief(e.target.value)} />
            <button className="btn primary" onClick={evaluateCurrentPolicy}>Evaluate</button>
            {evalResult && (
              <div className="result">
                <div className="result-title">{evalResult.verdict}</div>
                <div className="muted">{evalResult.reason_code}</div>
              </div>
            )}
            <CounterexampleExplorer result={evalResult} />
          </section>

          {isCompliance && (
            <>
              <section className="section card">
                <div className="section-header">
                  <h2>Keys & Trust</h2>
                  <span className="muted">Public keys registry</span>
                </div>
                <div className="form-grid">
                  <div>
                    <label>Kid</label>
                    <input value={keyKid} onChange={e => setKeyKid(e.target.value)} />
                  </div>
                  <div>
                    <label>Signer</label>
                    <input value={keySigner} onChange={e => setKeySigner(e.target.value)} />
                  </div>
                </div>
                <label>Public Key</label>
                <textarea rows={3} value={keyPublic} onChange={e => setKeyPublic(e.target.value)} />
                <div className="inline">
                  <button className="btn primary" onClick={createKey}>Register key</button>
                  <div className="muted">{keyStatus}</div>
                </div>
                <div className="list">
                  {keys.map(k => (
                    <div key={k.kid} className="list-row">
                      <div>
                        <div className="list-title">{k.kid.slice(0, 8)}</div>
                        <div className="muted">{k.signer} · {k.status}</div>
                      </div>
                      <button className="btn ghost" onClick={() => toggleKey(k.kid, k.status)}>Toggle</button>
                    </div>
                  ))}
                  {keys.length === 0 && <div className="placeholder">No keys registered.</div>}
                </div>
              </section>

              <section className="section card">
                <div className="section-header">
                  <h2>Subject Controls</h2>
                  <span className="muted">GDPR restriction controls</span>
                </div>
                <div className="form-grid">
                  <div>
                    <label>Actor ID</label>
                    <input value={subjectActorID} onChange={e => setSubjectActorID(e.target.value)} />
                  </div>
                  <div>
                    <label>Tenant (optional)</label>
                    <input value={subjectTenant} onChange={e => setSubjectTenant(e.target.value)} />
                  </div>
                </div>
                <label>Reason</label>
                <input value={subjectReason} onChange={e => setSubjectReason(e.target.value)} />
                <label>Requested By</label>
                <input value={subjectRequestedBy} onChange={e => setSubjectRequestedBy(e.target.value)} />
                <div className="inline">
                  <button className="btn primary" onClick={applySubjectRestriction}>Restrict</button>
                  <button className="btn ghost" onClick={liftSubjectRestriction}>Unrestrict</button>
                  <div className="muted">{subjectStatus}</div>
                </div>
                <div className="list">
                  {subjectRestrictions.map(item => (
                    <div key={`${item.tenant ?? 'global'}:${item.actor_id_hash}`} className="list-row">
                      <div>
                        <div className="list-title">{item.actor_id_hash.slice(0, 12)}</div>
                        <div className="muted">{item.reason} · {item.tenant || 'global'} · {item.created_by}</div>
                      </div>
                      <div className="chip warn">Restricted</div>
                    </div>
                  ))}
                  {subjectRestrictions.length === 0 && <div className="placeholder">No active restrictions.</div>}
                </div>
              </section>
            </>
          )}

          <section className="section card">
            <div className="section-header">
              <h2>Incidents</h2>
              <span className="muted">Security + compliance</span>
            </div>
            <label>Actor</label>
            <input value={incidentActor} onChange={e => setIncidentActor(e.target.value)} />
            <div className="list">
              {incidents.map(i => (
                <div key={i.incident_id} className="incident-card">
                  <div className="incident-title">{i.title}</div>
                  <div className="muted">{i.reason_code} · {i.status}</div>
                  <div className="incident-actions">
                    <button className="btn ghost" onClick={() => setIncident(i.incident_id, 'ACKNOWLEDGED')}>Ack</button>
                    <button className="btn primary" onClick={() => setIncident(i.incident_id, 'RESOLVED')}>Resolve</button>
                  </div>
                </div>
              ))}
              {incidents.length === 0 && <div className="placeholder">No incidents.</div>}
            </div>
          </section>
        </div>
      </main>
    </div>
  )
}
