# AxiomOS Runbook

## 1) Key Leak
1. Revoke compromised `kid` in policy service.
2. Rotate key material in KMS/secret manager.
3. Invalidate active certs by reducing acceptance TTL to 0 temporarily.
4. Audit `BAD_SIGNATURE` and `REPLAY_DETECTED` spikes.

## 2) Dependency CVE
1. Run `make vuln` and `npm audit --omit=dev` in `ui/console`.
2. Pin fixed version and rebuild.
3. Regenerate SBOM: `make sbom`.
4. Deploy staging, run smoke + replay checks, then prod.

## 3) Escrow Backlog Spike
1. Check `/v1/escrow/{id}` for stale pending items.
2. Verify approver role assignment and SoD constraints.
3. Increase approver pool or raise shield thresholds temporarily.

## 4) Source Lag / Degraded Mode
1. Monitor State service source ages.
2. Confirm gateway is issuing SHIELD/ESCROW/DEFER (no ALLOW).
3. Recover source feeds, then clear backlog.

## 5) Cost/CPU Spike
1. Inspect gateway/verifier p95 latency and request volume.
2. Scale gateway/verifier deployments horizontally.
3. Check for replay or bypass anomaly bursts.

## 6) Replay/Bypass Attempt (SECURITY_POLICY incident)
1. In `/v1/incidents`, filter by `reason_code=REPLAY_DETECTED` or `SEQUENCE_REPLAY`.
2. Revoke suspected `kid` in policy service: `PATCH /v1/keys/{kid}` → `revoked`.
3. Set `RATE_LIMIT_PER_MINUTE` lower temporarily and `MAX_DEFER_TOTAL_MS` higher to slow abuse.
4. Run compliance export for affected actor/tenant and preserve audit logs (WORM/append-only).
5. Rotate agent keys and re-register public keys; invalidate any cached certs by expiring TTLs.

## 7) SMT Unavailable / Z3 Crash
1. Verify `verifier` logs for `SMT_UNAVAILABLE` and `SMT_NON_FORMAL` spikes.
2. Confirm Z3 binary and libz3 are present in the container (`/usr/bin/z3`, `/usr/lib/libz3.so*`).
3. Restart verifier; if persist, switch to `SMT_BACKEND=z3` and ensure `Z3_PATH` is valid.
4. During outage, enforce `DEGRADED_NO_ALLOW=true` and monitor escrow backlog.

## 8) P95/P99 Latency SLO Breach
1. Check `AxiomP95LatencyHigh` / `AxiomP99LatencyHigh` alerts in Prometheus.
2. Identify affected endpoint from `axiom_latency_p95_seconds{endpoint=...}`.
3. Check upstream service health (`VERIFIER_URL`, `STATE_URL`, `TOOL_URL`).
4. Review `axiom_endpoint_max_millis` for outlier spikes.
5. If verifier: check SMT/Z3 load. If state: check Postgres connection pool.
6. Scale horizontally or increase `UPSTREAM_TIMEOUT_MS` if load-related.
7. SLO targets: P95 < 200ms, P99 < 500ms for all gateway endpoints.

## 9) GDPR Data Subject Request
1. Receive subject access request (SAR): `GET /v1/gdpr/export?requested_by={compliance_actor}&subject_id={subject_id}`.
2. Verify requester identity and compliance officer role.
3. For erasure: `POST /v1/gdpr/erasure` with `subject_id` — pseudonymizes mutable stores and logs immutable `audit_records` exception.
4. Confirm `compliance_events` table records the operation.
5. Response SLA: acknowledge within 72h, complete within 30 days (GDPR Art. 12).
6. For disputes: retain compliance_events as non-erasable legal basis record.
