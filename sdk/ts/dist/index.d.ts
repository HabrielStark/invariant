export type ActionIntent = {
    intent_id: string;
    idempotency_key: string;
    actor: {
        id: string;
        roles: string[];
        tenant: string;
    };
    action_type: 'TOOL_CALL' | 'ONTOLOGY_ACTION';
    target: {
        domain: string;
        object_types: string[];
        object_ids: string[];
        scope: 'single' | 'batch';
    };
    operation: {
        name: string;
        params: Record<string, string | number | boolean | null | Record<string, unknown> | unknown[]>;
    };
    time: {
        event_time: string;
        request_time: string;
    };
    data_requirements: {
        max_staleness_sec: number;
        required_sources: string[];
        uncertainty_budget: Record<string, unknown>;
    };
    safety_mode: 'STRICT' | 'NORMAL' | 'DEGRADED';
};
export type ActionCert = {
    cert_id: string;
    intent_hash: string;
    policy_set_id: string;
    policy_version: string;
    claims: Array<{
        type: string;
        statement: string;
    }>;
    assumptions: Record<string, unknown>;
    evidence: Record<string, unknown>;
    rollback_plan: Record<string, unknown>;
    expires_at: string;
    nonce: string;
    sequence?: number;
    signature: {
        signer: string;
        alg: 'ed25519';
        sig: string;
        kid: string;
    };
};
export type GatewayResponse = {
    verdict: 'ALLOW' | 'SHIELD' | 'DEFER' | 'ESCROW' | 'DENY';
    reason_code: string;
    retry_after_ms?: number;
    result?: unknown;
    shield?: {
        type: string;
        params: Record<string, unknown>;
    };
    escrow?: {
        escrow_id: string;
        status: string;
        ttl: string;
    };
    counterexample?: {
        minimal_facts: string[];
        failed_axioms: string[];
    };
};
export type ExecuteRequest = {
    intent: ActionIntent;
    cert: ActionCert;
    tool_payload?: Record<string, unknown>;
    action_payload?: Record<string, unknown>;
};
export declare class AxiomClient {
    private readonly baseURL;
    private readonly defaultHeaders;
    constructor(baseURL: string, defaultHeaders?: Record<string, string>);
    executeTool(req: ExecuteRequest): Promise<GatewayResponse>;
    executeOntology(req: ExecuteRequest): Promise<GatewayResponse>;
    verify(intent: ActionIntent, cert: ActionCert): Promise<{
        verdict: string;
        reason_code: string;
        retry_after_ms?: number;
        counterexample?: {
            minimal_facts: string[];
            failed_axioms: string[];
        };
        suggested_shield?: {
            type: string;
            params: Record<string, unknown>;
        };
    }>;
    approveEscrow(escrowID: string, approver: string): Promise<{
        status: string;
        approvals_received?: number;
    }>;
    replay(decisionID: string): Promise<{
        original: {
            verdict: string;
            reason_code: string;
        };
        replay: {
            verdict: string;
            reason_code: string;
        };
        drift: boolean;
    }>;
    listVerdicts(limit?: number): Promise<{
        items: Array<{
            decision_id: string;
            verdict: string;
            reason_code: string;
            created_at: string;
        }>;
    }>;
    listEscrows(limit?: number): Promise<{
        items: Array<{
            escrow_id: string;
            status: string;
            approvals_required: number;
            approvals_received: number;
        }>;
    }>;
    private getJSON;
    private postJSON;
}
export declare function canonicalizeJSON(value: unknown): string;
export declare function computeIntentHash(intent: ActionIntent, policyVersion: string, nonce: string): Promise<string>;
