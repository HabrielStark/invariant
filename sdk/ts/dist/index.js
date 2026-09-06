export class AxiomClient {
    baseURL;
    defaultHeaders;
    constructor(baseURL, defaultHeaders = {}) {
        this.baseURL = baseURL.replace(/\/$/, '');
        this.defaultHeaders = { ...defaultHeaders };
    }
    async executeTool(req) {
        return this.postJSON('/v1/tool/execute', req);
    }
    async executeOntology(req) {
        return this.postJSON('/v1/ontology/actions/execute', req);
    }
    async verify(intent, cert) {
        return this.postJSON('/v1/verify', { intent, cert });
    }
    async approveEscrow(escrowID, approver) {
        return this.postJSON('/v1/escrow/approve', { escrow_id: escrowID, approver });
    }
    async replay(decisionID) {
        return this.postJSON(`/v1/audit/${encodeURIComponent(decisionID)}/replay`, {});
    }
    async listVerdicts(limit = 50) {
        return this.getJSON(`/v1/verdicts?limit=${limit}`);
    }
    async listEscrows(limit = 50) {
        return this.getJSON(`/v1/escrows?limit=${limit}`);
    }
    async getJSON(path) {
        const res = await fetch(this.baseURL + path, {
            method: 'GET',
            headers: {
                ...this.defaultHeaders
            }
        });
        if (!res.ok) {
            throw new Error(`request failed (${res.status}): ${await res.text()}`);
        }
        return (await res.json());
    }
    async postJSON(path, payload) {
        const res = await fetch(this.baseURL + path, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                ...this.defaultHeaders
            },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            throw new Error(`request failed (${res.status}): ${await res.text()}`);
        }
        return (await res.json());
    }
}
// Match the existing Go wire format. This is not general RFC 8785 JCS.
function quoteCanonicalString(value) {
    return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, char => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}
// Go sorts valid UTF-8 keys by code point; JS's default sort uses UTF-16 units.
function compareCodePoints(a, b) {
    const left = Array.from(a, char => char.codePointAt(0));
    const right = Array.from(b, char => char.codePointAt(0));
    for (let i = 0; i < Math.min(left.length, right.length); i++) {
        if (left[i] !== right[i])
            return left[i] - right[i];
    }
    return left.length - right.length;
}
export function canonicalizeJSON(value) {
    if (value === null)
        return 'null';
    if (typeof value === 'boolean')
        return value ? 'true' : 'false';
    if (typeof value === 'string')
        return quoteCanonicalString(value);
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) {
            throw new Error('only safe integer JSON numbers are allowed; use decimal strings');
        }
        return String(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map(v => canonicalizeJSON(v)).join(',')}]`;
    }
    if (typeof value === 'object') {
        const obj = value;
        const keys = Object.keys(obj).sort(compareCodePoints);
        const parts = keys.map(k => `${quoteCanonicalString(k)}:${canonicalizeJSON(obj[k])}`);
        return `{${parts.join(',')}}`;
    }
    throw new Error('unsupported json type');
}
export async function computeIntentHash(intent, policyVersion, nonce) {
    const canonical = canonicalizeJSON(intent);
    const payload = `${canonical}|${policyVersion}|${nonce}`;
    const encoded = new TextEncoder().encode(payload);
    const digest = await crypto.subtle.digest('SHA-256', encoded);
    const bytes = new Uint8Array(digest);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
