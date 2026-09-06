import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { webcrypto } from 'node:crypto'
import { canonicalizeJSON, computeIntentHash } from '../dist/index.js'

if (!globalThis.crypto) globalThis.crypto = webcrypto
const vectors = JSON.parse(await readFile(new URL('../../../testdata/canonical-vectors.json', import.meta.url), 'utf8'))
for (const vector of vectors) {
  test(`Go/TypeScript canonical parity: ${vector.name}`, async () => {
    assert.equal(canonicalizeJSON(vector.input), vector.canonical)
    assert.equal(await computeIntentHash(vector.input, vector.policy_version, vector.nonce), vector.hash)
  })
}
test('reject numbers that cannot be safely represented on the wire', () => {
  for (const value of [1.5, NaN, Infinity, -Infinity, 9007199254740992, 1e21]) {
    assert.throws(() => canonicalizeJSON({ value }), /safe integer/)
  }
  assert.equal(canonicalizeJSON(-0), '0')
})
