// Phase 4 tests: every failure code, and the Phase 4 rows of
// docs/THREAT_MODEL.md (T1.1, T1.6, T1.10, T2.1-T2.5, T3.2, T3.3, T3.5, T4.1,
// T7.1, T7.2, T7.4). Proofs are real, made with Anon Aadhaar's published
// circuit from synthetic V5 codes signed with ephemeral test keys.
//
// Run: npm test. The proof tests need the circuit artifacts (cd ../circuit &&
// npm run fetch, or AA_ARTIFACTS=<dir>); without them they are reported as skipped.
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { buildBn128, utils } from 'ffjavascript';
import {
  FAILURE_CODES,
  MemoryStore,
  RequestError,
  checkVerifierId,
  close,
  createVerifier,
  nullifierSeedFor,
  signalHashFor,
  type FailureCode,
  type ProofRequest,
  type VerifierOptions,
  type VerifyResult,
} from '../src/index.ts';
import { testRegistry, type Registry } from '../../issuer-registry/index.ts';
import { DEFAULT_DIR, MANIFEST, buildInput, close as closeCircuit, keyHash, prove } from '../../circuit/index.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../secure-qr/synthetic.mjs';

const ARTIFACTS = process.env.AA_ARTIFACTS || DEFAULT_DIR;
const HAVE_ARTIFACTS = ['aadhaar-verifier.wasm', 'circuit_final.zkey'].every((f) => fs.existsSync(path.join(ARTIFACTS, f)));
const NEEDS_PROOFS = HAVE_ARTIFACTS ? {} : { skip: 'circuit artifacts missing: cd ../circuit && npm run fetch' };
after(async () => {
  await close();
  await closeCircuit();
});

const X = 'https://shop.example';
const Y = 'https://other.example';
const G = Date.parse('2026-10-26T04:30:00Z') / 1000; // 10:00 IST: a QR generated then has timestamp G
const ISSUED_AT = G + 3540; // when the requests were made

// Every code any test produced; the last test checks that all were.
const seenCodes = new Set<FailureCode>();
function expectFailure(result: VerifyResult, code: FailureCode) {
  assert.equal(result.ok, false, `expected ${code}, got success`);
  if (!result.ok) {
    assert.equal(result.code, code, result.detail);
    seenCodes.add(result.code);
  }
}

// ---- Without proofs ----------------------------------------------------------------

test('nullifier seed and signal hash: field elements, deterministic, bound to every field', async () => {
  const seedX = await nullifierSeedFor(X);
  assert.equal(seedX, await nullifierSeedFor(X));
  assert.notEqual(seedX, await nullifierSeedFor(Y));
  assert.ok(BigInt(seedX) < 2n ** 248n);
  const request: ProofRequest = { version: 1, verifierId: X, challenge: 'ab'.repeat(32), maxAgeSeconds: 3600, expiresAt: G };
  const signal = await signalHashFor(request);
  for (const changed of [{ verifierId: Y }, { challenge: 'cd'.repeat(32) }, { maxAgeSeconds: 3601 }, { expiresAt: G + 1 }]) {
    assert.notEqual(await signalHashFor({ ...request, ...changed }), signal, JSON.stringify(changed));
  }
});

test('verifier ids must be origins; requests must be well formed', async () => {
  for (const bad of ['https://shop.example/', 'https://shop.example/path', 'http://shop.example', 'shop.example', 'javascript:alert(1)']) {
    assert.throws(() => checkVerifierId(bad), (e: unknown) => e instanceof RequestError && e.code === 'INVALID_VERIFIER_ID', bad);
  }
  assert.equal(checkVerifierId('http://localhost:5173'), 'http://localhost:5173');
  const verifier = createVerifier({ verifierId: X, registry: testRegistry([]), now: () => ISSUED_AT });
  for (const maxAgeSeconds of [0, -1, 1.5, Number.NaN]) {
    await assert.rejects(verifier.createRequest({ maxAgeSeconds }), (e: unknown) => e instanceof RequestError && e.code === 'INVALID_REQUEST');
  }
  const [a, b] = [await verifier.createRequest({ maxAgeSeconds: 60 }), await verifier.createRequest({ maxAgeSeconds: 60 })];
  assert.notEqual(a.challenge, b.challenge);
  assert.equal(a.expiresAt, ISSUED_AT + 300);
});

test("the SDK's vkey.json is the pinned verification key", () => {
  const pinned = MANIFEST.files.find((f: { name: string }) => f.name === 'vkey.json').sha256;
  const actual = crypto.createHash('sha256').update(fs.readFileSync(new URL('../vkey.json', import.meta.url))).digest('hex');
  assert.equal(actual, pinned);
});

// ---- With proofs --------------------------------------------------------------------

const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const strangerKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const testKey = (k: crypto.KeyPairKeyObjectResult, id: string, window = {}) => ({ publicKey: k.publicKey, keyHash: keyHash(k.publicKey) as string, id, ...window });
const registry = testRegistry([testKey(keys, 'test-key-1')]);

const photo = syntheticPhoto(900);
const trailing = unknownTrailer(27);
const qr = (generatedAt: number, fields: Record<string, string> = {}) =>
  makeSyntheticSecureQr(keys.privateKey, { version: 'V5', photo, trailing, fields: syntheticFields({ generatedAt: new Date(generatedAt * 1000), ...fields }) }).text;

type Proof = { proof: any; publicSignals: string[] };
const requests: Record<string, ProofRequest> = {};
const proofs: Record<string, Proof> = {};

before(async () => {
  if (!HAVE_ARTIFACTS) return;
  const issuing = createVerifier({ verifierId: X, registry, now: () => ISSUED_AT });
  requests.r1 = await issuing.createRequest({ maxAgeSeconds: 3600 });
  requests.r2 = await issuing.createRequest({ maxAgeSeconds: 3600 });
  requests.r3 = await issuing.createRequest({ maxAgeSeconds: 86400 });
  requests.r4 = await issuing.createRequest({ maxAgeSeconds: 86400 });
  const proveFor = async (text: string, request: ProofRequest, seedOf = X): Promise<Proof> =>
    prove(buildInput(text, keys.publicKey, { nullifierSeed: await nullifierSeedFor(seedOf), signalHash: await signalHashFor(request) }), { dir: ARTIFACTS });
  proofs.p1 = await proveFor(qr(G), requests.r1); // an adult, fresh QR
  proofs.p2 = await proveFor(qr(G), requests.r2, Y); // the seed of another verifier
  proofs.p3 = await proveFor(qr(G, { dob: '26-10-2010' }), requests.r3); // a minor
  proofs.p4 = await proveFor(qr(G - 3600), requests.r4); // the same person, a QR downloaded an hour earlier
});

// A verifier holding the given requests, with its clock at `at`.
function verifierAt(at: number, requestsHeld: ProofRequest[], options: Partial<VerifierOptions> = {}) {
  const store = new MemoryStore();
  requestsHeld.forEach((r) => store.putRequest(r));
  return createVerifier({ verifierId: X, registry, store, now: () => at, ...options });
}
const VERIFY_AT = ISSUED_AT + 50;

test('a valid proof is accepted, with the issuer key and the QR time', NEEDS_PROOFS, async () => {
  const result = await verifierAt(VERIFY_AT, [requests.r1]).verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1);
  assert.deepEqual(result.ok && [result.newNullifier, result.issuerKeyId, result.credentialTime], [true, 'test-key-1', G]);
});

test('T2.2, T2.3: the same proof, or a re-randomized copy, cannot answer a request twice', NEEDS_PROOFS, async () => {
  const verifier = verifierAt(VERIFY_AT, [requests.r1]);
  const { proof, publicSignals } = proofs.p1;
  assert.equal((await verifier.verify(proof, publicSignals, requests.r1)).ok, true);
  expectFailure(await verifier.verify(proof, publicSignals, requests.r1), 'CHALLENGE_REUSED');

  // Groth16 malleability: (rA, B/r, C) is another valid proof of the same statement.
  const curve = await buildBn128(true);
  const r = curve.Fr.e(7n);
  const a = curve.G1.toAffine(curve.G1.timesFr(curve.G1.fromObject(utils.unstringifyBigInts(proof.pi_a)), r));
  const b = curve.G2.toAffine(curve.G2.timesFr(curve.G2.fromObject(utils.unstringifyBigInts(proof.pi_b)), curve.Fr.inv(r)));
  const mauled = { ...proof, pi_a: utils.stringifyBigInts(curve.G1.toObject(a)), pi_b: utils.stringifyBigInts(curve.G2.toObject(b)) };
  await curve.terminate();
  assert.notDeepEqual(mauled.pi_a, proof.pi_a);
  const vkey = JSON.parse(fs.readFileSync(new URL('../vkey.json', import.meta.url), 'utf8'));
  assert.equal(await snarkjs.groth16.verify(vkey, publicSignals, mauled), true, 'the mauled proof is valid');
  expectFailure(await verifier.verify(mauled, publicSignals, requests.r1), 'CHALLENGE_REUSED');
});

test('T2.1 (Phase 4 acceptance): a proof replayed against a different request is CHALLENGE_MISMATCH', NEEDS_PROOFS, async () => {
  const { proof, publicSignals } = proofs.p1;
  // Another verifier, with its own request.
  const other = createVerifier({ verifierId: Y, registry, now: () => VERIFY_AT });
  const theirRequest = await other.createRequest({ maxAgeSeconds: 3600 });
  expectFailure(await other.verify(proof, publicSignals, theirRequest), 'CHALLENGE_MISMATCH');
  expectFailure(await other.verify(proof, publicSignals, requests.r1), 'CHALLENGE_MISMATCH');
  // The same verifier, another of its requests.
  expectFailure(await verifierAt(VERIFY_AT, [requests.r1, requests.r2]).verify(proof, publicSignals, requests.r2), 'CHALLENGE_MISMATCH');
  // A request this verifier never issued.
  expectFailure(await verifierAt(VERIFY_AT, []).verify(proof, publicSignals, requests.r1), 'CHALLENGE_MISMATCH');
});

test('T7.4: a request changed after proving is CHALLENGE_MISMATCH', NEEDS_PROOFS, async () => {
  const verifier = verifierAt(VERIFY_AT, [requests.r1]);
  for (const changed of [{ maxAgeSeconds: 86400 }, { expiresAt: requests.r1.expiresAt + 600 }]) {
    expectFailure(await verifier.verify(proofs.p1.proof, proofs.p1.publicSignals, { ...requests.r1, ...changed }), 'CHALLENGE_MISMATCH');
  }
  assert.equal((await verifier.verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1)).ok, true, 'unchanged, it is still accepted');
});

test('T2.4: a request answered after it expired is CHALLENGE_EXPIRED', NEEDS_PROOFS, async () => {
  const verifier = verifierAt(requests.r1.expiresAt + 1, [requests.r1]);
  expectFailure(await verifier.verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1), 'CHALLENGE_EXPIRED');
});

test("T2.5: a proof under another verifier's nullifier seed is NULLIFIER_SEED_MISMATCH", NEEDS_PROOFS, async () => {
  const verifier = verifierAt(VERIFY_AT, [requests.r2]);
  expectFailure(await verifier.verify(proofs.p2.proof, proofs.p2.publicSignals, requests.r2), 'NULLIFIER_SEED_MISMATCH');
});

test('T7.1, T7.2: a changed public signal or proof element is rejected', NEEDS_PROOFS, async () => {
  const { proof, publicSignals } = proofs.p1;
  const verifier = verifierAt(VERIFY_AT, [requests.r1]);
  const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  // The two request-bound inputs are checked first and fail with their own codes.
  const expected: FailureCode[] = ['BAD_PROOF', 'BAD_PROOF', 'BAD_PROOF', 'BAD_PROOF', 'BAD_PROOF', 'BAD_PROOF', 'BAD_PROOF', 'NULLIFIER_SEED_MISMATCH', 'CHALLENGE_MISMATCH'];
  for (let i = 0; i < publicSignals.length; i++) {
    const changed = [...publicSignals];
    changed[i] = ((BigInt(changed[i]) + 1n) % FIELD).toString();
    expectFailure(await verifier.verify(proof, changed, requests.r1), expected[i]);
  }
  const bump = (v: string) => (BigInt(v) + 1n).toString();
  for (const changed of [
    { ...proof, pi_a: [bump(proof.pi_a[0]), ...proof.pi_a.slice(1)] },
    { ...proof, pi_b: [[bump(proof.pi_b[0][0]), proof.pi_b[0][1]], ...proof.pi_b.slice(1)] },
    { ...proof, pi_c: [proof.pi_c[0], bump(proof.pi_c[1]), proof.pi_c[2]] },
    { ...proof, pi_a: ['not a number', '1', '1'] },
  ]) {
    expectFailure(await verifier.verify(changed, publicSignals, requests.r1), 'BAD_PROOF');
  }
  expectFailure(await verifier.verify(proof, publicSignals.slice(1), requests.r1), 'BAD_PROOF');
  assert.equal((await verifier.verify(proof, publicSignals, requests.r1)).ok, true, 'a BAD_PROOF does not use up the request');
});

test('T1.1: a QR signed by a key outside the registry is UNTRUSTED_ISSUER', NEEDS_PROOFS, async () => {
  const otherRegistry: Registry = testRegistry([testKey(strangerKeys, 'stranger')]);
  const verifier = verifierAt(VERIFY_AT, [requests.r1], { registry: otherRegistry });
  expectFailure(await verifier.verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1), 'UNTRUSTED_ISSUER');
});

test("T1.6: a QR generated outside the key's validity window is ISSUER_KEY_NOT_VALID", NEEDS_PROOFS, async () => {
  for (const window of [{ notBefore: 0, notAfter: G - 1 }, { notBefore: G + 1, notAfter: 2 ** 32 }]) {
    const verifier = verifierAt(VERIFY_AT, [requests.r1], { registry: testRegistry([testKey(keys, 'test-key-1', window)]) });
    expectFailure(await verifier.verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1), 'ISSUER_KEY_NOT_VALID');
  }
});

test('T1.10: a proof that does not show 19 or older is AGE_NOT_PROVEN, and takes no account slot', NEEDS_PROOFS, async () => {
  const verifier = verifierAt(VERIFY_AT, [requests.r3, requests.r4]);
  expectFailure(await verifier.verify(proofs.p3.proof, proofs.p3.publicSignals, requests.r3), 'AGE_NOT_PROVEN');
  // The same photo (same nullifier) is still free for an adult proof afterwards.
  assert.equal((await verifier.verify(proofs.p4.proof, proofs.p4.publicSignals, requests.r4)).ok, true);
});

test("T3.3, T3.5: freshness holds to the second at the request's maxAge", NEEDS_PROOFS, async () => {
  const { proof, publicSignals } = proofs.p1; // QR time G, maxAge 3600
  assert.equal((await verifierAt(G + 3600, [requests.r1]).verify(proof, publicSignals, requests.r1)).ok, true);
  expectFailure(await verifierAt(G + 3601, [requests.r1]).verify(proof, publicSignals, requests.r1), 'CREDENTIAL_TOO_OLD');
});

test('T3.2, T4.1: the same person again (a re-download) is NULLIFIER_SEEN, unless returning users are accepted', NEEDS_PROOFS, async () => {
  const strict = verifierAt(VERIFY_AT, [requests.r1, requests.r4]);
  assert.equal((await strict.verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1)).ok, true);
  expectFailure(await strict.verify(proofs.p4.proof, proofs.p4.publicSignals, requests.r4), 'NULLIFIER_SEEN');

  const login = verifierAt(VERIFY_AT, [requests.r1, requests.r4], { onSeenNullifier: 'accept' });
  const first = await login.verify(proofs.p1.proof, proofs.p1.publicSignals, requests.r1);
  const again = await login.verify(proofs.p4.proof, proofs.p4.publicSignals, requests.r4);
  assert.ok(first.ok && again.ok);
  assert.deepEqual([first.newNullifier, again.newNullifier, first.nullifier === again.nullifier], [true, false, true]);
});

test('every failure code is produced by at least one test above', NEEDS_PROOFS, () => {
  assert.deepEqual([...seenCodes].sort(), [...FAILURE_CODES].sort());
});
