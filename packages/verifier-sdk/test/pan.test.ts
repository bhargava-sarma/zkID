// The SDK with PAN proofs: requests that accept a DigiLocker PAN record, the
// age cutoff a PAN proof must carry, and every failure code a PAN proof can
// meet. Proofs are real, made with the pinned PAN circuit (packages/pan) from
// SYNTHETIC records signed with ephemeral TEST keys.
//
// Run: npm test. Needs packages/pan installed (cd ../pan && npm ci).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  MemoryStore,
  PAN_VK_SHA256,
  RequestError,
  checkRequest,
  close,
  createVerifier,
  loadPanVerificationKey,
  nullifierSeedFor,
  panDobCutoff,
  signalHashFor,
  type Document,
  type FailureCode,
  type ProofRequest,
  type Rules,
  type VerifierOptions,
  type VerifyResult,
} from '../src/index.ts';
import { testRegistry } from '../../issuer-registry/index.ts';
import { circuitInput } from '../../pan/input.mjs';
import { prove } from '../../pan/prove.mjs';
import { readRecord } from '../../pan/record.mjs';
import { makeRecord, testIssuer, testKey } from '../../pan/synthetic.mjs';

after(close);

const X = 'https://shop.example';
const Y = 'https://other.example';
const ISSUED_AT = Date.parse('2026-11-11T06:00:00Z') / 1000; // 11:30 IST on 11 November 2026
const VERIFY_AT = ISSUED_AT + 50;
const VERIFIED_ON = '11-11-2026 10:15:00'; // DigiLocker checked the PAN at 10:15 IST that day
const VERIFIED_HOUR = Date.parse('2026-11-11T10:00:00+05:30') / 1000;

function expectFailure(result: VerifyResult, code: FailureCode) {
  assert.equal(result.ok, false, `expected ${code}, got success`);
  if (!result.ok) assert.equal(result.code, code, result.detail);
}

// ---- Without proofs -------------------------------------------------------------

test("T1.15: a PAN proof's age cutoff: the request's day in India, 19 years earlier", () => {
  assert.equal(panDobCutoff(ISSUED_AT), 20071111);
  // 23:00 UTC on 31 December is already 1 January in India.
  assert.equal(panDobCutoff(Date.parse('2026-12-31T23:00:00Z') / 1000), 20080101);
  // 29 February 2028 has no 29 February 19 years earlier.
  assert.equal(panDobCutoff(Date.parse('2028-02-29T06:00:00Z') / 1000), 20090228);
  assert.equal(panDobCutoff(Date.parse('2028-03-01T06:00:00Z') / 1000), 20090301);
});

test('requests: which documents they accept, and no PIN code or state rule when they accept a PAN record', async () => {
  const verifier = createVerifier({ verifierId: X, registry: testRegistry([]), now: () => ISSUED_AT });
  assert.deepEqual((await verifier.createRequest({ maxAgeSeconds: 60 })).documents, ['aadhaar']);
  for (const documents of [['pan'], ['aadhaar', 'pan']] as Document[][]) {
    const request = await verifier.createRequest({ maxAgeSeconds: 60, documents });
    assert.deepEqual(request.documents, documents);
    assert.equal(request.issuedAt, ISSUED_AT);
  }
  for (const documents of [[], ['pan', 'aadhaar'], ['pan', 'pan'], ['passport'], 'pan']) {
    await assert.rejects(verifier.createRequest({ maxAgeSeconds: 60, documents: documents as Document[] }), (e: unknown) => e instanceof RequestError, JSON.stringify(documents));
  }
  for (const rules of [{ age19: true, pinCode: ['5600'] }, { age19: true, state: ['Kerala'] }] as Rules[]) {
    await assert.rejects(verifier.createRequest({ maxAgeSeconds: 60, rules, documents: ['aadhaar', 'pan'] }), /PAN record has no address/);
    assert.ok(await verifier.createRequest({ maxAgeSeconds: 60, rules, documents: ['aadhaar'] }));
  }
  const request = await verifier.createRequest({ maxAgeSeconds: 60, documents: ['pan'] });
  assert.throws(() => checkRequest({ ...request, issuedAt: request.expiresAt + 1 }), RequestError);
});

test('T1.17: the SDK loads only the pinned PAN verification key', () => {
  const file = new URL('../../pan/artifacts/vk.json', import.meta.url);
  const pinned = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(crypto.createHash('sha256').update(loadPanVerificationKey(file)).digest('hex'), PAN_VK_SHA256);
  const changed = Buffer.from(pinned.vk, 'base64');
  changed[100] ^= 1;
  const copy = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-vk-')), 'vk.json');
  fs.writeFileSync(copy, JSON.stringify({ ...pinned, vk: changed.toString('base64') }));
  try {
    assert.throws(() => loadPanVerificationKey(pathToFileURL(copy)), new RegExp(`expected ${PAN_VK_SHA256}`));
  } finally {
    fs.rmSync(path.dirname(copy), { recursive: true });
  }
});

// ---- With proofs ----------------------------------------------------------------

const issuer = testIssuer();
const panKey = (window = {}) => ({ publicKey: issuer.publicKey, document: 'pan' as const, id: 'test-pan-key', ...window });
const registry = testRegistry([panKey()]);
const trusted = [testKey(issuer)];

type PanProof = { proof: string; publicInputs: string[] };
const requests: Record<string, ProofRequest> = {};
const proofs: Record<string, PanProof> = {};

// A proof for `request`, as the holder app makes it: the request's seed,
// signal hash and age cutoff, revealing the gender only under a gender rule.
async function proveFor(record: unknown, request: ProofRequest, options: { seedOf?: string; dobCutoff?: number } = {}): Promise<PanProof> {
  const input = circuitInput(record, {
    dobCutoff: options.dobCutoff ?? panDobCutoff(request.issuedAt),
    nullifierSeed: await nullifierSeedFor(options.seedOf ?? X),
    signalHash: await signalHashFor(request),
    revealGender: !!request.rules.gender,
  });
  const { proof, publicInputs } = await prove(input, { threads: 4 });
  return { proof: Buffer.from(proof).toString('base64'), publicInputs };
}

before(async () => {
  const issuing = createVerifier({ verifierId: X, registry, now: () => ISSUED_AT });
  const ask = (rules: Rules = { age19: true }, documents: Document[] = ['pan'], maxAgeSeconds = 7 * 86400) => issuing.createRequest({ maxAgeSeconds, rules, documents });
  const adult = await readRecord(await makeRecord(issuer, { dob: '01-01-1990', gender: 'FEMALE', uid: 'a'.repeat(32), verifiedOn: VERIFIED_ON }), trusted);
  const again = await readRecord(await makeRecord(issuer, { dob: '01-01-1990', gender: 'FEMALE', uid: 'a'.repeat(32), verifiedOn: '10-11-2026 09:00:00' }), trusted);
  const minor = await readRecord(await makeRecord(issuer, { dob: '12-11-2007', pan: 'TESTP0002T', verifiedOn: VERIFIED_ON }), trusted);
  const stale = await readRecord(await makeRecord(issuer, { pan: 'TESTP0003T', verifiedOn: '01-10-2026 12:00:00' }), trusted);

  requests.r1 = await ask();
  requests.r2 = await ask({ age19: true }, ['aadhaar', 'pan']);
  requests.r3 = await ask();
  requests.r4 = await ask({ age19: true, gender: ['F', 'T'] });
  requests.r5 = await ask({ age19: true, gender: ['M'] });
  requests.r6 = await ask({ age19: true }, ['aadhaar']);
  requests.r7 = await ask();
  requests.r8 = await ask();
  requests.r9 = await ask();
  proofs.p1 = await proveFor(adult, requests.r1);
  proofs.p2 = await proveFor(again, requests.r2); // the same person, a record verified the day before
  proofs.p3 = await proveFor(minor, requests.r3); // 19 tomorrow
  proofs.p4 = await proveFor(adult, requests.r4);
  proofs.p5 = await proveFor(adult, requests.r5); // reveals F; the rules accept M
  proofs.p6 = await proveFor(adult, requests.r6); // for a request that accepts only an Aadhaar QR
  proofs.p7 = await proveFor(adult, requests.r7, { dobCutoff: 99991231 }); // claims an age cutoff the request did not set
  proofs.p8 = await proveFor(adult, requests.r8, { seedOf: Y }); // the seed of another verifier
  proofs.p9 = await proveFor(stale, requests.r9); // verified by DigiLocker six weeks ago
});

function verifierAt(at: number, held: ProofRequest[], options: Partial<VerifierOptions> = {}) {
  const store = new MemoryStore();
  held.forEach((r) => store.putRequest(r));
  return createVerifier({ verifierId: X, registry, store, now: () => at, ...options });
}
const verifyAt = (at: number, p: PanProof, request: ProofRequest, options: Partial<VerifierOptions> = {}) =>
  verifierAt(at, [request], options).verify(p.proof, p.publicInputs, request, 'pan');

test('a valid PAN proof is accepted: the document, the key, the hour DigiLocker verified the PAN', async () => {
  const result = await verifyAt(VERIFY_AT, proofs.p1, requests.r1);
  assert.ok(result.ok, JSON.stringify(result));
  assert.equal(result.document, 'pan');
  assert.equal(result.issuerKeyId, 'test-pan-key');
  assert.equal(result.credentialTime, VERIFIED_HOUR);
  assert.deepEqual(result.disclosed, {});
  assert.ok(/^[0-9]+$/.test(result.nullifier));
});

test('T1.16: a gender rule: the proof reveals the gender, and it must be one the rules accept', async () => {
  const result = await verifyAt(VERIFY_AT, proofs.p4, requests.r4);
  assert.ok(result.ok, JSON.stringify(result));
  assert.deepEqual(result.disclosed, { gender: 'F' });
  expectFailure(await verifyAt(VERIFY_AT, proofs.p5, requests.r5), 'GENDER_NOT_ALLOWED');
});

test('T2.8: a PAN proof for a request that does not accept PAN records is refused, and does not use up the request', async () => {
  const verifier = verifierAt(VERIFY_AT, [requests.r6]);
  expectFailure(await verifier.verify(proofs.p6.proof, proofs.p6.publicInputs, requests.r6, 'pan'), 'DOCUMENT_NOT_ACCEPTED');
  expectFailure(await verifier.verify(proofs.p6.proof, proofs.p6.publicInputs, requests.r6, 'pan'), 'DOCUMENT_NOT_ACCEPTED');
  expectFailure(await verifier.verify(proofs.p6.proof, proofs.p6.publicInputs, requests.r6, 'passport' as Document), 'BAD_PROOF');
});

test('T2.7: binding: another request, another verifier, a used or expired request, another age cutoff', async () => {
  const verifier = verifierAt(VERIFY_AT, [requests.r1, requests.r3]);
  expectFailure(await verifier.verify(proofs.p1.proof, proofs.p1.publicInputs, requests.r3, 'pan'), 'CHALLENGE_MISMATCH');
  assert.equal((await verifier.verify(proofs.p1.proof, proofs.p1.publicInputs, requests.r1, 'pan')).ok, true);
  expectFailure(await verifier.verify(proofs.p1.proof, proofs.p1.publicInputs, requests.r1, 'pan'), 'CHALLENGE_REUSED');
  expectFailure(await verifyAt(requests.r1.expiresAt + 1, proofs.p1, requests.r1), 'CHALLENGE_EXPIRED');
  expectFailure(await verifyAt(VERIFY_AT, proofs.p1, { ...requests.r1, issuedAt: requests.r1.issuedAt - 86400 }), 'CHALLENGE_MISMATCH');
  expectFailure(await verifyAt(VERIFY_AT, proofs.p7, requests.r7), 'CHALLENGE_MISMATCH');
  expectFailure(await verifyAt(VERIFY_AT, proofs.p8, requests.r8), 'NULLIFIER_SEED_MISMATCH');
});

test('T7.7: BAD_PROOF: a changed proof or public input, or a malformed one; none uses up the request', async () => {
  const { proof, publicInputs } = proofs.p1;
  const verifier = verifierAt(VERIFY_AT, [requests.r1]);
  const bytes = Buffer.from(proof, 'base64');
  bytes[200] ^= 1;
  expectFailure(await verifier.verify(bytes.toString('base64'), publicInputs, requests.r1, 'pan'), 'BAD_PROOF');
  for (const i of [3, 4, 5, 6, 7]) {
    const changed = publicInputs.map((x, j) => (j === i ? `0x${(BigInt(x) ^ 1n).toString(16).padStart(64, '0')}` : x));
    expectFailure(await verifier.verify(proof, changed, requests.r1, 'pan'), 'BAD_PROOF');
  }
  for (const [p, inputs] of [
    ['not base64!', publicInputs],
    [proof, publicInputs.slice(1)],
    [proof, publicInputs.map((x) => x.toUpperCase())],
    [{ pi_a: [] }, publicInputs],
  ] as [unknown, unknown][]) {
    expectFailure(await verifier.verify(p, inputs, requests.r1, 'pan'), 'BAD_PROOF');
  }
  assert.equal((await verifier.verify(proof, publicInputs, requests.r1, 'pan')).ok, true, 'still accepted afterwards');
});

test('T1.12: the issuer: a key the registry does not trust for PAN records, or a record verified outside its window', async () => {
  const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  expectFailure(await verifyAt(VERIFY_AT, proofs.p1, requests.r1, { registry: testRegistry([{ publicKey, document: 'pan' }]) }), 'UNTRUSTED_ISSUER');
  // The same RSA key, trusted only for Aadhaar QRs, does not vouch for a PAN record.
  expectFailure(await verifyAt(VERIFY_AT, proofs.p1, requests.r1, { registry: testRegistry([{ publicKey: issuer.publicKey }]) }), 'UNTRUSTED_ISSUER');
  const window = testRegistry([panKey({ notBefore: VERIFIED_HOUR + 1 })]);
  expectFailure(await verifyAt(VERIFY_AT, proofs.p1, requests.r1, { registry: window }), 'ISSUER_KEY_NOT_VALID');
});

test('T1.15, T3.6, T4.4: age, freshness and one account per person', async () => {
  expectFailure(await verifyAt(VERIFY_AT, proofs.p3, requests.r3), 'AGE_NOT_PROVEN');
  expectFailure(await verifyAt(VERIFY_AT, proofs.p9, requests.r9), 'CREDENTIAL_TOO_OLD');
  const store = new MemoryStore();
  [requests.r1, requests.r2].forEach((r) => store.putRequest(r));
  // A nullifier already seen for an Aadhaar QR does not count against a PAN record.
  await store.addNullifier(BigInt(proofs.p1.publicInputs[4]).toString());
  const signup = createVerifier({ verifierId: X, registry, store, now: () => VERIFY_AT });
  assert.equal((await signup.verify(proofs.p1.proof, proofs.p1.publicInputs, requests.r1, 'pan')).ok, true);
  expectFailure(await signup.verify(proofs.p2.proof, proofs.p2.publicInputs, requests.r2, 'pan'), 'NULLIFIER_SEEN');
  const held = new MemoryStore();
  [requests.r1, requests.r2].forEach((r) => held.putRequest(r));
  const returning = createVerifier({ verifierId: X, registry, store: held, now: () => VERIFY_AT, onSeenNullifier: 'accept' });
  const first = await returning.verify(proofs.p1.proof, proofs.p1.publicInputs, requests.r1, 'pan');
  const second = await returning.verify(proofs.p2.proof, proofs.p2.publicInputs, requests.r2, 'pan');
  assert.ok(first.ok && first.newNullifier && second.ok && !second.newNullifier);
  assert.equal(first.nullifier, second.nullifier, "the same PAN and uid: the same code at this verifier, whichever day DigiLocker verified it");
});
