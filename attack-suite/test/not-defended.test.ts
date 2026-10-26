// Phase 6: the attacks docs/THREAT_MODEL.md says zkID does not defend, or only
// partly, shown working with real proofs: T2.6, T3.1, T3.4, T4.2, T4.3, T5.2
// and T5.3. A passing test here means the attack succeeds, as documented.
// The defended rows are tested in the packages; docs/ATTACK_REPORT.md lists
// them all.
//
// Every QR is synthetic, signed with an ephemeral test key. Run: npm test (the
// circuit artifacts must be fetched: cd ../packages/circuit && npm run fetch).
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { MemoryStore, close, createVerifier, nullifierSeedFor, signalHashFor, type ProofRequest, type VerifyResult } from '../../packages/verifier-sdk/src/index.ts';
import { testRegistry } from '../../packages/issuer-registry/index.ts';
import { DEFAULT_DIR, buildInput, close as closeCircuit, keyHash, prove, witness } from '../../packages/circuit/index.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../packages/secure-qr/synthetic.mjs';

const ARTIFACTS = process.env.AA_ARTIFACTS || DEFAULT_DIR;
const HAVE_ARTIFACTS = ['aadhaar-verifier.wasm', 'circuit_final.zkey'].every((f) => fs.existsSync(path.join(ARTIFACTS, f)));
const NEEDS_PROOFS = HAVE_ARTIFACTS ? {} : { skip: 'circuit artifacts missing: cd ../packages/circuit && npm run fetch' };
after(async () => {
  await close();
  await closeCircuit();
});

const A = 'https://shop.example';
const B = 'https://other.example';
const G = Date.parse('2026-10-26T04:30:00Z') / 1000; // the QRs' generation time (10:00 IST)
const ISSUED_AT = G + 600; // when the verifiers made their requests
const VERIFY_AT = ISSUED_AT + 60;
const MAX_AGE = 7 * 86400;

// UIDAI stand-in: an ephemeral key, trusted by the verifiers through a test registry.
const issuer = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const registry = testRegistry([{ id: 'test-key', publicKey: issuer.publicKey, keyHash: keyHash(issuer.publicKey) }]);

// The holder's QR. Each test changes only what its attack needs.
const photo = syntheticPhoto(900);
const trailing = unknownTrailer(27);
const qr = ({ version = 'V5', photoBytes = photo, trailingBytes = trailing, fields = {} }: { version?: string; photoBytes?: Buffer; trailingBytes?: Buffer; fields?: Record<string, string> } = {}) =>
  makeSyntheticSecureQr(issuer.privateKey, { version, photo: photoBytes, trailing: trailingBytes, fields: syntheticFields({ generatedAt: new Date(G * 1000), ...fields }) }).text;

type Proof = { proof: unknown; publicSignals: string[] };
const requests: Record<string, ProofRequest> = {};
const proofs: Record<string, Proof> = {};

// Anyone holding a QR can make this proof: the QR, the request and UIDAI's public key are all it takes.
const proveFor = async (text: string, request: ProofRequest): Promise<Proof> =>
  prove(buildInput(text, issuer.publicKey, { nullifierSeed: await nullifierSeedFor(request.verifierId), signalHash: await signalHashFor(request) }), { dir: ARTIFACTS });

before(async () => {
  if (!HAVE_ARTIFACTS) return;
  const [atA, atB] = [A, B].map((verifierId) => createVerifier({ verifierId, registry, now: () => ISSUED_AT }));
  for (const name of ['a1', 'a2', 'a3', 'a4']) requests[name] = await atA.createRequest({ maxAgeSeconds: MAX_AGE });
  requests.b1 = await atB.createRequest({ maxAgeSeconds: MAX_AGE });
  proofs.holderA = await proveFor(qr(), requests.a1); // the holder, at A
  proofs.lentA = await proveFor(qr(), requests.a2); // someone else, with a copy of the holder's QR, at A
  proofs.newPhotoA = await proveFor(qr({ photoBytes: syntheticPhoto(900) }), requests.a3); // the holder after a photo update
  proofs.longerA = await proveFor(qr({ fields: { street: 'TEST STREET2' } }), requests.a4); // after an address update: one byte longer
  proofs.holderB = await proveFor(qr(), requests.b1); // the holder, at B
});

// A verifier at `verifierId` that issued the given requests; one per test, so each starts with no accounts.
function verifier(verifierId: string, issued: ProofRequest[]) {
  const store = new MemoryStore();
  issued.forEach((r) => store.putRequest(r));
  return createVerifier({ verifierId, registry, store, now: () => VERIFY_AT });
}
const accepted = (result: VerifyResult) => {
  assert.ok(result.ok, result.ok ? '' : `${result.code}: ${result.detail}`);
  return result;
};
const signal = (p: Proof, name: 'pubkeyHash' | 'nullifier' | 'timestamp') => p.publicSignals[{ pubkeyHash: 0, nullifier: 1, timestamp: 2 }[name]];

test("T2.6: a victim's proof answers the attacker's request, and the attacker's session gets the account (A2.5)", NEEDS_PROOFS, async () => {
  // The attacker opens a session at A and relays A's request a1 to the victim,
  // who proves it. The proof is bound to the request, and nothing in it names
  // the session that asked.
  const result = accepted(await verifier(A, [requests.a1]).verify(proofs.holderA.proof, proofs.holderA.publicSignals, requests.a1));
  assert.equal(result.newNullifier, true);
});

test("T3.1: whoever holds a copy of an adult's QR gets that adult's account at a site, and the adult is then refused (A3.1, A3.3)", NEEDS_PROOFS, async () => {
  const site = verifier(A, [requests.a1, requests.a2]);
  const lent = accepted(await site.verify(proofs.lentA.proof, proofs.lentA.publicSignals, requests.a2));
  assert.equal(lent.newNullifier, true);
  // One account per QR per site holds; it is the first prover's.
  const owner = await site.verify(proofs.holderA.proof, proofs.holderA.publicSignals, requests.a1);
  assert.equal(owner.ok ? 'accepted' : owner.code, 'NULLIFIER_SEEN');
});

test('T3.4: the same person after a photo update gets a new nullifier, so a second account (A3.4, A4.4)', NEEDS_PROOFS, async () => {
  const site = verifier(A, [requests.a1, requests.a3]);
  const before = accepted(await site.verify(proofs.holderA.proof, proofs.holderA.publicSignals, requests.a1));
  const after = accepted(await site.verify(proofs.newPhotoA.proof, proofs.newPhotoA.publicSignals, requests.a3));
  assert.notEqual(after.nullifier, before.nullifier);
  assert.equal(after.newNullifier, true);
});

test('T4.3: one field one byte longer, as after an address update, gives a new nullifier and a second account; the same length does not (A4.6)', NEEDS_PROOFS, async () => {
  // The nullifier covers the SHA-256 padding after the photo, and the padding
  // encodes the signed data's length.
  const site = verifier(A, [requests.a1, requests.a4]);
  const before = accepted(await site.verify(proofs.holderA.proof, proofs.holderA.publicSignals, requests.a1));
  const after = accepted(await site.verify(proofs.longerA.proof, proofs.longerA.publicSignals, requests.a4));
  assert.notEqual(after.nullifier, before.nullifier);
  assert.equal(after.newNullifier, true);
  // Control: a change that keeps every length gives the same nullifier.
  const seedA = await nullifierSeedFor(A);
  const nullifierOf = async (text: string) => (await witness(buildInput(text, issuer.publicKey, { nullifierSeed: seedA, signalHash: 1n }), { dir: ARTIFACTS })).nullifier;
  assert.equal(await nullifierOf(qr({ fields: { street: 'TEST ROAD!!' } })), before.nullifier); // 'TEST STREET' has 11 bytes too
});

test('T4.2: the same photo after V1-style 64 trailing bytes or V5-style 27 gives two nullifiers; a V1 code cannot be proved at all (A4.3)', NEEDS_PROOFS, async () => {
  const seedA = await nullifierSeedFor(A);
  const nullifierOf = async (text: string) => (await witness(buildInput(text, issuer.publicKey, { nullifierSeed: seedA, signalHash: 1n }), { dir: ARTIFACTS })).nullifier;
  // V1 codes carry the mobile and email hashes (64 bytes) after the photo; Anon
  // Aadhaar's V2 test data, converted from V1, still does. With 64 bytes after
  // it, a 900-byte photo no longer fits the circuit (PHOTO_TOO_LARGE), so this
  // uses a smaller one in both codes.
  const v1Trailer = unknownTrailer(64);
  const samePhoto = syntheticPhoto(850);
  const v2 = await nullifierOf(qr({ version: 'V2', photoBytes: samePhoto, trailingBytes: v1Trailer }));
  const v5 = await nullifierOf(qr({ photoBytes: samePhoto }));
  assert.notEqual(v2, v5);
  assert.throws(() => buildInput(qr({ version: 'V1', trailingBytes: v1Trailer }), issuer.publicKey, { nullifierSeed: seedA, signalHash: 1n }), (e: { code?: string }) => e.code === 'UNSUPPORTED_LAYOUT');
});

test("T5.2: anyone with a copy of the QR computes the holder's nullifier at any site, offline (A5.2)", NEEDS_PROOFS, async () => {
  // The holder proves to B. With only the QR copy and UIDAI's public key, the
  // circuit's witness generator gives the same nullifier: no proof, no
  // interaction with the holder or with B.
  const atB = accepted(await verifier(B, [requests.b1]).verify(proofs.holderB.proof, proofs.holderB.publicSignals, requests.b1));
  const copy = qr();
  const offline = await witness(buildInput(copy, issuer.publicKey, { nullifierSeed: await nullifierSeedFor(B), signalHash: 1n }), { dir: ARTIFACTS });
  assert.equal(offline.nullifier, atB.nullifier);
});

test('T5.3: the same QR at two sites shows the same generation hour and key hash, so colluding sites can match it (A5.3, A6.3)', NEEDS_PROOFS, async () => {
  const atA = accepted(await verifier(A, [requests.a1]).verify(proofs.holderA.proof, proofs.holderA.publicSignals, requests.a1));
  const atB = accepted(await verifier(B, [requests.b1]).verify(proofs.holderB.proof, proofs.holderB.publicSignals, requests.b1));
  assert.notEqual(atA.nullifier, atB.nullifier); // unlinkable by nullifier (T5.1)...
  assert.equal(signal(proofs.holderA, 'timestamp'), signal(proofs.holderB, 'timestamp')); // ...but not by these
  assert.equal(signal(proofs.holderA, 'pubkeyHash'), signal(proofs.holderB, 'pubkeyHash'));
});
