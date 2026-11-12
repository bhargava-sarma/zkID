// Verifier side of zkID. A verifier creates single-use proof requests bound to
// its origin, and checks the holder's proof against the request, the issuer
// registry and its own state: a Groth16 proof of an Aadhaar Secure QR (Anon
// Aadhaar's circuit), or an UltraHonk proof of a DigiLocker PAN Verification
// Record (packages/pan). Each failure is a typed code; nothing falls back
// silently. Design: docs/THREAT_MODEL.md, sections 1.1 and 1.2.

import crypto from 'node:crypto';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { checkRegistry, findKey, type IssuerKey, type Registry } from '../../issuer-registry/index.ts';
import { istHourToUnix, publicValues, PUBLIC_INPUTS as PAN_PUBLIC_INPUTS } from '../../pan/public.mjs';
import { closeVerifier as closePanVerifier, ready as panVerifierReady, verifyProof as verifyPanProof } from '../../pan/verify.mjs';
import { DOCUMENTS, RequestError, checkDocuments, checkRequest, checkVerifierId, nullifierSeedFor, signalHashFor, type Document, type ProofRequest } from './request.ts';
import { canonicalRules, checkRules, decodeOutputs, disclosedFor, panDobCutoff, ruleFailure, type Disclosed, type Rules } from './rules.ts';

export { DOCUMENTS, RequestError, checkDocuments, checkRequest, checkVerifierId, nullifierSeedFor, signalHashFor, type Document, type ProofRequest } from './request.ts';
export { GENDERS, checkRules, decodeOutputs, panDobCutoff, revealFor, ruleFailure, type Disclosed, type Gender, type Rules } from './rules.ts';

export const FAILURE_CODES = [
  'BAD_PROOF',
  'DOCUMENT_NOT_ACCEPTED',
  'CHALLENGE_MISMATCH',
  'NULLIFIER_SEED_MISMATCH',
  'CHALLENGE_REUSED',
  'CHALLENGE_EXPIRED',
  'UNTRUSTED_ISSUER',
  'ISSUER_KEY_NOT_VALID',
  'AGE_NOT_PROVEN',
  'GENDER_NOT_ALLOWED',
  'PIN_CODE_NOT_ALLOWED',
  'STATE_NOT_ALLOWED',
  'CREDENTIAL_TOO_OLD',
  'NULLIFIER_SEEN',
] as const;
export type FailureCode = (typeof FAILURE_CODES)[number];

// `disclosed`: the values of the fields the request's rules name, which the
// proof revealed (rules.ts). `credentialTime`: when the credential was made,
// to the hour: an Aadhaar QR's generation, a PAN record's verification.
export type VerifyResult =
  | { ok: true; document: Document; nullifier: string; newNullifier: boolean; issuerKeyId: string; credentialTime: number; disclosed: Disclosed }
  | { ok: false; code: FailureCode; detail: string };

// Anon Aadhaar's public signals, in snarkjs order.
export const PUBLIC_SIGNALS = ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pinCode', 'state', 'nullifierSeed', 'signalHash'] as const;
type Signals = Record<(typeof PUBLIC_SIGNALS)[number], string>;
// The PAN circuit's public inputs, in Barretenberg's order (packages/pan/public.mjs).
export { PAN_PUBLIC_INPUTS };
type PanValues = Record<(typeof PAN_PUBLIC_INPUTS)[number], string>;

// The verifier's state. take/add must be atomic in a shared store.
export interface Store {
  putRequest(request: ProofRequest): Promise<void>;
  getRequest(challenge: string): Promise<{ request: ProofRequest; used: boolean } | undefined>;
  useChallenge(challenge: string): Promise<boolean>; // false if it was already used
  addNullifier(nullifier: string): Promise<boolean>; // false if it was already there
}

export class MemoryStore implements Store {
  private requests = new Map<string, { request: ProofRequest; used: boolean }>();
  private nullifiers = new Set<string>();
  async putRequest(request: ProofRequest) {
    this.requests.set(request.challenge, { request: { ...request }, used: false });
  }
  async getRequest(challenge: string) {
    const entry = this.requests.get(challenge);
    return entry && { request: { ...entry.request }, used: entry.used };
  }
  async useChallenge(challenge: string) {
    const entry = this.requests.get(challenge);
    if (!entry || entry.used) return false;
    entry.used = true;
    return true;
  }
  async addNullifier(nullifier: string) {
    if (this.nullifiers.has(nullifier)) return false;
    this.nullifiers.add(nullifier);
    return true;
  }
}

// Anon Aadhaar v2.0.0's verification key, pinned (packages/circuit/artifacts.json).
const VKEY_SHA256 = '40f2ea24b56ffe2b6e6e3578053cbda15e773cb560697bac883a404077fcf177';
function loadVerificationKey(): unknown {
  const bytes = fs.readFileSync(new URL('../vkey.json', import.meta.url));
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  if (digest !== VKEY_SHA256) throw new Error(`vkey.json has SHA-256 ${digest}, expected ${VKEY_SHA256}.`);
  return JSON.parse(bytes.toString('utf8'));
}

// The PAN circuit's UltraHonk verification key, pinned (packages/pan/build.mjs
// makes it from the circuit; CI checks it still does).
const PAN_VK_SHA256 = '264ce5ceb9e566b56a08c8d18bb0536eb3d11832430b22d8550450c5aa26d27c';
function loadPanVerificationKey(): Uint8Array {
  const { vk } = JSON.parse(fs.readFileSync(new URL('../../pan/artifacts/vk.json', import.meta.url), 'utf8')) as { vk: string };
  const bytes = Buffer.from(vk, 'base64');
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  if (digest !== PAN_VK_SHA256) throw new Error(`packages/pan/artifacts/vk.json holds a key with SHA-256 ${digest}, expected ${PAN_VK_SHA256}.`);
  return bytes;
}

const DECIMAL = /^[0-9]{1,78}$/;
const isPoint = (p: unknown, width: number) =>
  Array.isArray(p) && p.length === 3 && p.every((c) => (width === 1 ? typeof c === 'string' && DECIMAL.test(c) : isPoint2(c)));
const isPoint2 = (c: unknown) => Array.isArray(c) && c.length === 2 && c.every((x) => typeof x === 'string' && DECIMAL.test(x));
const isProof = (proof: unknown) => {
  const p = proof as { pi_a: unknown; pi_b: unknown; pi_c: unknown };
  return typeof p === 'object' && p !== null && isPoint(p.pi_a, 1) && isPoint(p.pi_b, 2) && isPoint(p.pi_c, 1);
};
// A PAN proof travels as base64; its public inputs as 32-byte hex strings.
const isPanProof = (proof: unknown) => typeof proof === 'string' && proof.length <= 64 * 1024 && /^[A-Za-z0-9+/]+={0,2}$/.test(proof);
const isPanInputs = (inputs: unknown) =>
  Array.isArray(inputs) && inputs.length === PAN_PUBLIC_INPUTS.length && inputs.every((x) => typeof x === 'string' && /^0x[0-9a-f]{64}$/.test(x));
const sameRequest = (a: ProofRequest, b: ProofRequest) =>
  a.version === b.version &&
  a.verifierId === b.verifierId &&
  a.challenge === b.challenge &&
  a.issuedAt === b.issuedAt &&
  a.maxAgeSeconds === b.maxAgeSeconds &&
  a.expiresAt === b.expiresAt &&
  a.documents.join(',') === b.documents.join(',') &&
  canonicalRules(a.rules) === canonicalRules(b.rules);

const RULE_DETAIL = {
  GENDER_NOT_ALLOWED: "the proof does not show a gender the request's rules accept",
  PIN_CODE_NOT_ALLOWED: "the proof does not show a PIN code the request's rules accept",
  STATE_NOT_ALLOWED: "the proof does not show a state the request's rules accept",
};

export interface VerifierOptions {
  verifierId: string; // this verifier's origin
  registry: Registry; // productionRegistry() in production; the build checks it has no test keys
  store?: Store; // default: in memory
  now?: () => number; // Unix seconds
  requestTtlSeconds?: number; // default 300
  onSeenNullifier?: 'reject' | 'accept'; // 'reject' for sign-up (default), 'accept' for returning users
  crsPath?: string; // where PAN verification keeps Barretenberg's setup points (packages/pan/verify.mjs); default ~/.bb-crs
}

export function createVerifier(options: VerifierOptions) {
  const verifierId = checkVerifierId(options.verifierId);
  const registry = checkRegistry(options.registry);
  const store = options.store ?? new MemoryStore();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const ttl = options.requestTtlSeconds ?? 300;
  const onSeenNullifier = options.onSeenNullifier ?? 'reject';
  const vkey = loadVerificationKey();
  const panVk = loadPanVerificationKey();
  const seed = nullifierSeedFor(verifierId);

  // `rules`: what the credential must show; `documents`: which credentials are
  // accepted. A rule on gender, PIN code or state reveals the holder's value of
  // that field to this verifier (rules.ts). Rules on PIN code or state need
  // documents: ['aadhaar'] (a PAN record has no address).
  async function createRequest({
    maxAgeSeconds,
    rules = { age19: true },
    documents = ['aadhaar'],
  }: {
    maxAgeSeconds: number;
    rules?: Rules;
    documents?: Document[];
  }): Promise<ProofRequest> {
    if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
      throw new RequestError('INVALID_REQUEST', 'maxAgeSeconds must be a positive whole number of seconds');
    }
    const issuedAt = now();
    const request: ProofRequest = {
      version: 3,
      verifierId,
      challenge: crypto.randomBytes(32).toString('hex'),
      issuedAt,
      maxAgeSeconds,
      expiresAt: issuedAt + ttl,
      documents: structuredClone(checkDocuments(documents)),
      rules: structuredClone(checkRules(rules)),
    };
    checkRequest(request);
    await store.putRequest(request);
    return request;
  }

  const fail = (code: FailureCode, detail: string): VerifyResult => ({ ok: false, code, detail });

  // 1 and 2, for either document: the proof is bound to this request and this
  // verifier, and the request is one this verifier issued, unused, unexpired,
  // that accepts this document. Returns a failure, or null.
  async function checkBinding(signalHash: string, nullifierSeed: string, request: ProofRequest, document: Document): Promise<VerifyResult | null> {
    let expectedSignal: string;
    try {
      expectedSignal = await signalHashFor(request);
    } catch {
      return fail('CHALLENGE_MISMATCH', 'the request is malformed');
    }
    if (request.verifierId !== verifierId) return fail('CHALLENGE_MISMATCH', 'the request names another verifier');
    if (signalHash !== expectedSignal) return fail('CHALLENGE_MISMATCH', 'the proof was made for another request');
    if (nullifierSeed !== (await seed)) return fail('NULLIFIER_SEED_MISMATCH', "the proof uses another verifier's nullifier seed");

    const stored = await store.getRequest(request.challenge);
    if (!stored || !sameRequest(stored.request, request)) return fail('CHALLENGE_MISMATCH', 'this verifier did not issue the request');
    if (stored.used) return fail('CHALLENGE_REUSED', 'the request was already answered');
    if (now() > request.expiresAt) return fail('CHALLENGE_EXPIRED', 'the request has expired');
    if (!request.documents.includes(document)) return fail('DOCUMENT_NOT_ACCEPTED', `the request does not accept a proof of ${document === 'pan' ? 'a PAN record' : 'an Aadhaar QR'}`);
    return null;
  }

  // 4 and 5, for either document, once the proof has verified and the request
  // is used up: the issuer key, the credential's time, the rules, and one
  // account per person.
  async function decide(
    request: ProofRequest,
    document: Document,
    out: { pubkeyHash: string; credentialTime: number; ageShown: boolean; disclosed: Disclosed; nullifier: string },
  ): Promise<VerifyResult> {
    const key: IssuerKey | undefined = findKey(registry, out.pubkeyHash, document);
    if (!key) return fail('UNTRUSTED_ISSUER', `the ${document === 'pan' ? 'record' : 'QR'} was signed by a key that is not in the registry`);
    if (out.credentialTime < key.notBefore || out.credentialTime > key.notAfter) {
      return fail('ISSUER_KEY_NOT_VALID', `the ${document === 'pan' ? "record's verification" : "QR's generation"} time is outside the validity of key ${key.id}`);
    }
    if (request.rules.age19 && !out.ageShown) {
      return fail(
        'AGE_NOT_PROVEN',
        document === 'pan'
          ? "the proof does not show a date of birth 19 or more years before the request's day"
          : 'the proof does not show a completed age above 18 (19 or older) when the QR was generated',
      );
    }
    const disclosed = disclosedFor(request.rules, out.disclosed);
    const broken = ruleFailure(request.rules, disclosed);
    if (broken) return fail(broken, RULE_DETAIL[broken]);
    if (now() - out.credentialTime > request.maxAgeSeconds) {
      return fail('CREDENTIAL_TOO_OLD', document === 'pan' ? "the record's verification by DigiLocker is older than the request allows" : 'the QR is older than the request allows');
    }

    // One account per person per verifier, per document: the two circuits'
    // nullifiers are unrelated (THREAT_MODEL A4.7).
    const newNullifier = await store.addNullifier(document === 'pan' ? `pan:${out.nullifier}` : out.nullifier);
    if (!newNullifier && onSeenNullifier === 'reject') return fail('NULLIFIER_SEEN', 'this person already has an account here');
    return { ok: true, document, nullifier: out.nullifier, newNullifier, issuerKeyId: key.id, credentialTime: out.credentialTime, disclosed };
  }

  async function verifyAadhaar(proof: unknown, publicSignals: unknown, request: ProofRequest): Promise<VerifyResult> {
    if (!isProof(proof) || !Array.isArray(publicSignals) || publicSignals.length !== PUBLIC_SIGNALS.length || !publicSignals.every((s) => typeof s === 'string' && DECIMAL.test(s))) {
      return fail('BAD_PROOF', 'malformed proof or public signals');
    }
    const s = Object.fromEntries(PUBLIC_SIGNALS.map((name, i) => [name, publicSignals[i]])) as Signals;
    const unbound = await checkBinding(s.signalHash, s.nullifierSeed, request, 'aadhaar');
    if (unbound) return unbound;

    // 3. The proof itself.
    let valid = false;
    try {
      valid = await snarkjs.groth16.verify(vkey, publicSignals as string[], proof);
    } catch {
      valid = false; // points not on the curve, for example; reported as BAD_PROOF below
    }
    if (!valid) return fail('BAD_PROOF', 'Groth16 verification failed');

    // One decision per request, from here on, whatever it is.
    if (!(await store.useChallenge(request.challenge))) return fail('CHALLENGE_REUSED', 'the request was already answered');
    return decide(request, 'aadhaar', {
      pubkeyHash: s.pubkeyHash,
      credentialTime: Number(s.timestamp),
      ageShown: s.ageAbove18 === '1',
      disclosed: decodeOutputs(s),
      nullifier: s.nullifier,
    });
  }

  async function verifyPan(proof: unknown, publicInputs: unknown, request: ProofRequest): Promise<VerifyResult> {
    if (!isPanProof(proof) || !isPanInputs(publicInputs)) return fail('BAD_PROOF', 'malformed proof or public inputs');
    const inputs = publicInputs as string[];
    const v = publicValues(inputs) as PanValues;
    const unbound = await checkBinding(v.signalHash, v.nullifierSeed, request, 'pan');
    if (unbound) return unbound;
    if (v.dobCutoff !== String(panDobCutoff(request.issuedAt))) return fail('CHALLENGE_MISMATCH', "the proof uses another date-of-birth cutoff than the request's");

    // 3. The proof itself. Barretenberg's own failures are the verifier's, not the proof's.
    await panVerifierReady({ crsPath: options.crsPath });
    let valid = false;
    try {
      valid = await verifyPanProof({ proof: Buffer.from(proof as string, 'base64'), publicInputs: inputs }, panVk, { crsPath: options.crsPath });
    } catch {
      valid = false; // a proof Barretenberg cannot read; reported as BAD_PROOF below
    }
    if (!valid) return fail('BAD_PROOF', 'UltraHonk verification failed');

    if (!(await store.useChallenge(request.challenge))) return fail('CHALLENGE_REUSED', 'the request was already answered');
    return decide(request, 'pan', {
      pubkeyHash: v.pubkeyHash,
      credentialTime: istHourToUnix(v.verifiedHour),
      ageShown: v.bornBy === '1',
      disclosed: decodeOutputs({ gender: v.gender, pinCode: '0', state: '0' }),
      nullifier: v.nullifier,
    });
  }

  // `request` is the one this verifier issued for the session that sent the
  // proof; `document` says which circuit made it. An Aadhaar proof is snarkjs's
  // proof object and its public signals; a PAN proof is the proof's bytes in
  // base64 and its public inputs.
  async function verify(proof: unknown, publicSignals: unknown, request: ProofRequest, document: Document = 'aadhaar'): Promise<VerifyResult> {
    if (!DOCUMENTS.includes(document)) return fail('BAD_PROOF', `unknown document ${String(document)}`);
    return document === 'pan' ? verifyPan(proof, publicSignals, request) : verifyAadhaar(proof, publicSignals, request);
  }

  return { verifierId, createRequest, verify };
}

// snarkjs keeps worker threads for the curve, and Barretenberg a worker; call
// this before the process exits.
export async function close(): Promise<void> {
  const g = globalThis as { curve_bn128?: { terminate(): Promise<void> } };
  await g.curve_bn128?.terminate();
  delete g.curve_bn128;
  await closePanVerifier();
}
