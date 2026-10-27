// Verifier side of zkID. A verifier creates single-use proof requests bound to
// its origin, and checks the holder's proof against the request, the issuer
// registry and its own state. Each failure is a typed code; nothing falls back
// silently. Design: docs/THREAT_MODEL.md, sections 1.1 and 1.2.

import crypto from 'node:crypto';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { checkRegistry, findKey, type Registry } from '../../issuer-registry/index.ts';
import { RequestError, checkVerifierId, nullifierSeedFor, signalHashFor, type ProofRequest } from './request.ts';
import { canonicalRules, checkRules, decodeOutputs, disclosedFor, ruleFailure, type Disclosed, type Rules } from './rules.ts';

export { RequestError, checkRequest, checkVerifierId, nullifierSeedFor, signalHashFor, type ProofRequest } from './request.ts';
export { GENDERS, checkRules, decodeOutputs, revealFor, ruleFailure, type Disclosed, type Gender, type Rules } from './rules.ts';

export const FAILURE_CODES = [
  'BAD_PROOF',
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
// proof revealed (rules.ts).
export type VerifyResult =
  | { ok: true; nullifier: string; newNullifier: boolean; issuerKeyId: string; credentialTime: number; disclosed: Disclosed }
  | { ok: false; code: FailureCode; detail: string };

// Anon Aadhaar's public signals, in snarkjs order.
export const PUBLIC_SIGNALS = ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pinCode', 'state', 'nullifierSeed', 'signalHash'] as const;
type Signals = Record<(typeof PUBLIC_SIGNALS)[number], string>;

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

const DECIMAL = /^[0-9]{1,78}$/;
const isPoint = (p: unknown, width: number) =>
  Array.isArray(p) && p.length === 3 && p.every((c) => (width === 1 ? typeof c === 'string' && DECIMAL.test(c) : isPoint2(c)));
const isPoint2 = (c: unknown) => Array.isArray(c) && c.length === 2 && c.every((x) => typeof x === 'string' && DECIMAL.test(x));
const isProof = (proof: unknown) => {
  const p = proof as { pi_a: unknown; pi_b: unknown; pi_c: unknown };
  return typeof p === 'object' && p !== null && isPoint(p.pi_a, 1) && isPoint(p.pi_b, 2) && isPoint(p.pi_c, 1);
};
const sameRequest = (a: ProofRequest, b: ProofRequest) =>
  a.version === b.version &&
  a.verifierId === b.verifierId &&
  a.challenge === b.challenge &&
  a.maxAgeSeconds === b.maxAgeSeconds &&
  a.expiresAt === b.expiresAt &&
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
}

export function createVerifier(options: VerifierOptions) {
  const verifierId = checkVerifierId(options.verifierId);
  const registry = checkRegistry(options.registry);
  const store = options.store ?? new MemoryStore();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const ttl = options.requestTtlSeconds ?? 300;
  const onSeenNullifier = options.onSeenNullifier ?? 'reject';
  const vkey = loadVerificationKey();
  const seed = nullifierSeedFor(verifierId);

  // `rules`: what the QR must show. A rule on gender, PIN code or state reveals
  // the holder's value of that field to this verifier (rules.ts).
  async function createRequest({ maxAgeSeconds, rules = { age19: true } }: { maxAgeSeconds: number; rules?: Rules }): Promise<ProofRequest> {
    if (!Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
      throw new RequestError('INVALID_REQUEST', 'maxAgeSeconds must be a positive whole number of seconds');
    }
    const request: ProofRequest = {
      version: 2,
      verifierId,
      challenge: crypto.randomBytes(32).toString('hex'),
      maxAgeSeconds,
      expiresAt: now() + ttl,
      rules: structuredClone(checkRules(rules)),
    };
    await store.putRequest(request);
    return request;
  }

  // `request` is the one this verifier issued for the session that sent the proof.
  async function verify(proof: unknown, publicSignals: unknown, request: ProofRequest): Promise<VerifyResult> {
    const fail = (code: FailureCode, detail: string): VerifyResult => ({ ok: false, code, detail });

    if (!isProof(proof) || !Array.isArray(publicSignals) || publicSignals.length !== PUBLIC_SIGNALS.length || !publicSignals.every((s) => typeof s === 'string' && DECIMAL.test(s))) {
      return fail('BAD_PROOF', 'malformed proof or public signals');
    }
    const s = Object.fromEntries(PUBLIC_SIGNALS.map((name, i) => [name, publicSignals[i]])) as Signals;

    // 1. Bound to this request and this verifier.
    let expectedSignal: string;
    try {
      expectedSignal = await signalHashFor(request);
    } catch {
      return fail('CHALLENGE_MISMATCH', 'the request is malformed');
    }
    if (request.verifierId !== verifierId) return fail('CHALLENGE_MISMATCH', 'the request names another verifier');
    if (s.signalHash !== expectedSignal) return fail('CHALLENGE_MISMATCH', 'the proof was made for another request');
    if (s.nullifierSeed !== (await seed)) return fail('NULLIFIER_SEED_MISMATCH', "the proof uses another verifier's nullifier seed");

    // 2. A request this verifier issued, unused and unexpired.
    const stored = await store.getRequest(request.challenge);
    if (!stored || !sameRequest(stored.request, request)) return fail('CHALLENGE_MISMATCH', 'this verifier did not issue the request');
    if (stored.used) return fail('CHALLENGE_REUSED', 'the request was already answered');
    if (now() > request.expiresAt) return fail('CHALLENGE_EXPIRED', 'the request has expired');

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

    // 4. What the proof says.
    const key = findKey(registry, s.pubkeyHash);
    if (!key) return fail('UNTRUSTED_ISSUER', 'the QR was signed by a key that is not in the registry');
    const credentialTime = Number(s.timestamp);
    if (credentialTime < key.notBefore || credentialTime > key.notAfter) {
      return fail('ISSUER_KEY_NOT_VALID', `the QR's generation time is outside the validity of key ${key.id}`);
    }
    if (request.rules.age19 && s.ageAbove18 !== '1') {
      return fail('AGE_NOT_PROVEN', 'the proof does not show a completed age above 18 (19 or older) when the QR was generated');
    }
    const disclosed = disclosedFor(request.rules, decodeOutputs(s));
    const broken = ruleFailure(request.rules, disclosed);
    if (broken) return fail(broken, RULE_DETAIL[broken]);
    if (now() - credentialTime > request.maxAgeSeconds) return fail('CREDENTIAL_TOO_OLD', 'the QR is older than the request allows');

    // 5. One account per person per verifier.
    const newNullifier = await store.addNullifier(s.nullifier);
    if (!newNullifier && onSeenNullifier === 'reject') return fail('NULLIFIER_SEEN', 'this person already has an account here');
    return { ok: true, nullifier: s.nullifier, newNullifier, issuerKeyId: key.id, credentialTime, disclosed };
  }

  return { verifierId, createRequest, verify };
}

// snarkjs keeps worker threads for the curve; call this before the process exits.
export async function close(): Promise<void> {
  const g = globalThis as { curve_bn128?: { terminate(): Promise<void> } };
  await g.curve_bn128?.terminate();
  delete g.curve_bn128;
}
