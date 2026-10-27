// What a verifier asks for, and the two values a proof commits to: the
// nullifier seed (one per verifier) and the signal hash (one per request).
// Shared by the verifier SDK and the holder app, so it uses only Web APIs.

import { RequestError } from './errors.ts';
import { canonicalRules, checkRules, type Rules } from './rules.ts';

export { RequestError } from './errors.ts';

export interface ProofRequest {
  version: 2;
  verifierId: string; // the verifier's origin, e.g. https://shop.example (THREAT_MODEL decision 1)
  challenge: string; // 32 random bytes, hex
  maxAgeSeconds: number; // oldest QR accepted, by its generation time
  expiresAt: number; // Unix seconds; the request is void after this
  rules: Rules; // what the QR must show (rules.ts)
}

const LOCAL_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

// An origin: https://host[:port], or http on localhost for development.
export function checkVerifierId(id: string): string {
  let url: URL;
  try {
    url = new URL(id);
  } catch {
    throw new RequestError('INVALID_VERIFIER_ID', 'not a URL');
  }
  const secure = url.protocol === 'https:' || (url.protocol === 'http:' && LOCAL_HOSTS.includes(url.hostname));
  if (url.origin !== id || !secure) {
    throw new RequestError('INVALID_VERIFIER_ID', `${id} is not an https origin (e.g. https://shop.example)`);
  }
  return id;
}

export function checkRequest(request: unknown): ProofRequest {
  const r = request as ProofRequest;
  const ok =
    typeof r === 'object' &&
    r !== null &&
    r.version === 2 &&
    typeof r.challenge === 'string' &&
    /^[0-9a-f]{64}$/.test(r.challenge) &&
    Number.isSafeInteger(r.maxAgeSeconds) &&
    r.maxAgeSeconds > 0 &&
    Number.isSafeInteger(r.expiresAt) &&
    r.expiresAt > 0;
  if (!ok) throw new RequestError('INVALID_REQUEST', 'malformed proof request');
  checkVerifierId(r.verifierId);
  checkRules(r.rules);
  return r;
}

// SHA-256 of a domain-separated string, cut to 31 bytes so it is always below
// the BN254 scalar field. Returned in decimal, as snarkjs writes signals.
async function fieldHash(domain: string, text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${domain}\0${text}`)));
  let value = 0n;
  for (const byte of digest.subarray(0, 31)) value = (value << 8n) | BigInt(byte);
  return value.toString();
}

// The same for every request of a verifier, so its nullifiers stay stable.
export const nullifierSeedFor = (verifierId: string): Promise<string> =>
  fieldHash('zkid/v1/nullifier-seed', checkVerifierId(verifierId));

// Binds a proof to one request: any change to any field, rules included, changes it.
export function signalHashFor(request: ProofRequest): Promise<string> {
  const r = checkRequest(request);
  return fieldHash('zkid/v2/request', [r.version, r.verifierId, r.challenge, r.maxAgeSeconds, r.expiresAt, canonicalRules(r.rules)].join('\n'));
}
