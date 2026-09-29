// The relying-party policy, off-chain: the same checks ZkIdPolicy makes on-chain.
import { bigIntToLimbs, issuerKeyId } from './proofCode.js';
import { TRUSTED_ISSUERS } from './trustedIssuers.js';

export const MINIMUM_AGE_YEARS = 18;

// Latest birth date that is 18 or older today: year*10000 + month*100 + day in
// UTC, minus 18 years. The same arithmetic as the backend and ZkIdPolicy.
export function cutoffDate(now = new Date()) {
  const today = now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();
  return today - MINIMUM_AGE_YEARS * 10000;
}

export function formatDate(yyyymmdd) {
  const s = String(yyyymmdd).padStart(8, '0');
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6)}`;
}

let trusted = null;

// Trusted issuers with their circuit limbs and key IDs.
export function trustedIssuerKeys(issuers = TRUSTED_ISSUERS) {
  const compute = () =>
    Promise.all(
      issuers.map(async ({ name, modulusHex }) => {
        const limbs = bigIntToLimbs(BigInt(`0x${modulusHex}`));
        return { name, limbs, keyId: await issuerKeyId(limbs) };
      })
    );
  if (issuers !== TRUSTED_ISSUERS) return compute();
  trusted ??= compute();
  return trusted;
}

// The issuer behind a proof's public signals (the first 17 are its key):
// { keyId, name } with name null when the key isn't trusted.
export async function issuerOf(publicSignals) {
  const keyId = await issuerKeyId(publicSignals.slice(0, 17));
  const match = (await trustedIssuerKeys()).find((i) => i.keyId === keyId);
  return { keyId, name: match ? match.name : null };
}
