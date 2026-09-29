import { bigIntToLimbs, decodeProofCode, issuerKeyId } from './proofCode.js';
import { TRUSTED_ISSUERS } from './trustedIssuers.js';

export const MINIMUM_AGE_YEARS = 18;

// Latest birth date that is 18 or older today: year*10000 + month*100 + day in
// UTC, minus 18 years. The same arithmetic as the backend's computeThresholdDate.
export function cutoffDate(now = new Date()) {
  const today = now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();
  return today - MINIMUM_AGE_YEARS * 10000;
}

export function formatDate(yyyymmdd) {
  const s = String(yyyymmdd).padStart(8, '0');
  return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6)}`;
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

let vkeyPromise = null;

// The credential circuit's verification key, as staged for the browser prover
// and checked against the release SHA-256.
export function loadVerificationKey() {
  vkeyPromise ??= (async () => {
    const manifest = await (await fetch('/circuit/manifest.json', { cache: 'no-store' })).json();
    const entry = manifest.files.find((f) => f.name === 'verification_key.json');
    const bytes = new Uint8Array(await (await fetch(`/circuit/${entry.parts[0]}`)).arrayBuffer());
    if ((await sha256Hex(bytes)) !== entry.sha256) throw new Error('Verification key checksum mismatch.');
    return JSON.parse(new TextDecoder().decode(bytes));
  })().catch((err) => {
    vkeyPromise = null;
    throw err;
  });
  return vkeyPromise;
}

// A scanned code is accepted only if all three hold:
//   issuer  its key id is in the trusted list
//   proof   the Groth16 proof verifies under that issuer's key and the code's cutoff
//   age     the cutoff is no later than today's 18-year cutoff (an earlier one is stricter)
// proofValid is null when the issuer is unknown: there is no key to check against.
export async function checkProofCode(code, { now = new Date(), issuers = TRUSTED_ISSUERS, vkey } = {}) {
  let decoded;
  try {
    decoded = decodeProofCode(code);
  } catch (err) {
    return { accepted: false, unreadable: err.message };
  }

  let issuer = null;
  for (const candidate of issuers) {
    const limbs = bigIntToLimbs(BigInt(`0x${candidate.modulusHex}`));
    if ((await issuerKeyId(limbs)) === decoded.keyId) issuer = { name: candidate.name, limbs };
  }

  let proofValid = null;
  if (issuer) {
    const { groth16 } = await import('snarkjs');
    const publicSignals = [...issuer.limbs, String(decoded.thresholdDate)];
    proofValid = await groth16.verify(vkey ?? (await loadVerificationKey()), publicSignals, decoded.proof).catch(() => false);
  }

  const cutoff = cutoffDate(now);
  const ageOk = decoded.thresholdDate <= cutoff;
  return {
    accepted: Boolean(issuer) && proofValid === true && ageOk,
    keyId: decoded.keyId,
    issuer: issuer ? issuer.name : null,
    proofValid,
    ageOk,
    bornOnOrBefore: formatDate(decoded.thresholdDate),
    cutoff: formatDate(cutoff),
  };
}
