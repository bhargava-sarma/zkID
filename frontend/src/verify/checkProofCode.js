import { decodeProofCode } from './proofCode.js';
import { cutoffDate, formatDate, trustedIssuerKeys } from './policy.js';
import { TRUSTED_ISSUERS } from './trustedIssuers.js';

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

  const issuer = (await trustedIssuerKeys(issuers)).find((i) => i.keyId === decoded.keyId) || null;

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
