// Name and gender proof: RSA signature check + in-circuit name and gender match.
// The values are read from the signed bytes, so a claim can only match what the
// issuer signed.

const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const CMP_DIR = path.join(__dirname, 'circuits', 'credential-match-proof');
const { buildMatchInput, normalizeName, signedFields, NAME_MAX } = require('./circuits/credential-match-proof/gen_input');
const { CredentialError, unavailable } = require('./signedcredential');

const CMP_WASM = path.join(CMP_DIR, 'credential_match_proof_js', 'credential_match_proof.wasm');
const CMP_ZKEY = path.join(CMP_DIR, 'cmp_final.zkey');
const CMP_VKEY = path.join(CMP_DIR, 'match_verification_key.json');
const GENDER_LABELS = { M: 'Male', F: 'Female', O: 'Other' };

class ClaimError extends Error {}

// { name, gender } from a request: at least one, gender as M, F or O.
function parseClaims({ claimedName, claimedGender } = {}) {
  const name = typeof claimedName === 'string' && claimedName.trim() ? claimedName : null;
  const gender = typeof claimedGender === 'string' && claimedGender ? claimedGender.toUpperCase() : null;
  if (!name && !gender) throw new ClaimError('Provide claimedName, claimedGender (M, F or O), or both.');
  if (gender && !GENDER_LABELS[gender]) throw new ClaimError('claimedGender must be M, F or O.');
  if (name && !/^[\x20-\x7E]+$/.test(name)) throw new ClaimError('claimedName must be printable ASCII.');
  if (name && normalizeName(name).length > NAME_MAX) throw new ClaimError(`claimedName must be at most ${NAME_MAX} characters.`);
  return { name, gender };
}

function mismatch(reason, userMessage) {
  return new CredentialError({
    code: 'CLAIM_MISMATCH',
    reason,
    userMessage,
    detail: reason,
    retryable: false,
    status: 422,
  });
}

async function generateMatchProof(circuitInputs, claims) {
  for (const [label, p] of [['wasm', CMP_WASM], ['zkey', CMP_ZKEY], ['vkey', CMP_VKEY]]) {
    if (!fs.existsSync(p)) {
      throw unavailable('artifact_missing', `Match-circuit ${label} not found at ${p}. Run: npm run fetch-circuit`);
    }
  }

  // Checked before proving so a wrong claim gets a precise answer and a later
  // circuit assert can only mean a real fault.
  const signed = signedFields(circuitInputs.message_bytes);
  if (claims.name && normalizeName(claims.name) !== signed.name.toLowerCase()) {
    throw mismatch('name_mismatch', "The name on this credential doesn't match the claimed name.");
  }
  if (claims.gender && claims.gender !== signed.gender) {
    throw mismatch('gender_mismatch', "The gender on this credential doesn't match the claimed gender.");
  }

  let input;
  try {
    input = buildMatchInput(circuitInputs, claims).input;
  } catch (err) {
    throw unavailable('input_build_failed', err.message);
  }

  const started = Date.now();
  let proof;
  let publicSignals;
  try {
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, CMP_WASM, CMP_ZKEY));
  } catch (err) {
    throw unavailable('witness_failed', `Match proof generation failed: ${err.message}`);
  }
  const proofDuration = Date.now() - started;

  const verifyStart = Date.now();
  const vkey = JSON.parse(fs.readFileSync(CMP_VKEY, 'utf8'));
  const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  const verificationDuration = Date.now() - verifyStart;

  console.log(
    `[PROOF:MATCH] generated in ${proofDuration}ms, verified in ${verificationDuration}ms — ${isValid ? 'VALID' : 'INVALID'} ` +
      `(claims: ${[claims.name && 'name', claims.gender && 'gender'].filter(Boolean).join(' + ')})`
  );

  if (!isValid) {
    throw unavailable('verification_failed', 'Match proof did not verify locally.');
  }

  const matched = [claims.name && 'NAME', claims.gender && 'GENDER'].filter(Boolean).join('_AND_');
  return {
    proof,
    publicSignals,
    isValid,
    proofDuration,
    verificationDuration,
    claimedName: claims.name,
    claimedGender: claims.gender,
    claimedGenderLabel: claims.gender ? GENDER_LABELS[claims.gender] : null,
    message: `${matched}_MATCH: VERIFIED (issuer-signed credential)`,
  };
}

// False on hosts without the proving key (e.g. Vercel): browsers prove instead.
function matchProvingAvailable() {
  return [CMP_WASM, CMP_ZKEY, CMP_VKEY].every((p) => fs.existsSync(p));
}

module.exports = { generateMatchProof, matchProvingAvailable, parseClaims, ClaimError };
