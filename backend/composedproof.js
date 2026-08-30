/**
 * Composed-circuit proof generation: RSA signature verification + in-circuit
 * field extraction + age comparison, in one proof.
 *
 * Unlike proofgen.js's AgeVerification, this does not take a date as input. The
 * date is extracted in-circuit from the very bytes the issuer's signature
 * covers, so a proof cannot assert an age that differs from the signed one.
 *
 * Artifacts are referenced from experiments/ rather than copied into backend/.
 * That couples this module to an experiments directory, which is a deliberate
 * short-term choice: the proving key is 128MB and moving it is not free.
 */

const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const { buildCircuitInput } = require(
  path.join(__dirname, '..', 'experiments', 'credential-age-proof', 'gen_input.js')
);
const { computeThresholdDate } = require('./proofgen');
const { CredentialError } = require('./signedcredential');

const CAP_DIR = path.join(__dirname, '..', 'experiments', 'credential-age-proof');
const CAP_WASM = path.join(CAP_DIR, 'credential_age_proof_js', 'credential_age_proof.wasm');
const CAP_ZKEY = path.join(CAP_DIR, 'cap_final.zkey');
const CAP_VKEY = path.join(CAP_DIR, 'verification_key.json');

/** Wraps an operator-side failure: the user did nothing wrong. */
function unavailable(reason, detail) {
  return new CredentialError({
    code: 'PROVING_UNAVAILABLE',
    reason,
    userMessage: 'Verification is temporarily unavailable. Please try again shortly.',
    detail,
    retryable: false,
    status: 500,
  });
}

/**
 * Generates and verifies a composed proof for a freshly signed credential.
 *
 * @param {object} circuitInputs Output of signedcredential.signCredential
 * @param {string} isoDob The payload's dob, YYYY-MM-DD, for the age pre-check
 * @returns {Promise<object>} proof, publicSignals, verification result and timings
 * @throws {CredentialError}
 */
async function generateComposedProof(circuitInputs, isoDob) {
  for (const [label, p] of [['wasm', CAP_WASM], ['zkey', CAP_ZKEY], ['vkey', CAP_VKEY]]) {
    if (!fs.existsSync(p)) {
      throw unavailable(
        'artifact_missing',
        `Composed-circuit ${label} not found at ${p}. Build it in experiments/credential-age-proof/.`
      );
    }
  }

  const thresholdDate = computeThresholdDate();

  // Age is checked here BEFORE proving, not inferred from a circuit assert.
  // The circuit enforces the same comparison, but a witness failure gives only
  // "Assert Failed ... line: N", which is brittle to match on and cannot be
  // distinguished from a genuine malfunction. Comparing in JS lets an underage
  // subject get a precise, non-retryable answer, and leaves any later assert
  // failure meaning something is actually wrong.
  const [y, m, d] = isoDob.split('-').map(Number);
  const dobEncoded = y * 10000 + m * 100 + d;
  if (dobEncoded > thresholdDate) {
    throw new CredentialError({
      code: 'AGE_REQUIREMENT_NOT_MET',
      reason: 'underage',
      userMessage: 'This credential does not meet the minimum age requirement.',
      detail: `dobEncoded ${dobEncoded} > thresholdDate ${thresholdDate}`,
      retryable: false,
      status: 422,
    });
  }

  let input;
  try {
    input = buildCircuitInput(circuitInputs, thresholdDate).input;
  } catch (err) {
    throw unavailable('input_build_failed', err.message);
  }

  const started = Date.now();
  let proof;
  let publicSignals;
  try {
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, CAP_WASM, CAP_ZKEY));
  } catch (err) {
    // Everything the circuit asserts has already been checked above, so an
    // assert failure here is a real inconsistency, not a user error.
    throw unavailable('witness_failed', `Composed proof generation failed: ${err.message}`);
  }
  const proofDuration = Date.now() - started;

  const verifyStart = Date.now();
  const vkey = JSON.parse(fs.readFileSync(CAP_VKEY, 'utf8'));
  const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  const verificationDuration = Date.now() - verifyStart;

  console.log(
    `[PROOF:COMPOSED] generated in ${proofDuration}ms, verified in ${verificationDuration}ms — ` +
      `${isValid ? 'VALID' : 'INVALID'} (threshold ${thresholdDate})`
  );

  if (!isValid) {
    throw unavailable('verification_failed', 'Composed proof did not verify locally.');
  }

  return {
    proof,
    publicSignals,
    isValid,
    thresholdDate,
    proofDuration,
    verificationDuration,
    message: 'AGE_OVER_18: VERIFIED (issuer-signed credential)',
  };
}

module.exports = { generateComposedProof, CAP_ZKEY };
