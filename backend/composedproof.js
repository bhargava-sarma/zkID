// Composed proof: RSA signature check + in-circuit DOB extraction + age check.
// The DOB is read from the signed bytes, so it can't differ from what the issuer signed.

const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');

const CAP_DIR = path.join(__dirname, 'circuits', 'credential-age-proof');
const { buildCircuitInput } = require('./circuits/credential-age-proof/gen_input');
const { CredentialError, unavailable } = require('./signedcredential');

const MINIMUM_AGE_YEARS = 18;

// Latest qualifying DOB: today as year*10000 + month*100 + day (UTC), minus 18
// years. Pure integer arithmetic, so no leap-year or Feb 29 rollover issues.
// ZkIdPolicy.cutoffDate and the verifier page use the same arithmetic.
function computeThresholdDate(now = new Date()) {
  const today = now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();
  return today - MINIMUM_AGE_YEARS * 10000;
}

const CAP_WASM = path.join(CAP_DIR, 'credential_age_proof_js', 'credential_age_proof.wasm');
const CAP_ZKEY = path.join(CAP_DIR, 'cap_final.zkey');
const CAP_VKEY = path.join(CAP_DIR, 'verification_key.json');

function proverInput(circuitInputs, thresholdDate = computeThresholdDate()) {
  try {
    return buildCircuitInput(circuitInputs, thresholdDate).input;
  } catch (err) {
    throw unavailable('input_build_failed', err.message);
  }
}

async function generateComposedProof(circuitInputs, isoDob) {
  for (const [label, p] of [['wasm', CAP_WASM], ['zkey', CAP_ZKEY], ['vkey', CAP_VKEY]]) {
    if (!fs.existsSync(p)) {
      throw unavailable('artifact_missing', `Composed-circuit ${label} not found at ${p}. Run: npm run fetch-circuit`);
    }
  }

  const thresholdDate = computeThresholdDate();

  // Checked before proving so an underage subject gets a precise answer and a
  // later circuit assert can only mean a real fault. Same encoding as the
  // circuit, so a year-only YYYY-99-99 sorts after every date in that year.
  const [y, m, d] = isoDob.split('-').map(Number);
  const dobEncoded = y * 10000 + m * 100 + d;
  if (dobEncoded > thresholdDate) {
    throw new CredentialError({
      code: 'AGE_REQUIREMENT_NOT_MET',
      reason: 'underage',
      userMessage:
        m === 99
          ? 'This credential does not meet the minimum age requirement. The card shows only a year of birth, so the check assumes the latest possible birthday in that year.'
          : 'This credential does not meet the minimum age requirement.',
      detail: `dobEncoded ${dobEncoded} > thresholdDate ${thresholdDate}`,
      retryable: false,
      status: 422,
    });
  }

  const input = proverInput(circuitInputs, thresholdDate);

  const started = Date.now();
  let proof;
  let publicSignals;
  try {
    ({ proof, publicSignals } = await snarkjs.groth16.fullProve(input, CAP_WASM, CAP_ZKEY));
  } catch (err) {
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

// False on hosts without the 133 MB proving key (e.g. Vercel): browsers prove instead.
function serverProvingAvailable() {
  return [CAP_WASM, CAP_ZKEY, CAP_VKEY].every((p) => fs.existsSync(p));
}

module.exports = { generateComposedProof, proverInput, serverProvingAvailable, computeThresholdDate };
