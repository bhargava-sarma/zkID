const snarkjs = require('snarkjs');
const path = require('path');
const fs = require('fs');

const CIRCUITS_DIR = path.join(__dirname, 'circuits');

// Age circuit paths
const AGE_WASM = path.join(CIRCUITS_DIR, 'AgeVerification_js', 'AgeVerification.wasm');
const AGE_ZKEY = path.join(CIRCUITS_DIR, 'age_final.zkey');
const AGE_VKEY = path.join(CIRCUITS_DIR, 'age_vkey.json');
// Fallback for backward compatibility
const AGE_VKEY_LEGACY = path.join(CIRCUITS_DIR, 'verification_key.json');

// Name circuit paths
const NAME_WASM = path.join(CIRCUITS_DIR, 'NameVerification_js', 'NameVerification.wasm');
const NAME_ZKEY = path.join(CIRCUITS_DIR, 'name_final.zkey');
const NAME_VKEY = path.join(CIRCUITS_DIR, 'name_vkey.json');

// Gender circuit paths
const GENDER_WASM = path.join(CIRCUITS_DIR, 'GenderVerification_js', 'GenderVerification.wasm');
const GENDER_ZKEY = path.join(CIRCUITS_DIR, 'gender_final.zkey');
const GENDER_VKEY = path.join(CIRCUITS_DIR, 'gender_vkey.json');

/**
 * Check that required circuit artifacts exist
 */
function checkArtifacts(wasmPath, zkeyPath, vkeyPath, circuitName) {
  if (!fs.existsSync(wasmPath)) {
    throw new Error(`${circuitName} WASM not found. Run the circuit setup script first.`);
  }
  if (!fs.existsSync(zkeyPath)) {
    throw new Error(`${circuitName} zkey not found. Run the circuit setup script first.`);
  }
  if (!fs.existsSync(vkeyPath)) {
    throw new Error(`${circuitName} verification key not found. Run the circuit setup script first.`);
  }
}

/**
 * Generic proof generation and verification
 */
async function runProof(input, wasmPath, zkeyPath, vkeyPath, tag) {
  console.log(`[PROOF:${tag}] Starting proof generation...`);

  const proofStart = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  const proofDuration = Date.now() - proofStart;
  console.log(`[PROOF:${tag}] Proof generated in ${proofDuration}ms`);

  const verifyStart = Date.now();
  const vkeyJson = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
  const isValid = await snarkjs.groth16.verify(vkeyJson, publicSignals, proof);
  const verificationDuration = Date.now() - verifyStart;
  console.log(`[PROOF:${tag}] Verification complete in ${verificationDuration}ms — result: ${isValid ? 'VALID' : 'INVALID'}`);

  return { proof, publicSignals, isValid, proofDuration, verificationDuration };
}

// =============================================
// Age Proof
// =============================================
const MINIMUM_AGE_YEARS = 18;

/**
 * Latest date of birth that still qualifies, as year*10000 + month*100 + day.
 *
 * Computed by subtracting the age from the year component directly, with no date
 * arithmetic. That is deliberate: the previous implementation used a constant
 * thresholdDays = 6570 (18 * 365), which ignored leap days and ran four days
 * lenient — someone four days short of eighteen verified as an adult.
 *
 * Doing it as pure integer arithmetic also sidesteps the Feb 29 trap. Building a
 * Date for Feb 29 in a non-leap year silently rolls over to Mar 1; here, a Feb 29
 * "today" yields an encoded threshold of e.g. 20080229, which compares correctly
 * against real dates on either side of it whether or not that date exists.
 *
 * @param {Date} [now] Reference date; defaults to today. Injectable for tests.
 * @returns {number} Encoded threshold date
 */
function computeThresholdDate(now = new Date()) {
  const year = now.getUTCFullYear() - MINIMUM_AGE_YEARS;
  const month = now.getUTCMonth() + 1;
  const day = now.getUTCDate();
  return year * 10000 + month * 100 + day;
}

async function generateProof(dobEncoded) {
  const vkeyPath = fs.existsSync(AGE_VKEY) ? AGE_VKEY : AGE_VKEY_LEGACY;
  checkArtifacts(AGE_WASM, AGE_ZKEY, vkeyPath, 'AgeVerification');

  const now = new Date();
  const thresholdDate = computeThresholdDate(now);
  // Not a public signal, and not an input to the circuit — reported only so the
  // UI can show which day the threshold was derived from.
  const todayDate =
    now.getUTCFullYear() * 10000 + (now.getUTCMonth() + 1) * 100 + now.getUTCDate();

  const input = { dobEncoded, thresholdDate };
  console.log(`[PROOF:AGE] today: ${todayDate}, threshold: ${thresholdDate} (${MINIMUM_AGE_YEARS}y)`);

  try {
    const result = await runProof(input, AGE_WASM, AGE_ZKEY, vkeyPath, 'AGE');
    return {
      ...result,
      message: result.isValid ? `AGE_OVER_${MINIMUM_AGE_YEARS}: VERIFIED` : 'VERIFICATION FAILED',
      thresholdDate,
      todayDate,
      minimumAgeYears: MINIMUM_AGE_YEARS,
    };
  } catch (err) {
    console.log(`[PROOF:AGE] Generation FAILED: ${err.message}`);
    if (err.message && err.message.includes('Assert Failed')) {
      throw new Error('Proof generation failed. Age condition not satisfied.');
    }
    throw err;
  }
}

// =============================================
// Name Proof
// =============================================
async function generateNameProof(nameHash, claimedNameHash) {
  checkArtifacts(NAME_WASM, NAME_ZKEY, NAME_VKEY, 'NameVerification');

  const input = { nameHash, claimedNameHash };
  console.log(`[PROOF:NAME] claimedHash: ${claimedNameHash.toString().substring(0, 16)}...`);

  try {
    const result = await runProof(input, NAME_WASM, NAME_ZKEY, NAME_VKEY, 'NAME');
    return {
      ...result,
      message: result.isValid ? 'NAME_MATCH: VERIFIED' : 'NAME VERIFICATION FAILED',
      claimedNameHash,
    };
  } catch (err) {
    console.log(`[PROOF:NAME] Generation FAILED: ${err.message}`);
    if (err.message && err.message.includes('Assert Failed')) {
      throw new Error('Proof generation failed. Name does not match claimed identity.');
    }
    throw err;
  }
}

// =============================================
// Gender Proof
// =============================================
async function generateGenderProof(genderCode, claimedGender) {
  checkArtifacts(GENDER_WASM, GENDER_ZKEY, GENDER_VKEY, 'GenderVerification');

  const input = { genderCode, claimedGender };
  const genderLabels = { 1: 'Male', 2: 'Female', 3: 'Other' };
  console.log(`[PROOF:GENDER] claiming: ${genderLabels[claimedGender] || claimedGender}`);

  try {
    const result = await runProof(input, GENDER_WASM, GENDER_ZKEY, GENDER_VKEY, 'GENDER');
    return {
      ...result,
      message: result.isValid ? 'GENDER_MATCH: VERIFIED' : 'GENDER VERIFICATION FAILED',
      claimedGender,
      claimedGenderLabel: genderLabels[claimedGender] || 'Unknown',
    };
  } catch (err) {
    console.log(`[PROOF:GENDER] Generation FAILED: ${err.message}`);
    if (err.message && err.message.includes('Assert Failed')) {
      throw new Error('Proof generation failed. Gender does not match claimed value.');
    }
    throw err;
  }
}

module.exports = { generateProof, generateNameProof, generateGenderProof, computeThresholdDate };
