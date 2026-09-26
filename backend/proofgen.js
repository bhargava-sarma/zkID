const snarkjs = require('snarkjs');
const path = require('path');
const fs = require('fs');

const CIRCUITS_DIR = path.join(__dirname, 'circuits');
const MINIMUM_AGE_YEARS = 18;
const GENDER_LABELS = { 1: 'Male', 2: 'Female', 3: 'Other' };

function circuit(name, prefix) {
  return {
    name,
    wasm: path.join(CIRCUITS_DIR, `${name}_js`, `${name}.wasm`),
    zkey: path.join(CIRCUITS_DIR, `${prefix}_final.zkey`),
    vkey: path.join(CIRCUITS_DIR, `${prefix}_vkey.json`),
  };
}

const AGE = circuit('AgeVerification', 'age');
const NAME = circuit('NameVerification', 'name');
const GENDER = circuit('GenderVerification', 'gender');

// Proves and verifies locally. A failed circuit assert is rethrown as failMessage.
async function runProof(c, input, tag, failMessage) {
  for (const [label, p] of [['WASM', c.wasm], ['zkey', c.zkey], ['verification key', c.vkey]]) {
    if (!fs.existsSync(p)) {
      throw new Error(`${c.name} ${label} not found. Run the circuit setup script first.`);
    }
  }

  console.log(`[PROOF:${tag}] Starting proof generation...`);
  try {
    const proofStart = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, c.wasm, c.zkey);
    const proofDuration = Date.now() - proofStart;
    console.log(`[PROOF:${tag}] Proof generated in ${proofDuration}ms`);

    const verifyStart = Date.now();
    const vkey = JSON.parse(fs.readFileSync(c.vkey, 'utf8'));
    const isValid = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    const verificationDuration = Date.now() - verifyStart;
    console.log(`[PROOF:${tag}] Verification complete in ${verificationDuration}ms — result: ${isValid ? 'VALID' : 'INVALID'}`);

    return { proof, publicSignals, isValid, proofDuration, verificationDuration };
  } catch (err) {
    console.log(`[PROOF:${tag}] Generation FAILED: ${err.message}`);
    if (err.message && err.message.includes('Assert Failed')) throw new Error(failMessage);
    throw err;
  }
}

// year*10000 + month*100 + day, in UTC.
function encodeDate(d) {
  return d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
}

// Latest qualifying DOB. Pure integer arithmetic: no leap-year or Feb 29 rollover issues.
function computeThresholdDate(now = new Date()) {
  return encodeDate(now) - MINIMUM_AGE_YEARS * 10000;
}

async function generateProof(dobEncoded) {
  const now = new Date();
  const thresholdDate = computeThresholdDate(now);
  const todayDate = encodeDate(now); // Display only, not a public signal.
  console.log(`[PROOF:AGE] today: ${todayDate}, threshold: ${thresholdDate} (${MINIMUM_AGE_YEARS}y)`);

  const result = await runProof(
    AGE,
    { dobEncoded, thresholdDate },
    'AGE',
    'Proof generation failed. Age condition not satisfied.'
  );
  return {
    ...result,
    message: result.isValid ? `AGE_OVER_${MINIMUM_AGE_YEARS}: VERIFIED` : 'VERIFICATION FAILED',
    thresholdDate,
    todayDate,
    minimumAgeYears: MINIMUM_AGE_YEARS,
  };
}

async function generateNameProof(nameHash, claimedNameHash) {
  console.log(`[PROOF:NAME] claimedHash: ${claimedNameHash.toString().substring(0, 16)}...`);

  const result = await runProof(
    NAME,
    { nameHash, claimedNameHash },
    'NAME',
    'Proof generation failed. Name does not match claimed identity.'
  );
  return {
    ...result,
    message: result.isValid ? 'NAME_MATCH: VERIFIED' : 'NAME VERIFICATION FAILED',
    claimedNameHash,
  };
}

async function generateGenderProof(genderCode, claimedGender) {
  console.log(`[PROOF:GENDER] claiming: ${GENDER_LABELS[claimedGender] || claimedGender}`);

  const result = await runProof(
    GENDER,
    { genderCode, claimedGender },
    'GENDER',
    'Proof generation failed. Gender does not match claimed value.'
  );
  return {
    ...result,
    message: result.isValid ? 'GENDER_MATCH: VERIFIED' : 'GENDER VERIFICATION FAILED',
    claimedGender,
    claimedGenderLabel: GENDER_LABELS[claimedGender] || 'Unknown',
  };
}

module.exports = { generateProof, generateNameProof, generateGenderProof, computeThresholdDate };
