// Year-only and masked cards through signing, the legacy preprocessing path and
// the unchanged v1 circuit. Circuit tests need `npm run fetch-circuit`.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { buildCanonicalPayload, cardNotes, signCredential } = require('../signedcredential');
const { validatePayload } = require('../../mock-issuer/sign_credential');
const { preprocessData } = require('../preprocessing');
const { buildCircuitInput } = require('../circuits/credential-age-proof/gen_input');
const { generateComposedProof } = require('../composedproof');

const OCR = {
  full: { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  yearOnly: { name: 'Sunita Devi', dob: '1985', aadhaarNumber: '2345 6789 0123', gender: 'Female' },
  masked: { name: 'Arjun Mehta', dob: '12/03/1992', aadhaarNumber: 'XXXX XXXX 4321', gender: 'Male' },
};

const CAP_DIR = path.join(__dirname, '..', 'circuits', 'credential-age-proof');
const WASM = path.join(CAP_DIR, 'credential_age_proof_js', 'credential_age_proof.wasm');
const ARTIFACTS = [WASM, path.join(CAP_DIR, 'cap_final.zkey'), path.join(CAP_DIR, 'verification_key.json')];
const needsCircuit = ARTIFACTS.every((p) => fs.existsSync(p)) ? false : 'run npm run fetch-circuit first';

test('full-date credentials are unchanged', () => {
  assert.deepEqual(buildCanonicalPayload(OCR.full), {
    name: 'Rajesh Kumar',
    dob: '1990-01-01',
    id_number: '123456789012',
    gender: 'M',
  });
});

test('card variants map to the signed forms', () => {
  const yearOnly = buildCanonicalPayload(OCR.yearOnly);
  const masked = buildCanonicalPayload(OCR.masked);
  assert.equal(yearOnly.dob, '1985-99-99');
  assert.equal(masked.id_number, 'XXXXXXXX4321');
  assert.deepEqual(cardNotes(yearOnly), { yearOfBirthOnly: true, maskedId: false });
  assert.deepEqual(cardNotes(masked), { yearOfBirthOnly: false, maskedId: true });
  assert.equal(buildCanonicalPayload({ ...OCR.masked, aadhaarNumber: 'xxxx xxxx 4321' }).id_number, 'XXXXXXXX4321');
});

test('the signer accepts only the documented variant forms', () => {
  const base = { name: 'Sunita Devi', gender: 'F', id_number: '234567890123', dob: '1985-99-99' };
  validatePayload(base);
  validatePayload({ ...base, id_number: 'XXXXXXXX0123' });
  const nextYear = new Date().getUTCFullYear() + 1;
  for (const dob of ['1850-99-99', `${nextYear}-99-99`, '1985-99-01', '1985-12-99']) {
    assert.throws(() => validatePayload({ ...base, dob }), /dob/, dob);
  }
  for (const id_number of ['XXXX56789012', 'xxxxxxxx0123', 'XXXXXXXX123', '12345678901']) {
    assert.throws(() => validatePayload({ ...base, id_number }), /id_number/, id_number);
  }
});

test('legacy path: year-only encodes as YYYY9999, masked stores no hash', () => {
  const yearOnly = preprocessData(OCR.yearOnly.name, OCR.yearOnly.dob, OCR.yearOnly.aadhaarNumber, OCR.yearOnly.gender);
  assert.equal(yearOnly.dobEncoded, 19859999);
  assert.equal(yearOnly.transformations[1].label, 'Encoded Date (YYYY9999)');

  const masked = preprocessData(OCR.masked.name, OCR.masked.dob, OCR.masked.aadhaarNumber, OCR.masked.gender);
  assert.equal(masked.dobEncoded, 19920312);
  assert.equal(masked.aadhaarHash, null);
  assert.ok(masked.transformations.some((t) => t.label === 'Masked Aadhaar'));

  const full = preprocessData(OCR.full.name, OCR.full.dob, OCR.full.aadhaarNumber, OCR.full.gender);
  assert.equal(full.dobEncoded, 19900101);
  assert.match(full.aadhaarHash, /^[0-9a-f]{64}$/);
});

test('the legacy age circuit treats YYYY9999 as after every date that year', async () => {
  const wasm = path.join(__dirname, '..', 'circuits', 'AgeVerification_js', 'AgeVerification.wasm');
  const run = (dobEncoded) => snarkjs.wtns.calculate({ dobEncoded, thresholdDate: 20080928 }, wasm, { type: 'mem' });
  await run(19859999);
  await run(20079999);
  await assert.rejects(run(20089999), /Assert Failed/);
});

test('the v1 circuit accepts the variant forms without changes', { skip: needsCircuit }, async () => {
  const CUTOFF = 20080928; // 18 years before 2026-09-28
  const witness = (ocr) => {
    const { circuitInputs } = signCredential(buildCanonicalPayload(ocr));
    return snarkjs.wtns.calculate(buildCircuitInput(circuitInputs, CUTOFF).input, WASM, { type: 'mem' });
  };

  await witness(OCR.full);
  await witness(OCR.yearOnly);
  await witness(OCR.masked);
  await witness({ ...OCR.yearOnly, dob: '2007' });

  // Born some time in 2008: not provably 18 on 2026-09-28. The age assertion
  // must be what fails, not the signature check.
  await assert.rejects(witness({ ...OCR.yearOnly, dob: '2008' }), (err) => {
    assert.match(err.message, /CredentialAgeProof_\d+ line: 127/);
    assert.doesNotMatch(err.message, /RSAVerifier/);
    return true;
  });
});

test('a year-only card in the boundary year gets a clear answer', { skip: needsCircuit }, async () => {
  const boundaryYear = String(new Date().getUTCFullYear() - 18);
  const payload = buildCanonicalPayload({ ...OCR.yearOnly, dob: boundaryYear });
  const { circuitInputs } = signCredential(payload);
  await assert.rejects(generateComposedProof(circuitInputs, payload.dob), (err) => {
    assert.equal(err.code, 'AGE_REQUIREMENT_NOT_MET');
    assert.match(err.userMessage, /only a year of birth/);
    return true;
  });
});
