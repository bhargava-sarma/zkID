// Name and gender proofs from the signed credential. Circuit tests need
// `npm run fetch-circuit`.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');
const { buildMatchInput, nameHash } = require('../circuits/credential-match-proof/gen_input');
const { buildCanonicalPayload, signCredential } = require('../signedcredential');
const { generateMatchProof, parseClaims, ClaimError } = require('../matchproof');

const CMP_DIR = path.join(__dirname, '..', 'circuits', 'credential-match-proof');
const WASM = path.join(CMP_DIR, 'credential_match_proof_js', 'credential_match_proof.wasm');
const ARTIFACTS = [WASM, path.join(CMP_DIR, 'cmp_final.zkey'), path.join(CMP_DIR, 'match_verification_key.json')];
const needsCircuit = ARTIFACTS.every((p) => fs.existsSync(p)) ? false : 'run npm run fetch-circuit first';
const FIXTURE = require('../hardhat-deploy/test/fixtures/match-name.json');

const OCR = {
  full: { name: 'Rajesh Kumar', dob: '01/01/1990', aadhaarNumber: '1234 5678 9012', gender: 'Male' },
  yearOnly: { name: 'Sunita Devi', dob: '1985', aadhaarNumber: '2345 6789 0123', gender: 'Female' },
  masked: { name: 'Arjun Mehta', dob: '12/03/1992', aadhaarNumber: 'XXXX XXXX 4321', gender: 'Male' },
};
const signed = (ocr) => signCredential(buildCanonicalPayload(ocr)).circuitInputs;
const witness = (input) => snarkjs.wtns.calculate(input, WASM, { type: 'mem' });

test('the name hash ignores case and spacing, as the circuit does', () => {
  assert.equal(nameHash('  test   USER one '), nameHash('Test User One'));
  assert.notEqual(nameHash('Test User One'), nameHash('Test User Two'));
  // The fixture proof's public claim came from the circuit's own hashing.
  assert.equal(nameHash('Test User One'), FIXTURE.publicSignals[17]);
  assert.throws(() => nameHash('A'.repeat(50)), /1 to 49/);
});

test('claims are validated before anything is signed', () => {
  assert.deepEqual(parseClaims({ claimedName: 'Rajesh Kumar' }), { name: 'Rajesh Kumar', gender: null });
  assert.deepEqual(parseClaims({ claimedGender: 'f' }), { name: null, gender: 'F' });
  for (const body of [{}, { claimedName: '  ' }, { claimedGender: 'X' }, { claimedName: 'Rājesh' }, { claimedName: 'A'.repeat(50) }]) {
    assert.throws(() => parseClaims(body), ClaimError, JSON.stringify(body));
  }
});

test('a wrong claim gets a clear answer before proving', { skip: needsCircuit }, async () => {
  const ci = signed(OCR.full);
  await assert.rejects(generateMatchProof(ci, { name: 'Priya Sharma', gender: null }), (err) => {
    assert.equal(err.code, 'CLAIM_MISMATCH');
    assert.equal(err.reason, 'name_mismatch');
    return true;
  });
  await assert.rejects(generateMatchProof(ci, { name: null, gender: 'F' }), (err) => err.reason === 'gender_mismatch');
});

test('the circuit proves name and gender claims from every card variant', { skip: needsCircuit }, async () => {
  await witness(buildMatchInput(signed(OCR.full), { name: 'rajesh kumar', gender: 'M' }).input);
  await witness(buildMatchInput(signed(OCR.yearOnly), { name: 'Sunita Devi', gender: 'F' }).input);
  await witness(buildMatchInput(signed(OCR.masked), { name: 'ARJUN MEHTA' }).input);
  // The longest name that fits the 119-byte payload.
  const longest = 'Venkata Satya Narayana Murthy Chowdary Kondapalli';
  assert.equal(longest.length, 49);
  await witness(buildMatchInput(signed({ ...OCR.full, name: longest }), { name: longest }).input);
});

test('the circuit rejects wrong claims, a wrong name length and a tampered name', { skip: needsCircuit }, async () => {
  const ci = signed(OCR.full);
  const fails = async (input, pattern) =>
    assert.rejects(witness(input), (err) => {
      assert.match(err.message, pattern);
      return true;
    });

  // Claims are checked at their own constraints, not by the signature check.
  await fails(buildMatchInput(ci, { name: 'Rajesh Kumari' }).input, /CredentialMatchProof_\d+ line: 222/);
  await fails(buildMatchInput(ci, { gender: 'F' }).input, /CredentialMatchProof_\d+ line: 131/);

  // A length hint that stops before or after the closing quote.
  const { input } = buildMatchInput(ci, { name: 'Rajesh Kumar' });
  await fails({ ...input, nameLength: input.nameLength - 1 }, /CredentialMatchProof_\d+/);
  await fails({ ...input, nameLength: input.nameLength + 1 }, /CredentialMatchProof_\d+/);

  // Changing a signed byte breaks the RSA check.
  await fails(buildMatchInput(ci, { name: 'Rajesh Kumar' }, 'name').input, /RSAVerifier65537/);
});
