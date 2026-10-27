// Phase 3 controls on Anon Aadhaar's published circuit: tests T1.2-T1.4,
// T1.7-T1.10, T4.1, T5.1, T7.1 and T7.6 of docs/THREAT_MODEL.md. Every QR is
// synthetic, signed with an ephemeral key.
//
// Run: npm test. Circuit tests need the artifacts (npm run fetch, or
// AA_ARTIFACTS=<dir holding them>); without them they are reported as skipped.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  CircuitError,
  DEFAULT_DIR,
  buildInput,
  checkedArtifact,
  close,
  keyHash,
  namedSignals,
  prove,
  verify,
  witness,
} from '../index.mjs';
import { SecureQrError, decodeSecureQr } from '../../secure-qr/secure-qr.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../../secure-qr/synthetic.mjs';

const DIR = process.env.AA_ARTIFACTS || DEFAULT_DIR;
const has = (name) => fs.existsSync(path.join(DIR, name));
const NEEDS_WASM = has('aadhaar-verifier.wasm') ? {} : { skip: 'circuit wasm missing: npm run fetch' };
const NEEDS_ZKEY = has('circuit_final.zkey') && has('vkey.json') ? {} : { skip: 'proving or verification key missing: npm run fetch' };
after(close);

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const tempDirs = [];
const tempDir = () => {
  tempDirs.push(fs.mkdtempSync(path.join(os.tmpdir(), 'zkid-artifacts-')));
  return tempDirs.at(-1);
};
after(() => tempDirs.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true })));
const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const GENERATED = new Date('2026-10-25T06:30:00Z'); // 12:00 IST
const PUBLIC = { nullifierSeed: 1111n, signalHash: 2222n };

// A synthetic V5 code laid out like a current one: 900-byte photo, 27 bytes after it.
function v5({ fields = {}, photo = syntheticPhoto(900), trailing = unknownTrailer(27), generatedAt = GENERATED } = {}) {
  return makeSyntheticSecureQr(keys.privateKey, {
    version: 'V5',
    photo,
    trailing,
    fields: syntheticFields({ generatedAt, ...fields }),
  }).text;
}
const input = (text, publicInputs = {}) => buildInput(text, keys.publicKey, { ...PUBLIC, ...publicInputs });
const run = (circuitInput) => witness(circuitInput, { dir: DIR });

// The failing template's name if the witness fails, null if it succeeds.
async function failure(circuitInput) {
  try {
    await run(circuitInput);
    return null;
  } catch (err) {
    if (err instanceof CircuitError && err.code === 'WITNESS_FAILED') return err.message;
    throw err;
  }
}
const flipByte = (circuitInput, i) => {
  const qrDataPadded = [...circuitInput.qrDataPadded];
  qrDataPadded[i] = String(Number(qrDataPadded[i]) ^ 0x01);
  return { ...circuitInput, qrDataPadded };
};
const throwsCode = (fn, code) => assert.throws(fn, (err) => err.code === code, `expected ${code}`);
const rejectsCode = (promise, code) => assert.rejects(promise, (err) => err.code === code, `expected ${code}`);

// ---- Without artifacts ----------------------------------------------------------

test('keyHash: deterministic, different per key, RSA-2048 with e = 65537 only', () => {
  assert.equal(keyHash(keys.publicKey), keyHash(keys.publicKey));
  assert.notEqual(keyHash(keys.publicKey), keyHash(otherKeys.publicKey));
  throwsCode(() => keyHash(crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey), 'UNSUPPORTED_KEY');
  throwsCode(() => keyHash(crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 3 }).publicKey), 'UNSUPPORTED_KEY');
  throwsCode(() => keyHash(crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey), 'UNSUPPORTED_KEY');
});

const flags = (circuitInput) => [circuitInput.revealAgeAbove18, circuitInput.revealGender, circuitInput.revealPinCode, circuitInput.revealState];

test('buildInput: reveals only the age bit, unless asked for other fields', () => {
  const circuitInput = input(v5());
  assert.deepEqual(flags(circuitInput), ['1', '0', '0', '0']);
  assert.deepEqual(flags(buildInput(v5(), keys.publicKey, PUBLIC, { ageAbove18: false, gender: true, pinCode: true, state: true })), ['0', '1', '1', '1']);
  assert.deepEqual(flags(buildInput(v5(), keys.publicKey, PUBLIC, { pinCode: true })), ['0', '0', '1', '0']);
  assert.equal(circuitInput.qrDataPadded.length, 1536);
  assert.equal(circuitInput.delimiterIndices.length, 18);
  assert.deepEqual([circuitInput.nullifierSeed, circuitInput.signalHash], ['1111', '2222']);
});

test('buildInput: fails explicitly outside what the circuit can read', () => {
  throwsCode(() => input('12ab'), 'NOT_DECIMAL'); // the parser's SecureQrError passes through
  assert.throws(() => input('12ab'), SecureQrError);
  const v1 = makeSyntheticSecureQr(keys.privateKey, { version: 'V1', fields: syntheticFields({ generatedAt: GENERATED }) }).text;
  throwsCode(() => input(v1), 'UNSUPPORTED_LAYOUT');
  throwsCode(() => input(v5({ fields: { name: 'SYNTHETIC '.repeat(50) } })), 'DATA_TOO_LONG');
  // Default synthetic fields put the photo at offset 195, where the largest
  // photo the circuit accepts is 985 bytes (docs/circuit-spec.md).
  assert.doesNotThrow(() => input(v5({ photo: syntheticPhoto(985) })));
  throwsCode(() => input(v5({ photo: syntheticPhoto(990) })), 'PHOTO_TOO_LARGE');
  for (const bad of [FIELD, -1n, 'not a number']) throwsCode(() => input(v5(), { nullifierSeed: bad }), 'BAD_PUBLIC_INPUT');
  throwsCode(() => input(v5(), { signalHash: FIELD }), 'BAD_PUBLIC_INPUT');
});

test('namedSignals: exactly nine public signals', () => {
  throwsCode(() => namedSignals(['1', '2']), 'BAD_PUBLIC_SIGNALS');
  assert.deepEqual(Object.keys(namedSignals(Array(9).fill('0'))), [
    'pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pinCode', 'state', 'nullifierSeed', 'signalHash',
  ]);
});

test('T1.7: an artifact is refused unless its SHA-256 matches artifacts.json', async () => {
  const tmp = tempDir();
  await rejectsCode(checkedArtifact('vkey.json', tmp), 'ARTIFACT_MISSING');
  await rejectsCode(checkedArtifact('nothing.bin', tmp), 'UNKNOWN_ARTIFACT');
  fs.writeFileSync(path.join(tmp, 'vkey.json'), '{"protocol":"groth16"}');
  await rejectsCode(checkedArtifact('vkey.json', tmp), 'ARTIFACT_MISMATCH');
  if (!has('vkey.json') || !has('aadhaar-verifier.wasm')) return;

  // Positive control, then one changed byte in each small artifact.
  for (const name of ['vkey.json', 'aadhaar-verifier.wasm']) {
    const copy = tempDir();
    const bytes = fs.readFileSync(path.join(DIR, name));
    fs.writeFileSync(path.join(copy, name), bytes);
    assert.equal(await checkedArtifact(name, copy), path.join(copy, name));
    const tampered = tempDir();
    bytes[Math.floor(bytes.length / 2)] ^= 0x01;
    fs.writeFileSync(path.join(tampered, name), bytes);
    await rejectsCode(checkedArtifact(name, tampered), 'ARTIFACT_MISMATCH');
  }
});

// ---- Witness generation (needs the wasm) ------------------------------------------

test('a valid synthetic V5 code: accepted; outputs as expected', NEEDS_WASM, async () => {
  const out = await run(input(v5()));
  assert.equal(out.pubkeyHash, keyHash(keys.publicKey)); // the JS key hash equals the circuit's
  assert.equal(out.timestamp, String(Date.parse('2026-10-25T06:30:00Z') / 1000)); // 12:00 IST, the generation hour
  assert.deepEqual([out.ageAbove18, out.gender, out.pinCode, out.state], ['1', '0', '0', '0']);
  assert.deepEqual([out.nullifierSeed, out.signalHash], ['1111', '2222']);
  // The largest photo buildInput lets through is one the circuit accepts.
  assert.equal((await run(input(v5({ photo: syntheticPhoto(985) })))).ageAbove18, '1');
});

// A string's bytes as one integer, first byte lowest.
const packed = (text) => [...Buffer.from(text, 'latin1')].reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n).toString();

test('revealed gender, PIN code and state: the character code, the six digits as a number, the name packed first byte lowest', NEEDS_WASM, async () => {
  const text = v5({ fields: { gender: 'F', pincode: '560034', state: 'Karnataka' } });
  const out = await run(buildInput(text, keys.publicKey, PUBLIC, { ageAbove18: true, gender: true, pinCode: true, state: true }));
  assert.deepEqual([out.ageAbove18, out.gender, out.pinCode, out.state], ['1', String('F'.charCodeAt(0)), '560034', packed('Karnataka')]);
  const one = await run(buildInput(text, keys.publicKey, PUBLIC, { pinCode: true }));
  assert.deepEqual([one.ageAbove18, one.gender, one.pinCode, one.state], ['0', '0', '560034', '0']);
});

test('a state over 31 bytes, or a PIN code field that is not 6 bytes, fails the witness, revealed or not', NEEDS_WASM, async () => {
  const state31 = 'Andaman and Nicobar Islands Uts'; // 31 bytes
  assert.equal((await run(input(v5({ fields: { state: state31 } })))).ageAbove18, '1');
  assert.equal((await run(buildInput(v5({ fields: { state: state31 } }), keys.publicKey, PUBLIC, { state: true }))).state, packed(state31));
  assert.match(await failure(input(v5({ fields: { state: 'Dadra and Nagar Haveli and Daman and Diu' } }))), /QRDataExtractor|ExtractAndPackAsInt|SelectSubArray|LessThan|Num2Bits/);
  assert.notEqual(await failure(input(v5({ fields: { pincode: '56003' } }))), null);
  assert.notEqual(await failure(input(v5({ fields: { pincode: '5600341' } }))), null);
});

test('T1.2: one changed byte of the signed data, wherever it is, fails the witness', NEEDS_WASM, async () => {
  const text = v5({ fields: { landmark: 'TEST LANDMARK', location: 'TEST LOCATION' } });
  const circuitInput = input(text);
  const delimiters = circuitInput.delimiterIndices.map(Number);
  const photoStart = delimiters[17] + 1;
  const firstByteOf = (field) => delimiters[field - 1] + 1; // field n starts after delimiter n-1
  const paddingStart = decodeSecureQr(text).signedData.length; // SHA-256's 0x80 byte
  const positions = {
    'version marker': 0,
    'email/mobile indicator': firstByteOf(1),
    'reference ID': firstByteOf(2),
    name: firstByteOf(3),
    DOB: firstByteOf(4),
    gender: firstByteOf(5),
    'care of': firstByteOf(6),
    landmark: firstByteOf(8),
    location: firstByteOf(10),
    PIN: firstByteOf(11),
    state: firstByteOf(13),
    'field 17': firstByteOf(17),
    'delimiter 1': delimiters[0],
    'delimiter 4': delimiters[3],
    'delimiter 11': delimiters[10],
    'delimiter 14': delimiters[13],
    'delimiter 18': delimiters[17],
    'photo start': photoStart,
    'photo middle': photoStart + 450,
    'photo end': photoStart + 899,
    'first byte after the photo': photoStart + 900,
    'last byte after the photo': photoStart + 926,
    'SHA padding marker': paddingStart,
    'SHA length field': Number(circuitInput.qrDataPaddedLength) - 1,
  };
  assert.equal(circuitInput.qrDataPadded[paddingStart], '128');
  for (const [where, i] of Object.entries(positions)) {
    assert.ok(await failure(flipByte(circuitInput, i)), `${where} (byte ${i}) changed but the witness succeeded`);
  }
});

test('T1.3: one changed signature bit fails the witness', NEEDS_WASM, async () => {
  const circuitInput = input(v5());
  for (const limb of [0, 8, 16]) {
    const signature = [...circuitInput.signature];
    signature[limb] = String(BigInt(signature[limb]) ^ 1n);
    assert.ok(await failure({ ...circuitInput, signature }), `signature limb ${limb}`);
  }
});

test('T1.4: a valid signature checked under another key fails the witness', NEEDS_WASM, async () => {
  const text = v5();
  const underOtherKey = buildInput(text, otherKeys.publicKey, PUBLIC);
  assert.match(await failure(underOtherKey), /RSA/);
});

test('T1.8: a DOB field that is not 10 bytes (year only) fails the witness', NEEDS_WASM, async () => {
  assert.match(await failure(input(v5({ fields: { dob: '1990' } }))), /AgeExtractor/);
});

test('T1.9: DOB digits are not range-checked; the circuit relies on UIDAI formatting (S4)', NEEDS_WASM, async () => {
  // Documents current behaviour. UIDAI would have to sign such a DOB for it to matter.
  assert.equal((await run(input(v5({ fields: { dob: '01-13-1990' } })))).ageAbove18, '1', 'month 13 accepted');
  assert.equal((await run(input(v5({ fields: { dob: '32-01-1990' } })))).ageAbove18, '1', 'day 32 accepted');
  assert.ok(await failure(input(v5({ fields: { dob: 'AB-CD-EFGH' } }))), 'non-digits fail, in a comparator');
  assert.ok(await failure(input(v5({ fields: { dob: '1990-01-01' } }))), 'YYYY-MM-DD fails');
});

test('T1.10: ageAbove18 is 1 only from the 19th birthday, on the QR generation date', NEEDS_WASM, async () => {
  // QR generated on 25-10-2026.
  const expected = {
    '26-10-2008': '0', // 17
    '25-10-2008': '0', // 18th birthday
    '24-10-2008': '0', // 18
    '26-10-2007': '0', // 18, 19th birthday tomorrow
    '25-10-2007': '1', // 19th birthday
    '24-10-2007': '1', // 19
  };
  for (const [dob, ageAbove18] of Object.entries(expected)) {
    assert.equal((await run(input(v5({ fields: { dob } })))).ageAbove18, ageAbove18, dob);
  }
  const hidden = { ...input(v5()), revealAgeAbove18: '0' };
  assert.equal((await run(hidden)).ageAbove18, '0', 'adult with the age flag off');
});

test('T4.1: same photo and trailing bytes give the same nullifier across downloads', NEEDS_WASM, async () => {
  const photo = syntheticPhoto(900);
  const trailing = unknownTrailer(27);
  const first = await run(input(v5({ photo, trailing })));
  const later = await run(input(v5({ photo, trailing, generatedAt: new Date('2026-10-26T10:17:00Z') })));
  assert.equal(first.nullifier, later.nullifier);
  assert.notEqual(first.timestamp, later.timestamp);
  // The nullifier also covers the 27 bytes after the photo (S8).
  const otherTrailing = await run(input(v5({ photo, trailing: unknownTrailer(27) })));
  assert.notEqual(first.nullifier, otherTrailing.nullifier);
});

test('T5.1: the same QR under two verifier seeds gives two nullifiers', NEEDS_WASM, async () => {
  const text = v5();
  const a = await run(input(text, { nullifierSeed: 1111n }));
  const b = await run(input(text, { nullifierSeed: 3333n }));
  assert.notEqual(a.nullifier, b.nullifier);
});

test('T7.6: wrong delimiter positions fail wherever the circuit reads them', NEEDS_WASM, async () => {
  const circuitInput = input(v5());
  const valid = await run(circuitInput);
  const shifted = (i, by) => {
    const delimiterIndices = [...circuitInput.delimiterIndices];
    delimiterIndices[i] = String(Number(delimiterIndices[i]) + by);
    return { ...circuitInput, delimiterIndices };
  };
  // Read by the circuit: DOB (index 3), PIN (10, 11), state (12, 13), photo (17).
  for (const i of [3, 10, 11, 12, 13, 17]) {
    for (const by of [-1, 1]) assert.ok(await failure(shifted(i, by)), `delimiter index ${i} shifted by ${by}`);
  }
  // The other positions are never read: shifting them changes nothing.
  for (const i of [0, 1, 2, 4, 5, 6, 7, 8, 9, 14, 15, 16]) {
    assert.deepEqual(await run(shifted(i, 1)), valid, `unused delimiter index ${i}`);
  }
});

// ---- Proof and verification (needs the proving and verification keys) ------------

test('T7.1: the proof verifies, and fails if any public signal changes', NEEDS_ZKEY, async () => {
  const { proof, publicSignals } = await prove(input(v5()), { dir: DIR });
  assert.equal(await verify(proof, publicSignals, { dir: DIR }), true);
  for (let i = 0; i < publicSignals.length; i++) {
    const changed = [...publicSignals];
    changed[i] = ((BigInt(changed[i]) + 1n) % FIELD).toString();
    assert.equal(await verify(proof, changed, { dir: DIR }), false, `public signal ${i} changed`);
  }
  // A verification key that is not the pinned one is refused before use.
  const tampered = tempDir();
  const vkey = JSON.parse(fs.readFileSync(path.join(DIR, 'vkey.json'), 'utf8'));
  vkey.IC[0][0] = '1';
  fs.writeFileSync(path.join(tampered, 'vkey.json'), JSON.stringify(vkey));
  await rejectsCode(verify(proof, publicSignals, { dir: tampered }), 'ARTIFACT_MISMATCH');
});
