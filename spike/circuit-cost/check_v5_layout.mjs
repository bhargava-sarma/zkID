#!/usr/bin/env node
// Does Anon Aadhaar's published circuit accept current (V5) Secure QR codes?
// Builds synthetic V5 codes laid out like one real code (docs/issuer-research.md,
// sections 3.2 and 7.4), then:
//   1. generates a witness for the measured shape (900-byte photo, 27 bytes after);
//   2. sweeps the photo size to find where witness generation starts failing;
//   3. checks the size rule that the sweep suggests at two more photo offsets;
//   4. changes only the 27 bytes after the photo and compares nullifiers.
//
// Usage: AA_ARTIFACTS=<dir with aadhaar-verifier.wasm> node check_v5_layout.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { anonAadhaarInput } from './aa_input.mjs';
import { decodeSecureQr } from '../secure-qr/secure-qr.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto, unknownTrailer } from '../secure-qr/synthetic.mjs';

const wasm = path.join(process.env.AA_ARTIFACTS ?? '', 'aadhaar-verifier.wasm');
if (!fs.existsSync(wasm)) throw new Error('Set AA_ARTIFACTS to the directory holding aadhaar-verifier.wasm.');

const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const sign = (fields, photo, trailing) => makeSyntheticSecureQr(keys.privateKey, { version: 'V5', fields, photo, trailing }).text;

// Only the photo's offset is taken from the real code (inspect-qr.mjs output);
// the circuit's limits depend on it, not on the individual text fields. The
// text is the default synthetic set, with the landmark field, which the circuit
// never reads, padded so that the photo starts at the wanted offset.
const REAL_PHOTO_OFFSET = 249;
const base = syntheticFields({ generatedAt: new Date('2026-10-25T06:30:00Z'), landmark: '' });
const baseOffset = decodeSecureQr(sign(base, syntheticPhoto(900), unknownTrailer(27))).photo.offset;
const fieldsAt = (offset) => ({ ...base, landmark: 'S'.repeat(offset - baseOffset) });

const code = (photoBytes, { offset = REAL_PHOTO_OFFSET, trailing = unknownTrailer(27), photo = syntheticPhoto(photoBytes) } = {}) =>
  sign(fieldsAt(offset), photo, trailing);

const OUTPUTS = ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18'];
async function witness(text) {
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(anonAadhaarInput(text, keys.publicKey), wasm, wtns);
  const w = await snarkjs.wtns.exportJson(wtns);
  return Object.fromEntries(OUTPUTS.map((name, i) => [name, w[i + 1].toString()]));
}
const attempt = async (text) => witness(text).then(() => 'accepted', (err) => `rejected (${err.message.match(/template (\w+)/)?.[1] ?? 'error'})`);

const results = {};
const measured = decodeSecureQr(code(900));
results.shape = { photoOffset: measured.photo.offset, signedBytes: measured.signedData.length, trailingBytes: measured.trailingBytes };
console.log(`replica: photo at ${measured.photo.offset}, ${measured.signedData.length} signed bytes, ${measured.trailingBytes} after the photo`);

const out = await witness(code(900));
results.measuredShape = { accepted: true, ageAbove18: out.ageAbove18 };
console.log(`measured shape (900-byte photo): accepted, ageAbove18=${out.ageAbove18}`);

results.photoSweep = [];
for (const size of [900, 920, 924, 925, 931, 932, 940, 960, 987, 988, 1000]) {
  const signed = decodeSecureQr(code(size)).signedData.length;
  const paddedBytes = Math.ceil((signed + 9) / 64) * 64;
  const result = await attempt(code(size));
  results.photoSweep.push({ photoBytes: size, signedBytes: signed, paddedBytes, result });
  console.log(`photo ${size} B: ${signed} signed, ${paddedBytes} padded -> ${result}`);
}

// The rule the sweep suggests: from the photo's first byte to the end of the
// SHA-padded data (at least 9 padding bytes, rounded up to 64) is at most 1,023
// bytes. With 27 trailing bytes the largest photo is then
// 987 - ((1023 + offset) mod 64). Checked at the offsets giving its smallest
// (924) and largest (987) values, and at the real code's offset.
const maxPhoto = (offset) => 1023 - 27 - 9 - ((1023 + offset) % 64);
results.ruleCheck = [];
for (const offset of [256, 257, REAL_PHOTO_OFFSET]) {
  const max = maxPhoto(offset);
  const atMax = await attempt(code(max, { offset }));
  const aboveMax = await attempt(code(max + 1, { offset }));
  results.ruleCheck.push({ photoOffset: offset, predictedMaxPhoto: max, atMax, aboveMax });
  console.log(`photo at ${offset}: predicted max ${max} B; ${max} B ${atMax}, ${max + 1} B ${aboveMax}`);
}

// Same photo, different trailing bytes: is the trailer part of the nullifier?
const photo = syntheticPhoto(900);
const [n1, n2] = await Promise.all([unknownTrailer(27), unknownTrailer(27)].map(async (trailing) => (await witness(code(900, { trailing, photo }))).nullifier));
results.trailerInNullifier = n1 !== n2;
console.log(`only the 27 trailing bytes changed: nullifier ${n1 === n2 ? 'same' : 'DIFFERENT'}`);

fs.mkdirSync(new URL('./results/', import.meta.url), { recursive: true });
fs.writeFileSync(new URL('./results/v5_layout.json', import.meta.url), JSON.stringify({ when: new Date().toISOString(), ...results }, null, 2) + '\n');
await globalThis.curve_bn128?.terminate();
