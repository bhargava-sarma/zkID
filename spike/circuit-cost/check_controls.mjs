#!/usr/bin/env node
// What Anon Aadhaar's published v2.0.0 circuit enforces, checked on synthetic
// data by witness generation: tampered inputs must fail; properties it only
// outputs (not asserts) are shown as outputs a verifier must check.
//
// Usage: AA_ARTIFACTS=<dir> node check_controls.mjs

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import * as snarkjs from 'snarkjs';
import { anonAadhaarInput } from './aa_input.mjs';
import { makeSyntheticSecureQr, syntheticFields, syntheticPhoto } from '../secure-qr/synthetic.mjs';

const wasm = path.join(process.env.AA_ARTIFACTS ?? '', 'aadhaar-verifier.wasm');
if (!fs.existsSync(wasm)) throw new Error('Set AA_ARTIFACTS to the directory holding aadhaar-verifier.wasm.');

const OUTPUTS = ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pinCode', 'state'];
async function outputs(input) {
  const wtns = { type: 'mem' };
  await snarkjs.wtns.calculate(input, wasm, wtns);
  const w = await snarkjs.wtns.exportJson(wtns);
  return Object.fromEntries(OUTPUTS.map((name, i) => [name, w[i + 1].toString()]));
}
async function rejects(input) {
  try {
    await outputs(input);
    return 'ACCEPTED';
  } catch (err) {
    return `rejected (${err.message.match(/template (\w+)/)?.[1] ?? 'error'})`;
  }
}

const keys = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const photo = syntheticPhoto(888);
const qr = (fields, k = keys) => makeSyntheticSecureQr(k.privateKey, { photo, fields: syntheticFields(fields) }).text;
const day1 = new Date('2026-10-01T04:30:00Z');
const day2 = new Date('2026-10-20T09:30:00Z');
const base = anonAadhaarInput(qr({ generatedAt: day1 }), keys.publicKey);
const flip = (input, field, index) => {
  const copy = structuredClone(input);
  copy[field][index] = (BigInt(copy[field][index]) ^ 1n).toString();
  return copy;
};

const results = [];
const record = (check, result, expected) => {
  results.push({ check, result, expected, ok: String(result).startsWith(expected) });
  console.log(`${results.at(-1).ok ? 'ok  ' : 'FAIL'} ${check}: ${result}`);
};

const valid = await outputs(base);
record('valid synthetic code', `accepted; ageAbove18=${valid.ageAbove18}`, 'accepted; ageAbove18=1');
const dob = Number(base.delimiterIndices[3]) + 1;
record('one DOB byte changed', await rejects(flip(base, 'qrDataPadded', dob)), 'rejected');
record('one photo byte changed', await rejects(flip(base, 'qrDataPadded', Number(base.delimiterIndices[17]) + 50)), 'rejected');
record('one signature limb bit changed', await rejects(flip(base, 'signature', 0)), 'rejected');
const wrongKey = anonAadhaarInput(qr({ generatedAt: day1 }), keys.publicKey);
wrongKey.pubKey = anonAadhaarInput(qr({ generatedAt: day1 }, other), other.publicKey).pubKey;
record('signature checked under a different key', await rejects(wrongKey), 'rejected');
const badHint = structuredClone(base);
badHint.delimiterIndices[3] = String(Number(badHint.delimiterIndices[3]) + 1);
record('DOB delimiter hint off by one', await rejects(badHint), 'rejected');

// Asserted nowhere: the circuit outputs these and the verifier must check them.
const minor = await outputs(anonAadhaarInput(qr({ generatedAt: day1, dob: '15-08-2015' }), keys.publicKey));
record('holder under 18 at QR time', `accepted; ageAbove18=${minor.ageAbove18}`, 'accepted; ageAbove18=0');
const hidden = await outputs({ ...base, revealAgeAbove18: '0' });
record('adult with revealAgeAbove18=0', `accepted; ageAbove18=${hidden.ageAbove18}`, 'accepted; ageAbove18=0');

// Nullifier: same photo, two downloads, same seed -> same; other seed -> different.
const later = await outputs(anonAadhaarInput(qr({ generatedAt: day2 }), keys.publicKey));
record('re-download, same seed: nullifier', valid.nullifier === later.nullifier ? 'equal' : 'different', 'equal');
record('re-download: timestamp output', valid.timestamp === later.timestamp ? 'equal' : 'different', 'different');
const otherSeed = await outputs({ ...base, nullifierSeed: '987654321' });
record('other verifier seed: nullifier', valid.nullifier === otherSeed.nullifier ? 'equal' : 'different', 'different');
// IST is UTC+5:30, so the circuit's hour is an IST hour boundary.
const istHour = Math.floor((day1.getTime() / 1000 + 19800) / 3600) * 3600 - 19800;
record('timestamp is the generation hour (IST)', valid.timestamp === String(istHour) ? 'yes' : `no (${valid.timestamp})`, 'yes');

fs.mkdirSync(new URL('./results/', import.meta.url), { recursive: true });
fs.writeFileSync(new URL('./results/controls.json', import.meta.url), JSON.stringify({ when: new Date().toISOString(), results }, null, 2) + '\n');
await globalThis.curve_bn128?.terminate();
process.exit(results.every((r) => r.ok) ? 0 : 1);
