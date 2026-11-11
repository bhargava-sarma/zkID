// The Noir circuit's input for a record read by ../pan/record.mjs, and what the
// circuit returns for it, computed in JavaScript for the tests. Nothing here
// logs a record's values.

import { BarretenbergSync } from '@aztec/bb.js';
import { GENDER_VALUES, MAX_DOC_BYTES } from '../pan/format.mjs';
import { PanError } from '../pan/record.mjs';
import { limbs } from './limbs.mjs';

// SHA-256 padding, then zeros to the circuit's size.
function padDoc(doc) {
  const paddedLength = Math.ceil((doc.length + 9) / 64) * 64;
  if (paddedLength > MAX_DOC_BYTES) throw new PanError('RECORD_TOO_LONG', `the record takes ${paddedLength} padded bytes; the circuit takes ${MAX_DOC_BYTES}`);
  const padded = new Uint8Array(MAX_DOC_BYTES);
  padded.set(doc);
  padded[doc.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(paddedLength - 8, BigInt(doc.length) * 8n);
  return { padded, paddedLength };
}

// signature^65537 mod n as the circuit checks it: sixteen squarings, then one
// multiplication by the signature, each with its quotient and remainder.
function rsaSteps(signature, modulus) {
  const q = [];
  const r = [];
  let x = signature;
  for (let step = 0; step < 17; step++) {
    const product = step < 16 ? x * x : x * signature;
    q.push(limbs(product / modulus));
    r.push(limbs(product % modulus));
    x = product % modulus;
  }
  return { q, r };
}

export function noirInput(record, { dobCutoff, nullifierSeed, signalHash, revealGender = false }) {
  const { padded, paddedLength } = padDoc(record.doc);
  const signature = BigInt(`0x${record.signature.toString('hex')}`);
  const { q, r } = rsaSteps(signature, record.modulus);
  return {
    doc: Array.from(padded),
    doc_padded_length: paddedLength,
    signature: limbs(signature),
    modulus: limbs(record.modulus),
    rsa_q: q,
    rsa_r: r,
    gender_at: record.hints.genderAt,
    uid_at: record.hints.uidAt,
    pan_at: record.hints.panAt,
    reveal_gender: revealGender,
    dob_cutoff: dobCutoff,
    nullifier_seed: String(nullifierSeed),
    signal_hash: String(signalHash),
  };
}

// Poseidon2 as circuit/src/poseidon2.nr computes it, over Barretenberg's permutation.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let bb;
const fr = (value) => Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'));
const big = (bytes) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
export async function poseidon2(inputs) {
  bb ??= await BarretenbergSync.initSingleton();
  const permute = (state) => bb.poseidon2Permutation({ inputs: state.map(fr) }).outputs.map(big);
  let state = [0n, 0n, 0n, BigInt(inputs.length) << 64n];
  const full = Math.floor(inputs.length / 3);
  for (let i = 0; i < full; i++) {
    for (let j = 0; j < 3; j++) state[j] = (state[j] + inputs[3 * i + j]) % P;
    state = permute(state);
  }
  for (let i = 0; i < inputs.length % 3; i++) state[i] = (state[i] + inputs[3 * full + i]) % P;
  return permute(state)[0];
}

const pack = (ascii) => [...Buffer.from(ascii, 'latin1')].reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
const ymd = (ddmmyyyy) => Number(`${ddmmyyyy.slice(6, 10)}${ddmmyyyy.slice(3, 5)}${ddmmyyyy.slice(0, 2)}`);

// What the circuit returns for a record, computed in JavaScript, for the tests.
export async function expectedOutputs(record, { dobCutoff, nullifierSeed, revealGender = false }) {
  const { values } = record;
  return {
    pubkeyHash: await poseidon2(limbs(record.modulus).map(BigInt)),
    nullifier: await poseidon2([BigInt(nullifierSeed), pack(values.pan), pack(values.uid.slice(0, 16)), pack(values.uid.slice(16))]),
    verifiedHour: ymd(values.verifiedOn) * 100 + Number(values.verifiedOn.slice(11, 13)),
    bornBy: ymd(values.dob) <= Number(dobCutoff),
    gender: revealGender ? GENDER_VALUES[values.gender].charCodeAt(0) : 0,
  };
}

// noir_js's return value for main, in the shape expectedOutputs gives.
export function outputsOf(returnValue) {
  const [pubkeyHash, nullifier, verifiedHour, bornBy, gender] = returnValue;
  return {
    pubkeyHash: BigInt(pubkeyHash),
    nullifier: BigInt(nullifier),
    verifiedHour: Number(BigInt(verifiedHour)),
    bornBy: bornBy === true || bornBy === '0x01' || BigInt(bornBy) === 1n,
    gender: Number(BigInt(gender)),
  };
}
