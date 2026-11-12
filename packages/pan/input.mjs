// The circuit's input for a record read by record.mjs, and what a proof of it
// outputs. Plain JavaScript (BigInt), for the holder app and Node.

import { GENDER_VALUES, MAX_DOC_BYTES } from './format.mjs';
import { limbs } from './limbs.mjs';
import { PanError, verifiedHour } from './record.mjs';
import { panKeyHash, poseidon2 } from './keyhash.mjs';

export { PUBLIC_INPUTS, publicValues } from './public.mjs';

// SHA-256 padding, then zeros to the circuit's size.
function padDoc(doc) {
  const paddedLength = Math.ceil((doc.length + 9) / 64) * 64;
  if (paddedLength > MAX_DOC_BYTES) throw new PanError('RECORD_TOO_LONG', `The record takes ${paddedLength} padded bytes; the circuit takes ${MAX_DOC_BYTES}.`);
  const padded = new Uint8Array(MAX_DOC_BYTES);
  padded.set(doc);
  padded[doc.length] = 0x80;
  new DataView(padded.buffer).setBigUint64(paddedLength - 8, BigInt(doc.length) * 8n);
  return { padded, paddedLength };
}

const toBigInt = (bytes) => BigInt(`0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`);

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

// The proof reveals the gender only with revealGender; everything else it
// outputs, it always outputs (docs/circuit-spec.md, section 7).
export function circuitInput(record, { dobCutoff, nullifierSeed, signalHash, revealGender = false }) {
  const { padded, paddedLength } = padDoc(record.doc);
  const signature = toBigInt(record.signature);
  const modulus = BigInt(`0x${record.signer.modulus}`);
  const { q, r } = rsaSteps(signature, modulus);
  return {
    doc: Array.from(padded),
    doc_padded_length: paddedLength,
    signature: limbs(signature),
    modulus: limbs(modulus),
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

const pack = (ascii) => [...new TextEncoder().encode(ascii)].reduceRight((value, byte) => (value << 8n) | BigInt(byte), 0n);
const ymd = (ddmmyyyy) => Number(`${ddmmyyyy.slice(6, 10)}${ddmmyyyy.slice(3, 5)}${ddmmyyyy.slice(0, 2)}`);

// What a proof of this record outputs, computed here: for the tests, and for
// the holder app to check before it proves.
export function expectedOutputs(record, { dobCutoff, nullifierSeed, revealGender = false }) {
  const { values } = record;
  return {
    pubkeyHash: panKeyHash(record.signer.modulus),
    nullifier: poseidon2([BigInt(nullifierSeed), pack(values.pan), pack(values.uid.slice(0, 16)), pack(values.uid.slice(16))]).toString(),
    verifiedHour: String(verifiedHour(values.verifiedOn)),
    bornBy: ymd(values.dob) <= Number(dobCutoff) ? '1' : '0',
    gender: revealGender ? String(GENDER_VALUES[values.gender].charCodeAt(0)) : '0',
  };
}
