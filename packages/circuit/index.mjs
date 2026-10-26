// Anon Aadhaar's Secure QR circuit, AadhaarQRVerifier(121, 17, 1536), from its
// published v2.0.0 artifacts. zkID uses it unchanged (option A; see
// docs/circuit-spec.md). This module builds the circuit input from a Secure QR,
// computes witnesses and proofs, verifies proofs, and refuses any artifact
// whose SHA-256 differs from artifacts.json.
//
// Every failure throws a CircuitError with a code. Nothing falls back silently.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { poseidon9 } from 'poseidon-lite';
import * as snarkjs from 'snarkjs';
import { decodeSecureQr } from '../secure-qr/secure-qr.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const MANIFEST = JSON.parse(fs.readFileSync(path.join(here, 'artifacts.json'), 'utf8'));
export const DEFAULT_DIR = path.join(here, 'artifacts');

export class CircuitError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = 'CircuitError';
    this.code = code;
  }
}

export const LIMB_BITS = 121;
export const LIMBS = 17;
export const MAX_DATA_BYTES = 1536;
// The photo extractor accepts at most this many bytes from the photo's first
// byte to the end of the SHA-padded data (zk-email SelectSubArray, 10-bit length).
export const MAX_PHOTO_SPAN = 1023;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Public signals in the order snarkjs returns them: 7 outputs, then 2 public inputs.
export const PUBLIC_SIGNALS = ['pubkeyHash', 'nullifier', 'timestamp', 'ageAbove18', 'gender', 'pinCode', 'state', 'nullifierSeed', 'signalHash'];

export function namedSignals(publicSignals) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== PUBLIC_SIGNALS.length) {
    throw new CircuitError('BAD_PUBLIC_SIGNALS', `Expected ${PUBLIC_SIGNALS.length} public signals.`);
  }
  return Object.fromEntries(PUBLIC_SIGNALS.map((name, i) => [name, String(publicSignals[i])]));
}

// ---- Artifacts --------------------------------------------------------------

const verified = new Map(); // path -> "size:mtime" of the file that last matched

async function sha256File(file) {
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

// Path of an artifact, after checking its SHA-256 against artifacts.json.
export async function checkedArtifact(name, dir = DEFAULT_DIR) {
  const entry = MANIFEST.files.find((f) => f.name === name);
  if (!entry) throw new CircuitError('UNKNOWN_ARTIFACT', name);
  const file = path.join(dir, name);
  if (!fs.existsSync(file)) throw new CircuitError('ARTIFACT_MISSING', `${file} not found; run npm run fetch.`);
  const { size, mtimeMs } = fs.statSync(file);
  if (verified.get(file) === `${size}:${mtimeMs}`) return file;
  const digest = await sha256File(file);
  if (digest !== entry.sha256) throw new CircuitError('ARTIFACT_MISMATCH', `${name} has SHA-256 ${digest}, expected ${entry.sha256}.`);
  verified.set(file, `${size}:${mtimeMs}`);
  return file;
}

// ---- Keys -------------------------------------------------------------------

const toBigInt = (bytes) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);

// Least-significant limb first.
function limbs(value) {
  const mask = (1n << BigInt(LIMB_BITS)) - 1n;
  return Array.from({ length: LIMBS }, (_, i) => (value >> (BigInt(LIMB_BITS) * BigInt(i))) & mask);
}

function modulusOf(key) {
  const publicKey = key instanceof crypto.X509Certificate ? key.publicKey : key;
  if (!(publicKey instanceof crypto.KeyObject) || publicKey.asymmetricKeyType !== 'rsa') {
    throw new CircuitError('UNSUPPORTED_KEY', 'Expected an RSA public key or certificate.');
  }
  const { n, e } = publicKey.export({ format: 'jwk' });
  const modulus = toBigInt(Buffer.from(n, 'base64url'));
  if (e !== 'AQAB' || modulus.toString(2).length !== 2048) {
    throw new CircuitError('UNSUPPORTED_KEY', 'The circuit verifies RSA-2048 with e = 65537 only.');
  }
  return modulus;
}

// The circuit's pubkeyHash output: Poseidon over the 17 key limbs, merged in
// pairs (limb[2i] + limb[2i+1] * 2^121) into 9 inputs.
export function keyHash(key) {
  const l = limbs(modulusOf(key));
  const inputs = [];
  for (let i = 0; i < LIMBS; i += 2) inputs.push(i + 1 < LIMBS ? l[i] + (l[i + 1] << BigInt(LIMB_BITS)) : l[i]);
  return poseidon9(inputs).toString();
}

// ---- Input ------------------------------------------------------------------

// SHA-256 padding, then zeros up to MAX_DATA_BYTES (as zk-email's sha256Pad).
function sha256Pad(message) {
  const paddedLength = Math.ceil((message.length + 9) / 64) * 64;
  if (paddedLength > MAX_DATA_BYTES) {
    throw new CircuitError('DATA_TOO_LONG', `${message.length} signed bytes need ${paddedLength} padded bytes; the circuit takes ${MAX_DATA_BYTES}.`);
  }
  const padded = Buffer.alloc(MAX_DATA_BYTES);
  message.copy(padded);
  padded[message.length] = 0x80;
  padded.writeBigUInt64BE(BigInt(message.length * 8), paddedLength - 8);
  return { padded, paddedLength };
}

function fieldElement(name, value) {
  let v;
  try {
    v = BigInt(value);
  } catch {
    throw new CircuitError('BAD_PUBLIC_INPUT', `${name} is not an integer.`);
  }
  if (v < 0n || v >= FIELD) throw new CircuitError('BAD_PUBLIC_INPUT', `${name} is outside the BN254 scalar field.`);
  return v.toString();
}

// Circuit input for a Secure QR and the key that signed it. Only the age bit is
// revealed: gender, PIN code and state stay hidden (docs/THREAT_MODEL.md, A6.1).
// The signature is not checked here; the circuit checks it.
export function buildInput(qrText, key, { nullifierSeed, signalHash }) {
  const qr = decodeSecureQr(qrText);
  if (qr.version !== 'V2' && qr.version !== 'V5') {
    throw new CircuitError('UNSUPPORTED_LAYOUT', `The circuit reads the V2/V5 field layout; this code is ${qr.version}.`);
  }
  const { padded, paddedLength } = sha256Pad(qr.signedData);
  const span = paddedLength - qr.photo.offset;
  if (span > MAX_PHOTO_SPAN) {
    throw new CircuitError('PHOTO_TOO_LARGE', `The photo and what follows it take ${span} padded bytes; the circuit accepts ${MAX_PHOTO_SPAN}.`);
  }
  return {
    qrDataPadded: Array.from(padded, String),
    qrDataPaddedLength: String(paddedLength),
    delimiterIndices: qr.delimiterIndices.map(String),
    signature: limbs(toBigInt(qr.signature)).map(String),
    pubKey: limbs(modulusOf(key)).map(String),
    revealAgeAbove18: '1',
    revealGender: '0',
    revealPinCode: '0',
    revealState: '0',
    nullifierSeed: fieldElement('nullifierSeed', nullifierSeed),
    signalHash: fieldElement('signalHash', signalHash),
  };
}

// ---- Witness, proof, verification -------------------------------------------

// The public signals of the witness for `input`, without proving. The error
// names the circuit template whose constraint failed.
export async function witness(input, { dir = DEFAULT_DIR } = {}) {
  const wasm = await checkedArtifact('aadhaar-verifier.wasm', dir);
  const wtns = { type: 'mem' };
  try {
    await snarkjs.wtns.calculate(input, wasm, wtns);
  } catch (err) {
    const template = String(err.message).match(/Error in template (\w+)/)?.[1] ?? 'unknown';
    throw new CircuitError('WITNESS_FAILED', `constraint failed in ${template}`);
  }
  const w = await snarkjs.wtns.exportJson(wtns);
  return namedSignals(w.slice(1, 1 + PUBLIC_SIGNALS.length).map(String));
}

export async function prove(input, { dir = DEFAULT_DIR } = {}) {
  const wasm = await checkedArtifact('aadhaar-verifier.wasm', dir);
  const zkey = await checkedArtifact('circuit_final.zkey', dir);
  try {
    return await snarkjs.groth16.fullProve(input, wasm, zkey);
  } catch (err) {
    const template = String(err.message).match(/Error in template (\w+)/)?.[1];
    if (template) throw new CircuitError('WITNESS_FAILED', `constraint failed in ${template}`);
    throw err;
  }
}

// true only if the proof verifies for exactly these nine public signals.
export async function verify(proof, publicSignals, { dir = DEFAULT_DIR } = {}) {
  namedSignals(publicSignals);
  const vkey = JSON.parse(fs.readFileSync(await checkedArtifact('vkey.json', dir), 'utf8'));
  return snarkjs.groth16.verify(vkey, publicSignals.map(String), proof);
}

// snarkjs keeps worker threads for the curve; call this before exiting.
export async function close() {
  await globalThis.curve_bn128?.terminate();
  delete globalThis.curve_bn128;
}
