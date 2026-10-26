// Anon Aadhaar's Secure QR circuit, AadhaarQRVerifier(121, 17, 1536), from its
// published v2.0.0 artifacts, in Node. zkID uses it unchanged (option A; see
// docs/circuit-spec.md). This module computes witnesses and proofs, verifies
// proofs, and refuses any artifact whose SHA-256 differs from artifacts.json.
// The circuit input is built by input.mjs, which also runs in a browser.
//
// Every failure throws a CircuitError with a code. Nothing falls back silently.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { decodeSecureQr } from '../secure-qr/secure-qr.mjs';
import { CircuitError, PUBLIC_SIGNALS, circuitInput, keyHashFromModulus, namedSignals } from './input.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
export const MANIFEST = JSON.parse(fs.readFileSync(path.join(here, 'artifacts.json'), 'utf8'));
export const DEFAULT_DIR = path.join(here, 'artifacts');

export {
  CircuitError,
  LIMBS,
  LIMB_BITS,
  MAX_DATA_BYTES,
  MAX_PHOTO_SPAN,
  PUBLIC_SIGNALS,
  circuitInput,
  keyHashFromModulus,
  namedSignals,
} from './input.mjs';

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

// ---- Keys and input -----------------------------------------------------------

function modulusOf(key) {
  const publicKey = key instanceof crypto.X509Certificate ? key.publicKey : key;
  if (!(publicKey instanceof crypto.KeyObject) || publicKey.asymmetricKeyType !== 'rsa') {
    throw new CircuitError('UNSUPPORTED_KEY', 'Expected an RSA public key or certificate.');
  }
  const { n, e } = publicKey.export({ format: 'jwk' });
  if (e !== 'AQAB') throw new CircuitError('UNSUPPORTED_KEY', 'The circuit verifies RSA-2048 with e = 65537 only.');
  return BigInt(`0x${Buffer.from(n, 'base64url').toString('hex')}`);
}

// The circuit's pubkeyHash for an RSA public key or certificate.
export const keyHash = (key) => keyHashFromModulus(modulusOf(key));

// Circuit input for a Secure QR (its text) and the key that signed it.
export const buildInput = (qrText, key, publicInputs) => circuitInput(decodeSecureQr(qrText), modulusOf(key), publicInputs);

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
